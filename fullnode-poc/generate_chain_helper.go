package core

// Full-node PoC chain generation for the BEP-703 payment-lane gas-basis
// divergence. This mirrors GenerateChainWithGenesis's exact flow, with two
// changes needed for real-Parlia, full-node-importable chains:
//
//   - the genesis block is seeded into the chain-maker's by-hash index so the
//     engine (whose Finalize resolves the parent header by hash) works, and
//   - generation is split into passes so a block can be Parlia-sealed and then
//     used as the parent of the next pass (the child header's parent hash and
//     the EIP-2935 parent-hash history record must commit to the SEALED hash).
//
// Without real-engine generation, block 1 would lack the seven system-contract
// init transactions Parlia's Finalize appends at height 1, and any full-node
// import would reject it with "init contract failed".

import (
        "math/big"

        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/consensus"
        "github.com/ethereum/go-ethereum/consensus/misc"
        "github.com/ethereum/go-ethereum/consensus/misc/eip4844"
        "github.com/ethereum/go-ethereum/core/rawdb"
        "github.com/ethereum/go-ethereum/core/state"
        "github.com/ethereum/go-ethereum/core/systemcontracts"
        "github.com/ethereum/go-ethereum/core/types"
        "github.com/ethereum/go-ethereum/core/vm"
        "github.com/ethereum/go-ethereum/ethdb"
        "github.com/ethereum/go-ethereum/params"
        "github.com/ethereum/go-ethereum/triedb"
)

// PrepareBep703PoCChain commits gspec into a fresh memory database and returns
// the database plus the genesis block to generate on top of.
func PrepareBep703PoCChain(gspec *Genesis) (ethdb.Database, *types.Block) {
        db := rawdb.NewMemoryDatabase()
        genesisTriedb := triedb.NewDatabase(db, triedb.HashDefaults)
        parent, err := gspec.Commit(db, genesisTriedb, nil)
        if err != nil {
                panic(err)
        }
        genesisTriedb.Close()
        return db, parent
}

// GenerateBep703PoCBlocks generates n blocks on top of parent, committing the
// post-state into db as it goes, exactly like core.GenerateChain.
func GenerateBep703PoCBlocks(db ethdb.Database, parent *types.Block, engine consensus.Engine, config *params.ChainConfig, n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
        cm := newChainMaker(parent, config, engine)
        cm.chainByHash[parent.Hash()] = parent // parent visible to engine lookups

        stdb := triedb.NewDatabase(db, triedb.HashDefaults)
        defer stdb.Close()

        genblock := func(i int, parent *types.Block, tdb *triedb.Database, statedb *state.StateDB) (*types.Block, types.Receipts) {
                b := &BlockGen{i: i, cm: cm, parent: parent, statedb: statedb, engine: engine}
                b.header = cm.makeHeader(parent, statedb, b.engine)
                if b.header.EmptyWithdrawalsHash() {
                        b.withdrawals = make([]*types.Withdrawal, 0)
                }
                if b.header.Difficulty == nil {
                        if config.TerminalTotalDifficulty == nil {
                                b.header.Difficulty = big.NewInt(2)
                        } else {
                                b.header.Difficulty = big.NewInt(0)
                        }
                }
                if daoBlock := config.DAOForkBlock; daoBlock != nil {
                        limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
                        if b.header.Number.Cmp(daoBlock) >= 0 && b.header.Number.Cmp(limit) < 0 {
                                if config.DAOForkSupport {
                                        b.header.Extra = common.CopyBytes(params.DAOForkBlockExtra)
                                }
                        }
                }
                if config.DAOForkSupport && config.DAOForkBlock != nil && config.DAOForkBlock.Cmp(b.header.Number) == 0 {
                        misc.ApplyDAOHardFork(statedb)
                }
                lane, err := ResolveLaneState(config, engine, parent.Header(), b.header, statedb)
                if err != nil {
                        panic(err)
                }
                b.lane = lane
                systemcontracts.TryUpdateBuildInSystemContract(config, b.header.Number, parent.Time(), b.header.Time, statedb, true)
                if config.IsPrague(b.header.Number, b.header.Time) || config.IsUBT(b.header.Number, b.header.Time) {
                        blockContext := NewEVMBlockContext(b.header, cm, &b.header.Coinbase)
                        blockContext.Random = &common.Hash{}
                        evm := vm.NewEVM(blockContext, statedb, cm.config, vm.Config{})
                        ProcessParentBlockHash(b.header.ParentHash, evm)
                }
                if gen != nil {
                        gen(i, b)
                }
                requests := b.collectRequests(false)
                if requests != nil {
                        reqHash := types.CalcRequestsHash(requests)
                        b.header.RequestsHash = &reqHash
                }
                body := types.Body{
                        Transactions: b.txs,
                        Uncles:       b.uncles,
                        Withdrawals:  b.withdrawals,
                }
                if !config.IsShanghai(b.header.Number, b.header.Time) {
                        if body.Withdrawals != nil {
                                panic("unexpected withdrawal before shanghai")
                        }
                } else {
                        if body.Withdrawals == nil {
                                body.Withdrawals = make([]*types.Withdrawal, 0)
                        }
                }
                block, receipts, err := AssembleBlock(b.engine, cm, b.header, statedb, &body, b.receipts)
                if err != nil {
                        panic(err)
                }
                if err := b.lane.Verify(block.GasUsed()); err != nil {
                        panic(err)
                }
                if config.IsCancun(block.Number(), block.Time()) {
                        for _, s := range b.sidecars {
                                s.BlockNumber = block.Number()
                                s.BlockHash = block.Hash()
                        }
                        block = block.WithSidecars(b.sidecars)
                }
                root, err := statedb.Commit(b.header.Number.Uint64(), config.IsEIP158(b.header.Number), config.IsCancun(b.header.Number, b.header.Time))
                if err != nil {
                        panic(err)
                }
                if err = tdb.Commit(root, false); err != nil {
                        panic(err)
                }
                return block, receipts
        }

        for i := 0; i < n; i++ {
                statedb, err := state.New(parent.Root(), state.NewDatabase(stdb, nil))
                if err != nil {
                        panic(err)
                }
                block, receipts := genblock(i, parent, stdb, statedb)

                receiptsCount := len(receipts)
                txs := block.Transactions()
                if len(receipts) > len(txs) {
                        receipts = receipts[:len(txs)]
                } else if len(receipts) < len(txs) {
                        txs = txs[:len(receipts)]
                }
                var blobGasPrice *big.Int
                if block.ExcessBlobGas() != nil {
                        blobGasPrice = eip4844.CalcBlobFee(cm.config, block.Header())
                }
                if err := receipts.DeriveFields(config, block.Hash(), block.NumberU64(), block.Time(), block.BaseFee(), blobGasPrice, txs); err != nil {
                        panic(err)
                }
                receipts = receipts[:receiptsCount]

                cm.add(block, receipts)
                parent = block
        }
        return cm.chain, cm.receipts
}
