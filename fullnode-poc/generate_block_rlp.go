// BEP-703 Payment Lane gas-basis divergence — full-node PoC chain generator.
//
// Builds, with bnb-chain/bsc's own primitives and the REAL Parlia consensus
// engine at the pinned commit:
//
//   genesis.json        — a single-validator Parlia chain: every BSC fork
//                         active from genesis, Jenner at 0 (lane bound from
//                         block 1), Amsterdam at t=20, the Rialto PaymentLane
//                         system contract pre-installed at 0x…2007, a funded
//                         validator/sender account and the SSTORE-clearing
//                         "clearer" contract.
//   chain_no_bal.rlp    — block 1 (t=10, pre-Amsterdam, carries Parlia's
//                         seven block-1 system-contract init transactions,
//                         produced by the real engine) followed by block 2
//                         (t=20, the first Amsterdam block) with 58
//                         transactions: 2 high-refund SSTORE-clearing txs,
//                         1 payment-lane value transfer, 55 plain general
//                         transfers. Block 2's header carries NO
//                         BlockAccessListHash/SlotNumber — exactly the header
//                         form reth-bsc produces at Amsterdam, since it has
//                         no Amsterdam fork — and receipt-basis gasUsed,
//                         exactly the accounting reth-bsc books.
//                         bsc (Amsterdam ON) must REJECT block 2; reth-bsc
//                         must ACCEPT the whole chain.
//   chain_with_bal.rlp  — the same chain with block 2 carrying the two
//                         trailing Amsterdam header fields, i.e. the header
//                         form bsc itself requires post-Amsterdam. bsc
//                         accepts the header, executes, and REJECTS block 2
//                         on the payment-lane inequality (EIP-7778 peak
//                         basis); reth-bsc REJECTS the fields' presence
//                         pre-activation (PR #499).
//   manifest.json       — hashes and gas figures for cross-checking logs.
//
// The chain is generated with the lane and Amsterdam switched OFF (the
// receipt-basis packing reth-bsc's producer performs), then imported under a
// genesis that schedules Jenner at 0 and Amsterdam at 20. The genesis block
// bytes are identical under both configurations (Amsterdam is inactive at the
// genesis timestamp 0); the generator asserts that on every run.
package main

import (
        "encoding/json"
        "flag"
        "fmt"
        "math/big"
        "os"
        "path/filepath"

        "github.com/ethereum/go-ethereum/accounts"
        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/consensus/parlia"
        "github.com/ethereum/go-ethereum/core"
        "github.com/ethereum/go-ethereum/core/forkid"
        "github.com/ethereum/go-ethereum/core/paymentlane"
        "github.com/ethereum/go-ethereum/core/systemcontracts/jenner"
        "github.com/ethereum/go-ethereum/core/types"
        "github.com/ethereum/go-ethereum/crypto"
        "github.com/ethereum/go-ethereum/params"
        "github.com/ethereum/go-ethereum/rlp"
        "github.com/ethereum/go-ethereum/trie"
)

// ---------------------------------------------------------------------------
// PoC parameters (transaction mix identical to
// core/payment_lane_gas_basis_poc_test.go)
// ---------------------------------------------------------------------------

const (
        pocGasLimit      = 2_000_000
        pocClearerTxs    = 2       // high-refund SSTORE-clearing txs
        pocClearedSlots  = 100     // storage slots cleared per tx
        pocClearerGasCap = 600_000 // tx gas limit headroom for a clearer
        pocFillerTxs     = 55      // plain zero-value general transfers

        pocChainID       = 714
        pocAmsterdamTime = 20 // first Amsterdam block is height 2 (t=20)
)

// Deterministic single validator / transaction sender.
const validatorKeyHex = "b7035a67e1177ad4e901695e1b4b9ee17ae16c8431dfeb0b8fb00be1381e0e01"

// pocClearingCode returns runtime bytecode that clears storage slots 0..99
// (PUSH1 0; PUSH2 <slot>; SSTORE; per slot, then STOP). Each clear on a cold,
// non-zero slot costs 2100 (cold) + 2900 (clear) gas and refunds 4800, capped
// by EIP-3529 at used/5 — the maximum refund spread the quotient allows.
func pocClearingCode() []byte {
        code := make([]byte, 0, pocClearedSlots*6+1)
        for i := 0; i < pocClearedSlots; i++ {
                code = append(code, 0x60, 0x00)                     // PUSH1 0 (new value)
                code = append(code, 0x61, byte(i>>8), byte(i&0xff)) // PUSH2 <slot>
                code = append(code, 0x55)                           // SSTORE
        }
        return append(code, 0x00) // STOP
}

// pocClearingStorage pre-sets slots 0..99 to 1 so each SSTORE is a
// non-zero-to-zero clear earning the 4800-gas refund.
func pocClearingStorage() map[common.Hash]common.Hash {
        storage := make(map[common.Hash]common.Hash, pocClearedSlots)
        one := common.BigToHash(big.NewInt(1))
        for i := 0; i < pocClearedSlots; i++ {
                storage[common.BigToHash(big.NewInt(int64(i)))] = one
        }
        return storage
}

// pocConfig builds the chain configuration: every BSC fork at 0, Jenner at 0
// (lane bound from block 1), Amsterdam at the given timestamp.
func pocConfig(amsterdam uint64) *params.ChainConfig {
        config := *params.ParliaTestChainConfig
        config.ChainID = big.NewInt(pocChainID)
        config.HaberTime = new(uint64)
        config.HaberFixTime = new(uint64)
        config.BohrTime = new(uint64)
        config.PascalTime = new(uint64)
        config.PragueTime = new(uint64)
        config.LorentzTime = new(uint64)
        config.MaxwellTime = new(uint64)
        config.FermiTime = new(uint64)
        config.OsakaTime = new(uint64)
        config.MendelTime = new(uint64)
        config.PasteurTime = new(uint64)
        jennerTime := uint64(0)
        config.JennerTime = &jennerTime
        amsterdamTime := amsterdam
        config.AmsterdamTime = &amsterdamTime
        config.BlobScheduleConfig = &params.BlobScheduleConfig{
                Cancun:    params.DefaultCancunBlobConfig,
                Prague:    params.DefaultPragueBlobConfigBSC,
                Osaka:     params.DefaultOsakaBlobConfigBSC,
                Amsterdam: params.DefaultCancunBlobConfig,
        }
        return &config
}

// pocGenesisExtra builds the genesis extra-data: 28-byte vanity + 4-byte
// next-fork-hash slot + 1 validator (20-byte address + 48-byte zero BLS vote
// key) + 1-byte turn length + 65-byte zero seal. 167 bytes total — the exact
// layout geth's parseValidators and reth-bsc's parse_validators_from_header
// both require for a post-Luban, post-Bohr genesis checkpoint header.
// Turn length 2 lets the single validator sign two consecutive blocks.
func pocGenesisExtra(validator common.Address) []byte {
        extra := make([]byte, 0, 167)
        extra = append(extra, make([]byte, 28)...) // vanity
        extra = append(extra, make([]byte, 4)...)  // next-fork-hash slot (content unverified)
        extra = append(extra, byte(1))             // validator count (post-Luban format)
        extra = append(extra, validator.Bytes()...)
        extra = append(extra, make([]byte, 48)...) // zero BLS vote public key (types.BLSPublicKeyLength)
        extra = append(extra, byte(2))             // turn length (post-Bohr format)
        extra = append(extra, make([]byte, 65)...) // zero seal
        return extra
}

func main() {
        outDir := flag.String("out-dir", ".", "output directory")
        flag.Parse()

        priv, err := crypto.HexToECDSA(validatorKeyHex)
        if err != nil {
                panic(err)
        }
        validator := crypto.PubkeyToAddress(priv.PublicKey)

        // Final configuration (what the importers run with) and the generation
        // configuration (lane + Amsterdam far: receipt-basis packing).
        far := ^uint64(0) >> 1
        finalCfg := pocConfig(pocAmsterdamTime)
        genCfg := pocConfig(far)

        // The lane system contract (Rialto PaymentLane bytecode, read from the
        // repo's own embedded system contracts) and the funded accounts.
        rialtoCode, err := decodeHex(jenner.RialtoPaymentLaneContract)
        if err != nil {
                panic(fmt.Errorf("decoding Rialto PaymentLane contract: %v", err))
        }
        clearer := common.Address{0xdd}
        alloc := types.GenesisAlloc{
                paymentlane.ContractAddress: {Code: rialtoCode, Balance: common.Big0},
                validator:                   {Balance: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1e6))},
                clearer:                     {Code: pocClearingCode(), Storage: pocClearingStorage(), Balance: common.Big0},
        }
        genesisExtra := pocGenesisExtra(validator)

        newGenesis := func(cfg *params.ChainConfig) *core.Genesis {
                return &core.Genesis{
                        Config:        cfg,
                        GasLimit:      pocGasLimit,
                        ExtraData:     genesisExtra,
                        Difficulty:    big.NewInt(1),
                        BaseFee:       big.NewInt(params.GWei),
                        ExcessBlobGas: new(uint64),
                        BlobGasUsed:   new(uint64),
                        Alloc:         alloc,
                }
        }
        finalGenesis := newGenesis(finalCfg)
        genGenesis := newGenesis(genCfg)

        // The genesis block must be byte-identical under both configurations
        // (Amsterdam is inactive at timestamp 0 in both). Assert it.
        if finalGenesis.ToBlock().Hash() != genGenesis.ToBlock().Hash() {
                panic("genesis hash differs between generation and final configuration")
        }
        genesisHash := finalGenesis.ToBlock().Hash()
        fmt.Printf("genesis hash: %s\n", genesisHash.Hex())

        // Generate the chain with the REAL Parlia engine, in two passes with a
        // seal in between: the engine's Finalize appends block 1's seven
        // system-contract init transactions exactly as a real validator would
        // seal them, and block 2 must be generated on top of the SEALED block
        // 1 (its parent hash and the EIP-2935 parent-hash history record
        // commit to the sealed hash). Authorize() supplies the validator
        // identity and the system-tx signer, mirroring the miner on a live node.
        db, genesisBlock := core.PrepareBep703PoCChain(genGenesis)
        engine := parlia.New(genCfg, db, nil, genesisHash)
        signTxFn := func(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
                if account.Address != validator {
                        return nil, fmt.Errorf("unexpected signing account %s", account.Address)
                }
                return types.SignTx(tx, types.LatestSignerForChainID(chainID), priv)
        }
        signFn := func(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
                return crypto.Sign(crypto.Keccak256Hash(data).Bytes(), priv)
        }
        engine.Authorize(validator, signFn, signTxFn)

        // parliaExtra builds the 97-byte non-epoch extra-data: 28-byte vanity +
        // 4-byte next-fork-hash + 65-byte seal space.
        parliaExtra := func(number uint64, time uint64) []byte {
                nextForkHash := forkid.NextForkHash(finalCfg, genesisHash, finalGenesis.Timestamp, number, time)
                extra := make([]byte, 0, 97)
                extra = append(extra, make([]byte, 28)...)
                extra = append(extra, nextForkHash[:]...)
                extra = append(extra, make([]byte, 65)...)
                return extra
        }

        // Pass 1: block 1 (t=10, pre-Amsterdam) — benign, only the engine's
        // seven system-contract init transactions.
        blocks1, rs1 := core.GenerateBep703PoCBlocks(db, genesisBlock, engine, genCfg, 1, func(i int, b *core.BlockGen) {
                b.SetCoinbase(validator)
                b.SetDifficulty(big.NewInt(2))
                b.SetExtra(parliaExtra(1, 10))
        })
        blk1 := blocks1[0]

        // Seal block 1 with an ECDSA signature over types.SealHash (the
        // chain-id-prefixed sig header with the 65-byte seal space stripped) —
        // the preimage consensus/parlia.ecrecover recovers on both clients.
        seal := func(blk *types.Block, rs types.Receipts, withBalFields bool) *types.Block {
                h := types.CopyHeader(blk.Header())
                h.Coinbase = validator
                h.Difficulty = big.NewInt(2) // diffInTurn: single validator is always in turn
                h.Nonce = types.BlockNonce{}
                h.MixDigest = common.Hash{} // Lorentz millisecond remainder = 0
                if withBalFields {
                        // Amsterdam-era trailing rlp:"optional" fields — present, as bsc
                        // itself requires them post-Amsterdam. (The import path verifies
                        // presence only; content is not recomputed at this commit.)
                        balHash := crypto.Keccak256Hash([]byte("bep703-poc-empty-bal"))
                        h.BlockAccessListHash = &balHash
                        h.SlotNumber = new(uint64)
                }
                sig, err := crypto.Sign(types.SealHash(h, finalCfg.ChainID).Bytes(), priv)
                if err != nil {
                        panic(err)
                }
                copy(h.Extra[len(h.Extra)-65:], sig)
                body := &types.Body{Transactions: blk.Transactions(), Withdrawals: []*types.Withdrawal{}}
                return types.NewBlock(h, body, rs, trie.NewStackTrie(nil))
        }

        sealed1 := seal(blk1, rs1[0], false)
        fmt.Printf("block 1: txs=%d gasUsed=%d (system-contract init block) hash=%s\n", blk1.Transactions().Len(), blk1.GasUsed(), sealed1.Hash().Hex())

        // Pass 2: block 2 (t=20, the first Amsterdam block) on top of the
        // SEALED block 1. The transaction set is packed with the lane OFF and
        // Amsterdam OFF — receipt-basis accounting, the only basis reth-bsc
        // ever has. This mirrors core/payment_lane_gas_basis_poc_test.go.
        signer := types.LatestSigner(genCfg)
        blocks2, rs2 := core.GenerateBep703PoCBlocks(db, sealed1, engine, genCfg, 1, func(i int, b *core.BlockGen) {
                b.SetCoinbase(validator)
                b.SetDifficulty(big.NewInt(2))
                b.SetExtra(parliaExtra(2, 20))
                for c := 0; c < pocClearerTxs; c++ { // high-refund general txs
                        tx, err := types.SignNewTx(priv, signer, &types.LegacyTx{
                                Nonce: b.TxNonce(validator), To: &clearer, Value: common.Big0,
                                Gas: pocClearerGasCap, GasPrice: big.NewInt(params.GWei),
                        })
                        if err != nil {
                                panic(err)
                        }
                        b.AddTx(tx)
                }
                // One payment-lane transaction: a bare value transfer is payment gas.
                paymentTo := common.Address{0xaa}
                tx, err := types.SignNewTx(priv, signer, &types.LegacyTx{
                        Nonce: b.TxNonce(validator), To: &paymentTo, Value: common.Big1,
                        Gas: params.TxGas, GasPrice: big.NewInt(params.GWei),
                })
                if err != nil {
                        panic(err)
                }
                b.AddTx(tx)
                for f := 0; f < pocFillerTxs; f++ { // plain general transfers
                        fillerTo := common.Address{0xbb}
                        tx, err := types.SignNewTx(priv, signer, &types.LegacyTx{
                                Nonce: b.TxNonce(validator), To: &fillerTo, Value: common.Big0,
                                Gas: params.TxGas, GasPrice: big.NewInt(params.GWei),
                        })
                        if err != nil {
                                panic(err)
                        }
                        b.AddTx(tx)
                }
        })
        blk2 := blocks2[0]
        if blk2.ParentHash() != sealed1.Hash() {
                panic("block 2 does not extend the sealed block 1")
        }
        fmt.Printf("block 2: txs=%d receipt-basis gasUsed=%d (attack block, header)\n", blk2.Transactions().Len(), blk2.GasUsed())

        if err := os.MkdirAll(*outDir, 0o755); err != nil {
                panic(err)
        }

        // Block 1 is shared byte-for-byte between the two chain files.
        sealed2NoBal := seal(blk2, rs2[0], false)
        sealed2WithBal := seal(blk2, rs2[0], true)

        writeChain := func(name string, b1, b2 *types.Block) common.Hash {
                f, err := os.Create(filepath.Join(*outDir, name))
                if err != nil {
                        panic(err)
                }
                defer f.Close()
                if err := rlp.Encode(f, b1); err != nil {
                        panic(err)
                }
                if err := rlp.Encode(f, b2); err != nil {
                        panic(err)
                }
                fmt.Printf("%s: block1=%s block2=%s\n", name, b1.Hash().Hex(), b2.Hash().Hex())
                return b2.Hash()
        }
        noBalHash := writeChain("chain_no_bal.rlp", sealed1, sealed2NoBal)
        withBalHash := writeChain("chain_with_bal.rlp", sealed1, sealed2WithBal)

        // genesis.json: the FINAL configuration importers run under.
        genesisJSON, err := json.MarshalIndent(finalGenesis, "", "  ")
        if err != nil {
                panic(err)
        }
        if err := os.WriteFile(filepath.Join(*outDir, "genesis.json"), genesisJSON, 0o644); err != nil {
                panic(err)
        }

        manifest := map[string]any{
                "chain_id":               pocChainID,
                "gas_limit":              pocGasLimit,
                "lane_quota":             100_000,
                "payment_gas":            21_000,
                "block2_receipt_gas_used": blk2.GasUsed(),
                "expected_peak_gas_used": blk2.GasUsed() + 104_320,
                "refund_delta":           104_320,
                "amsterdam_time":         pocAmsterdamTime,
                "jenner_time":            0,
                "validator":              validator.Hex(),
                "genesis_hash":           genesisHash.Hex(),
                "block1_hash":            sealed1.Hash().Hex(),
                "chain_no_bal_block2_hash": noBalHash.Hex(),
                "chain_with_bal_block2_hash": withBalHash.Hex(),
                "block1_txs":             blk1.Transactions().Len(),
                "block2_txs":             blk2.Transactions().Len(),
        }
        manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
        if err != nil {
                panic(err)
        }
        if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), manifestJSON, 0o644); err != nil {
                panic(err)
        }
        fmt.Println("wrote genesis.json, chain_no_bal.rlp, chain_with_bal.rlp, manifest.json")
}

// decodeHex decodes a hex string that may or may not carry a 0x prefix and
// may contain whitespace (the embedded system contract strings do).
func decodeHex(s string) ([]byte, error) {
        clean := ""
        for _, r := range s {
                switch r {
                case ' ', '\t', '\n', '\r':
                default:
                        clean += string(r)
                }
        }
        if len(clean) >= 2 && clean[:2] == "0x" {
                clean = clean[2:]
        }
        if len(clean)%2 == 1 {
                clean = "0" + clean
        }
        out := make([]byte, len(clean)/2)
        for i := 0; i < len(out); i++ {
                hi := hexVal(clean[i*2])
                lo := hexVal(clean[i*2+1])
                if hi < 0 || lo < 0 {
                        return nil, fmt.Errorf("invalid hex byte %q", clean[i*2:i*2+2])
                }
                out[i] = byte(hi<<4 | lo)
        }
        return out, nil
}

func hexVal(c byte) int {
        switch {
        case c >= '0' && c <= '9':
                return int(c - '0')
        case c >= 'a' && c <= 'f':
                return int(c-'a') + 10
        case c >= 'A' && c <= 'F':
                return int(c-'A') + 10
        }
        return -1
}
