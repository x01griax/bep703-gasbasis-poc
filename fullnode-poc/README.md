# BEP-703 Payment Lane Gas-Basis Divergence — Full-Node PoC

Candidate: `BNB-BEP703-GASBASIS-DIVERGENCE-001` (PROVEN — L4 unit harnesses + L5/L6 full-node imports).

## Contents

- `genesis.json` — single-validator Parlia chain: every BSC fork at 0, Jenner at 0
  (lane bound from block 1), **Amsterdam at t=20**, the Rialto PaymentLane system
  contract at 0x…2007, a funded validator/sender, and an SSTORE-clearing "clearer"
  contract. Gas limit 2,000,000. Deterministic validator
  `0x6c9356587a1C0e4C9c1292fB34a2C5E0faC210bD` (key in the generator).
- `generate_block_rlp.go` + `generate_chain_helper.go` — the chain generator, run
  inside the pinned bsc checkout (`go run ./pocgen --out-dir <dir>`): builds the
  chain with bsc's own primitives and its **real Parlia engine** (block 1 carries
  Parlia's seven system-contract init transactions; both blocks are sealed with
  validator ECDSA over the Parlia sig-header preimage), packing the attack block
  with the lane and Amsterdam OFF — receipt-basis accounting, the only basis
  reth-bsc ever has. Emits `genesis.json`, `chain_no_bal.rlp` (block 2 without
  the Amsterdam `BlockAccessListHash`/`SlotNumber` fields — the header form
  reth-bsc produces at Amsterdam), `chain_with_bal.rlp` (block 2 with the fields —
  the form bsc itself requires post-Amsterdam), and `manifest.json`.
- `import_harness.rs` — an added binary for the reth-bsc checkout (pure file
  addition at `src/bin/import_harness.rs`; no existing code is modified): the
  standard `reth_cli_commands::import_core::import_blocks_from_file` import
  pipeline with the node-path global provider registration that the stock
  `reth-bsc import` command's wiring omits (documented tooling gap — the stock
  command aborts any BSC chain at the Execution stage with
  "Failed to get parent header from global header reader").
- `fullnode_poc.yml` — the GitHub Actions workflow: checks out both pinned
  commits, builds both clients, generates the chain, runs the four imports, and
  asserts each verdict with grep (a green run certifies the divergence).
- `manifest.json` + `pocgen.log` — hashes and gas figures (deterministic across
  machines; identical in every CI run and the local run).

## Verified verdict matrix (GitHub Actions run, 2026-10-09)

| client (pinned commit) | `chain_no_bal.rlp` | `chain_with_bal.rlp` |
|---|---|---|
| bsc Go `8cc60b24` — `geth init` + `geth import` | **REJECT block 2** — `header has nil BlockAccessListHash after Amsterdam` (block 1 with its seven system-contract init txs imports under full Parlia verification) | **REJECT block 2** — `payment lane inequality violated: gas used 1939200 payment 21000 quota 100000 limit 2000000` (EIP-7778 peak basis) |
| reth-bsc Rust `95884fd` — `import-harness` (same import pipeline) | **ACCEPT** — `Import complete. Total: 2/2 blocks, 66/66 transactions` | **REJECT block 2** — `invalid BlockAccessListHash, have 0x8767…, expected nil` (PR #499 pre-activation rejection) |

The first column is the required demonstration: **the exact same serialized RLP
chain receives opposite verdicts from the two compiled clients.** The second
column isolates the lane gas-basis verdict on the bsc side and documents the
third Amsterdam surface on the reth side — all three rooted in reth-bsc having
no Amsterdam fork.

## Empirical constants

gas limit 2,000,000; lane quota 100,000 (ratio 500, read from the Rialto
contract at parent state — `Loaded payment lane metadata ratio=500`); payment
gas 21,000; receipt-basis total 1,834,880; EIP-7778 peak total 1,939,200;
refund delta 104,320; genesis `0x6b3282af…29cc5c`; block 1
`0x9e7558bb…543c204f` (7 system-init txs); attack block hashes in
`manifest.json`.
