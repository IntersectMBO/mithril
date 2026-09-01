# halo2_ivc Test Assets

## Purpose

All `halo2_ivc` test layers (`encoding`, `golden`, `in_circuit`, `off_circuit`,
`transitions`) share this committed asset set so normal test runs can validate
recursive behavior without regenerating the full proving flow.

The expensive proofs are generated manually through ignored tests in
`mithril-stm/src/circuits/halo2_ivc/tests/common/generators/asset_generation.rs`.
The recursive circuit verification key golden anchor is generated through an
ignored writer in `mithril-stm/src/circuits/halo2_ivc/tests/common/generators/verification_key.rs`.
All test layers load the stored outputs at compile time via `include_bytes!`,
while regeneration uses the file-based readers/writers.

## Asset Set

Reader helpers live in:

`mithril-stm/src/circuits/halo2_ivc/tests/common/asset_readers.rs`

All test layers assume these committed asset files are present in the worktree
at compile time. If they were removed locally, restore them from git before
rebuilding or regenerating:

```bash
git restore mithril-stm/src/circuits/halo2_ivc/tests/assets
```

The current asset set is:

- `verification_context.bin` — static verifier-side context (verifying key, global inputs, fixed bases, SRS)
- `recursive_chain_state.bin` — chain checkpoint after several recursive steps
- `genesis_step_output.bin` — output of the genesis base-case step
- `same_epoch_step_output.bin` — output of a same-epoch recursive step
- `recursive_step_output.bin` — output of a next-epoch recursive step
- `first_step_cert.bin` — first certificate produced from the genesis-base-case next-state; used to test the first real certificate step after the internal genesis IVC step (`step_counter == 1`)
- `recursive_step_output_accumulator_bytes.bin` — raw serialized accumulator extracted from `recursive_step_output.bin`; golden anchor for the encoding stability test
- `golden_recursive_circuit_verification_key.bin` — golden anchor for recursive circuit VK stability

## Dependency Order

1. `golden_recursive_circuit_verification_key.bin` — no dependencies
2. `verification_context.bin` — no dependencies
3. `genesis_step_output.bin` — no dependencies
4. `recursive_chain_state.bin` — no dependencies
5. `first_step_cert.bin` — no dependencies
6. `same_epoch_step_output.bin` — depends on `recursive_chain_state.bin`
7. `recursive_step_output.bin` — depends on `recursive_chain_state.bin`
8. `recursive_step_output_accumulator_bytes.bin` — depends on `recursive_step_output.bin`

## Generation Model

Asset generation uses:

- deterministic shared setup
- deterministic universal KZG parameters built with `ParamsKZG::unsafe_setup(...)`
- OS randomness for proof generation (signatures use `sign_unique` with the same RNG)

The recursive circuit verification key golden anchor uses deterministic unsafe
SRS generation and a small deterministic certificate circuit. It does not
generate proofs, but it does commit recursive circuit fixed columns into the VK.

The public-state evolution is reproducible at the semantic level. Proof-bearing
assets are not expected to be byte-identical across regenerations.

## How To Regenerate Everything

Run these commands from the repository root in order:

```bash
cargo test -p mithril-stm --features future_snark,rustls --release generate_golden_recursive_circuit_verification_key_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_verification_context_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_genesis_step_output_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_recursive_chain_state_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_same_epoch_step_output_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_recursive_step_output_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_first_step_cert_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_recursive_step_output_accumulator_bytes_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark,rustls --release generate_recursive_proof_accumulator_bytes_only -- --ignored --nocapture
```

These commands intentionally use `--release` because asset generation is a
manual workflow dominated by real proof generation.

## When Regeneration Is Needed

Regenerate the assets when one of these changes:

- recursive circuit logic
- recursive circuit fixed assignments or constants, including DST values
- recursive public input or state layout
- accumulator encoding
- recursive or certificate verifying key inputs
- verifier-side SRS data format
- generation setup or proving randomness model
- chained-flow replay contract for the recursive step assets

## Certificate Circuit

Asset generation uses `CertificateCircuit` from `circuits/halo2/circuit.rs` as the
certificate relation. The temporary duplicate `test_certificate.rs` has been
removed.
