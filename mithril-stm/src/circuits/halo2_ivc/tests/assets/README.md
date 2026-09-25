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

- `verification_context.asset` — static verifier-side context (verifying key, global inputs, fixed bases, SRS)
- `recursive_chain_state.asset` — chain checkpoint after several recursive steps
- `genesis_step_output.asset` — output of the genesis base-case step
- `same_epoch_step_output.asset` — output of a same-epoch recursive step
- `recursive_step_output.asset` — output of a next-epoch recursive step
- `first_step_cert.asset` — first certificate produced from the genesis-base-case next-state; used to test the first real certificate step after the internal genesis IVC step (`step_counter == 1`)
- `genesis_benchmark_fixture.asset` — genesis proving inputs (raw genesis message, genesis verification key, genesis signature, protocol-message preimage) the IVC benchmarks use to build a `Global` and run a genesis proving step
- `recursive_step_output_accumulator_bytes.asset` — raw serialized accumulator extracted from `recursive_step_output.asset`; golden anchor for the encoding stability test
- `recursive_proof_accumulator_bytes.asset` — raw serialized accumulator obtained by verifying the IVC proof of `recursive_chain_state.asset`; golden anchor for the encoding stability test
- `golden_recursive_circuit_verification_key.asset` — golden anchor for recursive circuit VK stability

## Dependency Order

1. `golden_recursive_circuit_verification_key.asset` — no dependencies
2. `verification_context.asset` — no dependencies
3. `genesis_step_output.asset` — no dependencies
4. `recursive_chain_state.asset` — no dependencies
5. `first_step_cert.asset` — no dependencies
6. `genesis_benchmark_fixture.asset` — no dependencies
7. `same_epoch_step_output.asset` — depends on `recursive_chain_state.asset`
8. `recursive_step_output.asset` — depends on `recursive_chain_state.asset`
9. `recursive_step_output_accumulator_bytes.asset` — depends on `recursive_step_output.asset`
10. `recursive_proof_accumulator_bytes.asset` — depends on `verification_context.asset` and `recursive_chain_state.asset`

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
cargo test -p mithril-stm --features future_snark --release generate_golden_recursive_circuit_verification_key_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_verification_context_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_genesis_step_output_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_recursive_chain_state_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_same_epoch_step_output_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_recursive_step_output_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_first_step_cert_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_genesis_benchmark_fixture_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_recursive_step_output_accumulator_bytes_only -- --ignored --nocapture
cargo test -p mithril-stm --features future_snark --release generate_recursive_proof_accumulator_bytes_only -- --ignored --nocapture
```

These commands intentionally use `--release` because asset generation is a
manual workflow dominated by real proof generation.

## Source Constants To Update

Regenerating the assets is only half the work. Four constants are pinned in source and are not
written by any generator.

| Constant                                  | File                                             | Test that computes it                                  | Computed value appears |
| ----------------------------------------- | ------------------------------------------------ | ------------------------------------------------------ | ---------------------- |
| production recursive key digest           | `circuits/verification_key_digest.rs`            | `golden_digests_of_production_circuit_keys`            | right                  |
| verification-context recursive key digest | `circuits/verification_key_digest.rs`            | `golden_digests_of_embedded_verification_context_keys` | right                  |
| `GOLDEN_R` combiner challenge             | `proof_system/halo2_ivc_snark/proof.rs`          | `golden_combiner_r_for_stored_recursive_step_output`   | left                   |
| `EXPECTED_IVC_ANCILLARY_DIGEST`           | `protocol/aggregate_signature/ancillary_data.rs` | `ivc_ancillary_encoding_is_byte_stable`                | left                   |

The assertions are not written the same way round, so check the last column before copying a value:
taking the wrong side copies the old expected value back, leaving the test failing.

Each constant binds something different, which is what decides whether it moves:

- The two key digests bind the raw verifying key's **transcript representation**.
- `GOLDEN_R` binds the **proof verification transcript and accumulator**.
- `EXPECTED_IVC_ANCILLARY_DIGEST` binds the **complete encoded CBOR**, embedded keys included.

These four checks compute golden values; they do not establish validity. Confirm the regenerated keys
and proofs pass their integrity and verification checks before updating any constant — the
`GOLDEN_R` test in particular prepares the transcript without performing the final pairing check —
then rerun the golden checks.

So the rule is not to predict which will move. Rerun all four checks after regenerating, and update
only those whose inputs you deliberately changed. Some cases are counter-intuitive: a constraint
system change can alter a transcript representation without altering the serialized commitments; a
key encoding change moves only the ancillary digest, since the other three never see the envelope;
and regenerating a randomized proof can move `GOLDEN_R` even when the circuit identity is untouched.

If a value changes and you cannot say which input caused it, stop and find out before updating it.

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
