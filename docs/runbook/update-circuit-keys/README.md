# Update the circuit keys after a change in one of the circuits

## When to use this guide

> [!IMPORTANT]
> Modifying any of the circuits keys is a breaking change that requires a re-genesis. The process of changing the keys is complex and cumbersome and requires thorough reviews to make sure it is done properly. It happens when a change is made to a circuit (recursive, non-recursive or both) or when the underlying libraries are updated and create modifications to the circuits. This guide is intended to be used in such cases so when one of the golden tests for the circuit verification key fails, either for the non-recursive or recursive certificate.

## Role and responsibilities

Updating any circuit verification key is a complex process so we need to make sure it is done correctly and that it is justified. In order to do so, several people need to be involved in the process.

The author of the change:

- Prepares the PR that includes the change
- Needs to justify the change in the circuit
- Checks that the changes did not increase the degree of the circuits
- Checks if the value `nr_pow2range_cols` (in `mithril/mithril-stm/src/circuits/halo2/circuit.rs`) can be decreased without increasing the degree of the circuit (a lower value can reduce the proof size)
- Updates the key values (golden and production)
- Ensures the approval of the tech lead and all cryptographers before the merge

Reviewers:

- Perform a thorough review of the change
- Analyse the justification of the change to make sure it is valid and cannot be avoided
- Make sure the degree of the circuits did not increase
- Reviews the update of the key values (golden and production)
- Run the tests for the integrity of the production keys

Commands to run the integrity tests:

```bash
cargo test -p mithril-stm --features future_snark,rustls --release integrity_test_for_non_recursive_production_key -- --ignored
```

and

```bash
cargo test -p mithril-stm --features future_snark,rustls --release integrity_test_for_recursive_production_key -- --ignored
```

Release manager:

- Prepares the release of this update
- Schedule the re-genesis of the certificate chain

## Update of the golden value

The author needs to update the golden value of the verification keys in the golden test in `mithril-stm/src/circuits/halo2/tests/golden/mod.rs` and `mithril-stm/src/circuits/halo2_ivc/tests/golden/mod.rs`. The failing tests (in red) need to be updated by changing the golden value used (in the golden files) to turn them green again.

## Update of the production circuit verification key

To update the production circuit verification keys, one needs to run the following commands:

```bash
cargo test -p mithril-stm --features future_snark,rustls --release write_non_recursive_circuit_verification_key_for_production_to_file -- --ignored
```

and

```bash
cargo test -p mithril-stm --features future_snark,rustls --release write_recursive_circuit_verification_key_for_production_to_file -- --ignored
```

that will update the files holding the values of the production keys, `mithril-stm/src/circuits/halo2/non_recursive_circuit_verification_key_for_production.bin` and `mithril-stm/src/circuits/halo2_ivc/recursive_circuit_verification_key_for_production.bin`.

## Scheduling of the re-genesis

Once the review is done and all the circuit verification keys are updated, the release manager can schedule the re-genesis. Re-genesis is scheduled with the release of the next distribution where the new circuit is deployed. It goes through the sequence:

- `testing-preview`: re-genesis once the PR is merged
- `pre-release-preview`: re-genesis once the new distribution pre-release is deployed
- `release-mainnet` and `release-preprod`: re-genesis once the new distribution is deployed
