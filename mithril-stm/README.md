# Mithril-stm [![CI workflow](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml/badge.svg)](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml) [![crates.io](https://img.shields.io/crates/v/mithril-stm.svg)](https://crates.io/crates/mithril-stm) [![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/IntersectMBO/mithril/blob/main/LICENSE) [![Discord](https://img.shields.io/discord/500028886025895936.svg?logo=discord&style=flat-square)](https://discord.gg/5kaErDKDRq)

**This is a work in progress** 🛠

- `mithril-stm` is a Rust implementation of the scheme described in the paper [Mithril: Stake-based Threshold Multisignatures](https://eprint.iacr.org/2021/916.pdf) by Pyrros Chaidos and Aggelos Kiayias.
- The BLS12-381 signature library [blst](https://github.com/supranational/blst) is used as the backend for the implementation of STM.
- Three proof systems are available:
  - the [_concatenation proof system_](https://mithril.network/doc/mithril/advanced/mithril-protocol/aggregation/concatenation) (Section 4.3), currently used by the Mithril network. The aggregate signature carries one entry per contributing signer, together covering at least the `k` winning lottery indices the quorum requires, so its size follows the number of signers needed rather than `k` alone. Verification needs no trusted setup.
  - a [_non-recursive SNARK_](https://mithril.network/doc/mithril/advanced/mithril-protocol/aggregation/non-recursive-snark) proof system, in which the aggregate signature consists in a single succinct proof that the quorum was met, so a verifier checks one proof rather than every individual signature.
  - a [_recursive SNARK_](https://mithril.network/doc/mithril/advanced/mithril-protocol/aggregation/recursive-snark) proof system, in which each aggregate signature proves the whole chain behind it, so a verifier checks one proof rather than every aggregate signature since genesis.
- The two SNARK proof systems are **experimental**. They are gated behind the `future_snark` feature, which also requires one of `rustls` or `native-tls` for the trusted setup download.
- We implemented the concatenation proof system as batch proofs:
  - Individual signatures do not contain the Merkle path to prove membership of the avk. Instead, it is the role of the aggregator to generate such proofs. This allows for a more efficient implementation of batched membership proofs (or batched Merkle paths).
- Protocol documentation is given in [Mithril Protocol in depth](https://mithril.network/doc/mithril/mithril-protocol/protocol/).
- This library provides:
  - The implementation of the Stake-based Threshold Multisignatures
  - Key registration procedure for STM signatures
  - The three aggregation proof systems, with their aggregate signatures and verification keys
  - BLS signatures for the concatenation proof system, and standard and unique Schnorr signatures for the SNARK ones
  - The membership digest, hashing with Blake2b for the concatenation proof system and with Poseidon for the SNARK ones, which keeps the membership commitment aligned with the circuits
  - The Halo2 certificate and recursive circuits backing the two SNARK proof systems
  - The tests for the library functions and the STM scheme
  - Benchmark tests

## Pre-requisites

**Install Rust**

- Install a [correctly configured](https://www.rust-lang.org/learn/get-started) Rust toolchain (latest stable version).

- Install Build Tools `build-essential` and `m4`. For example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`.

## Download source code

```bash
# Download sources from github
git clone https://github.com/IntersectMBO/mithril

# Go to sources directory
cd mithril-stm
```

## Compiling the library

```shell
cargo build --release
```

## TLS backend

The `future_snark` feature downloads the SRS of the trusted setup over HTTPS and lets the caller pick the TLS backend. Enable exactly one of the `rustls` or `native-tls` features along with it:

```shell
cargo build --release --features future_snark,rustls
```

## Running the tests

For running rust tests, simply run (to run the tests faster, the use of `--release` flag is recommended):

```shell
cargo test --release
```

## Running the benches

```shell
cargo bench
```

## Examples

One runnable example per proof system, each covering aggregation and verification.

| Example                                                                                                                                  | Command                                                                                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| [Concatenation](https://github.com/IntersectMBO/mithril/blob/main/mithril-stm/examples/concatenation_aggregate_signature.rs)             | `cargo run -p mithril-stm --example concatenation_aggregate_signature`                                                |
| [Non-recursive SNARK](https://github.com/IntersectMBO/mithril/blob/main/mithril-stm/examples/non_recursive_snark_aggregate_signature.rs) | `cargo run --release -p mithril-stm --example non_recursive_snark_aggregate_signature --features future_snark,rustls` |
| [Recursive SNARK](https://github.com/IntersectMBO/mithril/blob/main/mithril-stm/examples/recursive_snark_aggregate_signature.rs)         | `cargo run --release -p mithril-stm --example recursive_snark_aggregate_signature --features future_snark,rustls`     |

The concatenation example runs in well under a second. The two SNARK examples generate real proofs and are substantially more demanding; each states its measured cost and its hardware requirement in its own header. The first run of either downloads the trusted setup, unless it is already cached.

[Key registration](https://github.com/IntersectMBO/mithril/blob/main/mithril-stm/examples/key_registration.rs) shows the registration phase on its own, treating each participant individually.

## Benchmarks

Here we give the benchmark results of STM for size and time. We run the benchmarks on macOS 12.6 on an Apple M1 Pro machine with 16 GB of RAM.

Note that the size of an individual signature with one valid index is **72 bytes** (48 bytes from `sigma`, 8 bytes from `party_index`, 8 bytes for the `length` of winning indices and at least 8 bytes for a single winning `index`) and increases linearly in the length of valid indices (where an index is 8 bytes).

```shell
+----------------------+
| Size of benchmarks   |
+----------------------+
| Results obtained by using the parameters suggested by the paper.
+----------------------+
+----------------------+
| Aggregate signatures |
+----------------------+
+----------------------+
| Hash: Blake2b 512    |
+----------------------+
k = 445 | m = 2728 | nr parties = 3000; 118760 bytes
+----------------------+
| Hash: Blake2b 256    |
+----------------------+
k = 445 | m = 2728 | nr parties = 3000; 99384 bytes
+----------------------+
+----------------------+
| Aggregate signatures |
+----------------------+
| Hash: Blake2b 512    |
+----------------------+
k = 554 | m = 3597 | nr parties = 3000; 133936 bytes
+----------------------+
| Hash: Blake2b 256    |
+----------------------+
k = 554 | m = 3597 | nr parties = 3000; 113728 bytes
```

```shell
STM/Blake2b/Key registration/k: 25, m: 150, nr_parties: 300
                        time:   [409.70 ms 426.81 ms 446.30 ms]
STM/Blake2b/Play all lotteries/k: 25, m: 150, nr_parties: 300
                        time:   [696.58 µs 697.62 µs 698.75 µs]
STM/Blake2b/Aggregation/k: 25, m: 150, nr_parties: 300
                        time:   [18.765 ms 18.775 ms 18.785 ms]
STM/Blake2b/Verification/k: 25, m: 150, nr_parties: 300
                        time:   [2.1577 ms 2.1715 ms 2.1915 ms]

STM/Blake2b/Key registration/k: 250, m: 1523, nr_parties: 2000
                        time:   [2.5807 s 2.5880 s 2.5961 s]
STM/Blake2b/Play all lotteries/k: 250, m: 1523, nr_parties: 2000
                        time:   [5.9318 ms 5.9447 ms 5.9582 ms]
STM/Blake2b/Aggregation/k: 250, m: 1523, nr_parties: 2000
                        time:   [190.81 ms 191.15 ms 191.54 ms]
STM/Blake2b/Verification/k: 250, m: 1523, nr_parties: 2000
                        time:   [13.944 ms 14.010 ms 14.077 ms]
```

## Certificate Circuit Benchmarks

Criterion benchmarks for the non-recursive `CertificateCircuit` (Halo2/KZG), gated behind the `future_snark` and `benchmark-internals` features.

Three metrics are measured per tier: VK/PK setup time, proof generation time, and proof verification time. Circuit cost and proof size are printed at startup.

### Hardware requirements

| Tier       | Min RAM | Typical machine                         |
| ---------- | ------- | --------------------------------------- |
| small      | < 1 GB  | Any                                     |
| medium     | ~1 GB   | Any                                     |
| large      | ~38 GB  | Apple M4 Max 48 GB or equivalent        |
| production | ~70 GB  | AWS r7i.12xlarge (384 GB) or equivalent |

### Reference results (Apple M4 Max, 48 GB, macOS, 3 000 signers, depth = 12)

| Tier        | Degree | k     | Setup   | Prove   | Verify  | Proof size |
| ----------- | ------ | ----- | ------- | ------- | ------- | ---------- |
| small       | 13     | 3     | ~196 ms | ~365 ms | ~4.1 ms | 3,600 B    |
| medium      | 16     | 32    | ~1.99 s | ~3.08 s | ~4.1 ms | 3,600 B    |
| large       | 21     | 1,024 | ~89 s   | ~111 s  | ~6.3 ms | 3,600 B    |
| production† | 22     | 1,944 | ~136 s  | ~362 s  | ~7 ms   | 3,824 B    |

†Production numbers from the SNARK Book (AWS r7i.12xlarge, 48 vCPU, 384 GB RAM). Requires ≥ 70 GB RAM.

### Running the benchmarks

Small and medium tiers use Criterion (10 samples, flat sampling — one iteration per sample):

```bash
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/small
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/medium
```

Large and production tiers run a single timed measurement (Criterion's 10-sample minimum is impractical at this scale):

```bash
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/large
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/production
```

## CI Parameter Benchmarks

Single-run benchmarks for the `CertificateCircuit` across small `k` values, covering both the real prover and the mock prover (`MockProver` from `midnight_proofs`). Used to determine the optimal circuit parameters for CI and end-to-end tests.

Gated behind the `future_snark` and `benchmark-internals` features.

### E2E extrapolation formula

The E2E columns are derived from individual timings using the following formula:

```text
E2E (mock prover) ≈ mock_circuit_gen + 80 × mock_prove
E2E (real prover) ≈ 80 × proof_gen
```

The constant 80 is the number of certificates generated in a standard Mithril end-to-end test run (with k = 70 or k = 140).

### Hardware requirements

All tiers complete in under 15 minutes on any developer machine with at least 4 GB RAM.

### Reference results (Apple M4 Max, 48 GB, macOS, 3 000 signers, depth = 12)

| k   | K   | mock_circuit_gen | mock_prove | mock_verify | e2e_mock | proof_gen | proof_verify | e2e_real |
| --- | --- | ---------------- | ---------- | ----------- | -------- | --------- | ------------ | -------- |
| 1   | 12  | ~25 ms           | ~62 ms     | ~11 ms      | ~5.0 s   | ~178 ms   | ~4 ms        | ~14.2 s  |
| 2   | 13  | ~51 ms           | ~121 ms    | ~16 ms      | ~9.7 s   | ~300 ms   | ~4 ms        | ~23.9 s  |
| 5   | 14  | ~133 ms          | ~300 ms    | ~33 ms      | ~24.1 s  | ~606 ms   | ~4 ms        | ~48.5 s  |
| 10  | 15  | ~285 ms          | ~592 ms    | ~60 ms      | ~47.6 s  | ~1.2 s    | ~4 ms        | ~94.2 s  |
| 20  | 16  | ~631 ms          | ~1.2 s     | ~115 ms     | ~94.8 s  | ~2.3 s    | ~4 ms        | ~184.9 s |
| 50  | 17  | ~1.8 s           | ~3.0 s     | ~268 ms     | ~238.7 s | ~5.3 s    | ~4 ms        | ~422.1 s |
| 100 | 18  | ~3.9 s           | ~5.9 s     | ~528 ms     | ~477.3 s | ~10.1 s   | ~4 ms        | ~811.4 s |

### Running the benchmarks

```bash
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_prover_modes
```
