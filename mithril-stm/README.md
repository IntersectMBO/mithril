# Mithril-stm [![CI workflow](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml/badge.svg)](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml) [![crates.io](https://img.shields.io/crates/v/mithril-stm.svg)](https://crates.io/crates/mithril-stm) [![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/IntersectMBO/mithril/blob/main/LICENSE) [![Discord](https://img.shields.io/discord/500028886025895936.svg?logo=discord&style=flat-square)](https://discord.gg/5kaErDKDRq)

**This is a work in progress** 🛠

- `mithril-stm` is a Rust implementation of the scheme described in the paper [Mithril: Stake-based Threshold Multisignatures](https://eprint.iacr.org/2021/916.pdf) by Pyrros Chaidos and Aggelos Kiayias.
- The BLS12-381 signature library [blst](https://github.com/supranational/blst) is used as the backend for the implementation of STM.
- This implementation supports the _trivial concatenation proof system_ (Section 4.3). Other proof systems such as _Bulletproofs_ or _Halo2_ are not supported in this version.
- We implemented the concatenation proof system as batch proofs:
  - Individual signatures do not contain the Merkle path to prove membership of the avk. Instead, it is the role of the aggregator to generate such proofs. This allows for a more efficient implementation of batched membership proofs (or batched Merkle paths).
- Protocol documentation is given in [Mithril Protocol in depth](https://mithril.network/doc/mithril/mithril-protocol/protocol/).
- The API also includes _core verification_. This functionality allows a full node verifier (`CoreVerifier`) that is
  able to verify the signatures that are generated without the registration information, i.e., `avk`. A
  `CoreVerifier` is assumed to know identities of the signers, so, it does not need to check the registration.

- This library provides:
  - The implementation of the Stake-based Threshold Multisignatures
  - The implementation of `CoreVerifier`
  - Key registration procedure for STM signatures
  - The tests for the library functions, STM scheme, and `CoreVerifier`
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

## Example

The following is a simple example of the STM implementation:

```rust
use blake2::{digest::consts::U32, Blake2b};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;

use mithril_stm::{
    AggregateSignatureType, AggregationError, AncillaryGenesisData, AncillaryProofInput, Clerk,
    Initializer, KeyRegistration, Parameters, Signer, SingleSignature,
    MithrilMembershipDigest, AggregateVerificationKey,
};

type D = MithrilMembershipDigest;

let nparties = 32;
let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
let mut msg = [0u8; 16];
rng.fill_bytes(&mut msg);

//////////////////////////
// initialization phase //
//////////////////////////

let params = Parameters {
    k: 357,
    m: 2642,
    phi_f: 0.2,
};

let parties = (0..nparties)
    .into_iter()
    .map(|_| 1 + (rng.next_u64() % 9999))
    .collect::<Vec<_>>();

let mut key_reg = KeyRegistration::initialize();

let mut ps: Vec<Initializer> = Vec::with_capacity(nparties as usize);
for stake in parties {
    let p = Initializer::new(params, stake, &mut rng);
    key_reg.register(
        p.stake,
        &p.get_verification_key_proof_of_possession_for_concatenation(),
        #[cfg(feature = "future_snark")] p.schnorr_verification_key,
    )
    .unwrap();
    ps.push(p);
}

let closed_reg = key_reg.close_registration(&params).unwrap();

let ps = ps
    .into_par_iter()
    .map(|p| p.try_create_signer(&closed_reg).unwrap())
    .collect::<Vec<Signer<D>>>();

/////////////////////
// operation phase //
/////////////////////

let sigs = ps
    .par_iter()
    .filter_map(|p| p.create_single_signature(&msg).ok())
    .collect::<Vec<SingleSignature>>();

let clerk = Clerk::new_clerk_from_signer(&ps[0]);
let avk: AggregateVerificationKey<D>  = clerk.compute_aggregate_verification_key();

// Check all parties can verify every sig
for s in sigs.iter() {
    let entry = closed_reg.get_registration_entry_for_index(&s.signer_index).unwrap();
    assert!(s.verify::<D>(&params, &entry.get_verification_key_for_concatenation(), &entry.get_stake(), &avk, &msg, #[cfg(feature = "future_snark")] None).is_ok(), "Verification failed");
}

// Aggregate a concatenation proof with random parties
let ancillary_input = AncillaryProofInput::new(None, AncillaryGenesisData::new(#[cfg(feature = "future_snark")] Vec::new(), #[cfg(feature = "future_snark")] None, #[cfg(feature = "future_snark")] None), #[cfg(feature = "future_snark")] Vec::new());
let msig = clerk.aggregate_signatures_with_type(&sigs, &msg, AggregateSignatureType::Concatenation, ancillary_input);

match msig {
    Ok((aggr, ancillary_proof_output)) => {
        println!("Aggregate ok");
        assert!(aggr.verify(&msg, &clerk.compute_aggregate_verification_key(), &params, ancillary_proof_output.verifier_data().cloned(), None).is_ok());
    }
    Err(error) => match error.downcast_ref::<AggregationError>() {
        Some(AggregationError::NotEnoughSignatures(n, k)) => {
            println!("Not enough signatures");
            assert!(n < &params.k && k == &params.k)
        },

        Some(AggregationError::UnsupportedProofSystem(aggregate_signature_type)) => {
            println!("Unsupported proof system: {:?}", aggregate_signature_type);
        },
        _ => {
            println!("Unexpected error during aggregation: {:?}", error);
        }
    },
}
```

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
