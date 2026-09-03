# `mithril-stm` benchmarks

This folder holds the benchmark harnesses for `mithril-stm`. The two Halo2 **circuit** benchmark suites are
the focus of this document:

- the **recursive IVC circuit** — [`halo2_ivc_snark`](halo2_ivc_snark.rs), which ships a small **CLI** to
  list and select what runs;
- the **non-recursive certificate circuit** — [`halo2_snark`](halo2_snark.rs) and
  [`halo2_prover_modes`](halo2_prover_modes.rs).

Every harness is declared `harness = false` in `Cargo.toml` (a custom `main`, or a Criterion-generated
`main`), and each delegates to a **benchmark-only façade** in the library —
`circuits::halo2_ivc::bench::helpers` and `circuits::halo2::bench::helpers` — so the measured operations run
the same production code paths. (The one exception is the IVC `verify/kzg_opening` diagnostic, which
reproduces just the KZG-opening sub-step of `IvcProof::verify`.) The façades live in the library (not here)
because they call `pub(crate)`/private production code; these harness files are the thin public-API
front-ends.

## Prerequisites

- **Toolchain:** the crate's dev-dependencies require the latest stable Rust toolchain.
- **Features:** all circuit benches require `--features future_snark,rustls,benchmark-internals`. `future_snark`
  downloads the SRS over HTTPS and needs a TLS backend: pick either `rustls` or `native-tls`.
- **Resources:** the recursive circuit runs at degree 19 (GB-scale RAM, minutes per proof); the non-recursive
  `production` tier needs ≥ 70 GB RAM (server-class). Scope your run accordingly.

General invocation:

```bash
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench <name> -- <args>
```

Everything after `--` is passed to the benchmark binary.

## Benchmark index

| Bench                                             | Circuit / area                         | What it measures                                                                  | Selection                                           |
| ------------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------- |
| `halo2_ivc_snark`                                 | recursive IVC circuit                  | prove / verify / fold per transition path + setup (cold/warm), single observation | **custom CLI** (`--list`, literal id/prefix filter) |
| `halo2_snark`                                     | non-recursive certificate circuit      | constraints, VK size, proof size, prove & verify time across parameter tiers      | Criterion (filter `certificate/<tier>`)             |
| `halo2_prover_modes`                              | non-recursive certificate circuit      | mock-prover vs real-prover cost projected to an e2e run, across `k` tiers         | no arguments                                        |
| `multi_sig`, `schnorr_sig`, `stm`, `size_benches` | other crate areas (not Halo2 circuits) | see each file                                                                     | —                                                   |

---

## Recursive IVC circuit — `halo2_ivc_snark`

Exercises the recursive IVC prover/verifier at its production degree (19), using the small committed
certificate as the inner proof. It measures, for each of the three transition **paths** — `genesis`,
`same_epoch`, `next_epoch`:

- **prove** with each transcript: `prove/poseidon`, `prove/blake2b`;
- **verify**: `verify/full` (message binding + KZG opening + folded-accumulator pairing) and
  `verify/kzg_opening` (the isolated opening);
- **fold**: the off-circuit accumulator fold (`genesis` has none — it is a passthrough);

plus **setup** measured cold vs warm: `setup/srs` and `setup/keys`. Each measurement is a single
observation, printed as a small table when the run finishes.

### The CLI

Because a full run is expensive, this harness parses its own arguments (fail-closed, so a stray option can
never silently trigger a multi-minute key generation). Arguments go after `--`:

```bash
# List every benchmark id — no benchmark setup or key generation (Cargo may still compile the target):
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark -- --list

# Show usage:
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark -- --help

# Run everything (tens of minutes; performs TWO recursive key generations — the shared per-path
# environment and the cold setup/keys measurement — then all proofs):
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark

# Run a subset: pass ONE literal id or prefix (substring match against the ids from --list).
# One transition path (prove + verify + fold):
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark -- ivc/same_epoch
# One path's verification only:
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark -- ivc/genesis/verify
# SRS cold vs warm (no key generation):
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark -- ivc/setup/srs
# Keys cold vs warm (cold performs a full recursive key generation):
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_ivc_snark -- ivc/setup/keys
```

The filter is a **literal** substring, not a regex. The parser rejects (rather than silently ignores):
regex metacharacters in the filter, any value-taking option (`--sample-size`, `--color`, `--save-baseline`,
…), and `--exact` / `--test` / `--profile-time` (the last two would force a recursive keygen). Valueless
flags that `cargo bench` injects (`--bench`, `--nocapture`, `--quiet`, `--verbose`) are tolerated.

Benchmark ids:

```
ivc/{genesis,same_epoch,next_epoch}/prove/{poseidon,blake2b}
ivc/{genesis,same_epoch,next_epoch}/verify/{full,kzg_opening}
ivc/{same_epoch,next_epoch}/fold          # genesis has no fold
ivc/setup/{srs,keys}
```

Filtering to a subset still builds the shared environment it needs (one recursive keygen), so isolated
verify/fold runs pay that cost up front.

---

## Non-recursive certificate circuit — `halo2_snark`, `halo2_prover_modes`

### `halo2_snark`

For each parameter **tier** it reports constraint rows vs `2^k`, advice columns, VK size, proof size, and
proving/verification time. The two cheap tiers (`small`, `medium`) are **Criterion-sampled** (10 samples);
the two expensive tiers (`large`, `production`) print a **single manually-timed observation** (10 Criterion
samples would be prohibitive).

**Always pass a `certificate/<tier>` filter.** The harness runs every tier that a positional filter does not
exclude, so a bare invocation — or a run whose only arguments are Criterion control flags such as `--list`,
which are not positional filters — executes **all four tiers, including `production` (≥ 70 GB RAM)**.
Criterion's list/filter modes do **not** gate the manually-timed `large`/`production` tiers; only a
positional `certificate/<tier>` filter does.

```bash
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/small
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/medium
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/large
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_snark -- certificate/production
```

| Tier         | Quorum | `k` | Measurement           |
| ------------ | ------ | --- | --------------------- |
| `small`      | 3      | 13  | Criterion, 10 samples |
| `medium`     | 32     | 16  | Criterion, 10 samples |
| `large`      | 1024   | 21  | single observation    |
| `production` | 1944   | 22  | single observation    |

`small` is the lightest and a good smoke test after touching the circuit or the façade. `production` requires
≥ 70 GB RAM (server only).

### `halo2_prover_modes`

Takes no arguments — it sweeps a range of `k` tiers and prints, for each, the mock-prover vs real-prover
timings projected onto a standard e2e run (~80 certificates):

```bash
cargo bench -p mithril-stm --features future_snark,rustls,benchmark-internals --bench halo2_prover_modes
```
