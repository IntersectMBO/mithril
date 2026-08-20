# Backward compatibility

The end-to-end tests scenarios are backward compatible with previous nodes versions.

This is achieved by differentiating the scenarios based on the version of the nodes they are testing.

There are multiple ways to do this:

- disabling part of the scenarios
- adding or removing arguments to the binaries (e.g. `--backend` flag for the client-cli)

> [!TIP]
> Node versions and distribution versions below are the ones that first included the changes, as node versions evolve
> faster than distribution versions the actual node version included in the distribution may be higher.
>
> e.g. `--origin-tag` flag for the client-cli was introduced in version `0.11.13`, the first distribution that included
> that change is `2517.0`, which include client-cli `0.12.0`.

---

## Supported changes

List of breaking changes that are supported by the end-to-end tests.

format is: `- **since 'X.Y.Z' (distribution version) [to 'X.Y.Z' (distribution version) (optional)]**: supported change`

### Mithril client

- **since `0.13.1`**: addition of `--backend` flag with `v1`/`v2` values for cardano-transaction
- **since `0.13.0`**: removal of `v1` backend from the `cardano-db` commands
- **since `0.12.34` (2543.0)**: test of new `--epoch` filter to `cardano-db list` (disabled on lower versions)
- **since `0.12.11` (2524.0)**: removal of `cardano-db-v2` replaced with `cardano-db [command] --backend [v1,v2]`
- **since `0.11.14` (2517.0)**: addition of `--include-ancillary` flag to `cardano-db download`
- **since `0.11.13` (2517.0)**: addition of global `--origin-tag` parameter

### Mithril aggregator

- **since `0.8.34`**: addition of `--mithril-era` flag to `genesis bootstrap` command
- **since `0.7.94` (next to 2543.1)**: only the leader aggregator must be restarted when updating protocol parameters
- **since `0.10.0` (next to 2630.0)**: support of on cardano on-chain protocol parameters

### Mithril signer

---

## Unsupported changes

List of breaking changes that are NOT supported by the end-to-end tests, running the tests with nodes versions
violating at least one of the case below will result in an error and an exit code of `3`.

format is:

- for an incompatibility of a node below a specific version:
  `- **min supported version is 'X.Y.Z' (distribution version)**: explanatory message`
- for an incompatibility between two nodes:
  `- **below 'X.Y.Z' (distribution version) with {other node} `X.Y.Z` (other distribution version) and up**: explanatory message`

### Mithril client

- **below `0.11.14` (2517.0) with aggregator `0.7.31` (2517.0) and up**: split ancillary files are not correctly supported
  for older clients, causing the verification to fail because the incomplete immutable files trio is missing.

### Mithril aggregator

- **below `0.7.91` (next to 2543.1) with signer `0.2.277` (next to 2543.1) and up**: new `/protocol-configuration/{epoch}`aggregator
  route to update network parameters (required by signer`0.2.277` and up)
- **below `0.7.55` (2524.0) with cardano-node version `10.4.1` and up**: support of UTxO-HD was added only on aggregator `0.7.55` and up
- **below `0.8.46` (next to 2543.1) with cardano-node version `10.7.0` and up**: changes in the UTxO-HD ledger state snapshot format

### Mithril signer

- **min supported version is `0.2.221` (2450.0)**: addition of the `CardanoDatabase` signed entity type, previous signers
  are not able to handle unknown signed entities
