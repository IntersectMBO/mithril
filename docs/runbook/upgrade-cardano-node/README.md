# Upgrade the Cardano node of a Mithril network

## Introduction

When a new version of the Cardano node is released, we need to update this dependency in the Mithril codebase and make sure that Mithril nodes are compatible with it. The upgrade affects the infrastructure of all Mithril networks (aggregator, signers, Cardano nodes), as well as the Docker images, CI workflows, E2E tests, devnet, and documentation.

> [!IMPORTANT]
> :fire: A critical preliminary step is to determine whether the new Cardano node version requires a **ledger state re-computation from genesis** (a.k.a. ledger replay). If so, a specific warmup process must be performed to avoid many hours of aggregator downtime. See the [Cardano node warmup for ledger replay](../warmup-cardano-node/README.md) runbook for details.

## Pre-requisites

- Access to the GitHub repository and CI/CD workflows
- Access to the GitHub environments configuration

## Step 1: Determine if a ledger replay is needed

Before upgrading, you must verify whether the new Cardano node version requires a ledger state re-computation from genesis. This information is typically available in the Cardano node release notes.

Another option is to download a Mithril snapshot created for the previous version of the Cardano node. Once restored, use the Docker start command provided by the client CLI and use the new version of the Cardano node to start it. You will see in the logs whether a ledger replay is triggered or not.

If a ledger replay is required:

> [!IMPORTANT]
> :fire: Perform the [Cardano node warmup for ledger replay](../warmup-cardano-node/README.md) on the (pre-)production aggregator nodes **before** proceeding with the infrastructure upgrade. This warmup avoids many hours of aggregator downtime by pre-loading the Cardano database from a Mithril snapshot.

## Step 2: Update Cardano configurations in infrastructure

Export the environment variables for the target Cardano node version:

```bash
export CARDANO_NODE_VERSION=**CARDANO_NODE_VERSION**
```

Here is an example for version `11.0.1`:

```bash
export CARDANO_NODE_VERSION=11.0.1
```

The Cardano node configuration files (topology, genesis, config) for each network must be updated in the `mithril-infra` directory. The configuration files are available in the release bundle of the Cardano node in the `share` directory.

When deploying the infrastructure, the version of the Cardano node is matched exactly and fails over the minor version by matching the folder name in the `mithril-infra/assets/docker/cardano/config` folder. If the new version configuration files are valid for all minor versions you can name the folder by omitting the patch version (eg `11.0` instead of `11.0.1`).

Update the Cardano node image version in the infrastructure configuration for each network:

- `preview`
- `preprod`
- `mainnet`

Also cleanup any previous unsupported Cardano configurations from the infra (by following the [update policy by network](../maintain-networks-configuration-file/README.md#update-policy-by-network)).

## Step 3: Check Mithril compatibility with the new Cardano node

Verify that the latest stable versions of the Mithril aggregator and signer are compatible with the new Cardano node version by monitoring the production networks after the upgrade.

Check the following:

- Mithril signer: verify it registers correctly and participates in signing rounds
- Mithril aggregator: verify it produces certificates without errors

## Step 4: Update the Cardano CLI version in the codebase

Update the Cardano CLI version to `$CARDANO_NODE_VERSION` in the following locations:

- Infrastructure configuration (Terraform variables and deployment matrices)
- Docker images (base image references and `Dockerfile` files)
- Documentation pages that reference the Cardano CLI version

## Step 5: Update CI workflows

Update the Cardano node version to `$CARDANO_NODE_VERSION` in the following CI workflows:

- Manual workflows
- Nightly workflows

Add a new entry for `$CARDANO_NODE_VERSION` in the E2E test matrix of the CI.

## Step 6: Update the devnet and E2E tests

Update the Cardano node and CLI to `$CARDANO_NODE_VERSION` in:

- The `devnet` configuration
- The E2E test configuration

And make sure that the E2E tests are successful. If not, it means that some further adaptation is required.

## Step 7: Update the network configuration files

Update the `networks.json` files and the **Network configurations** documentation page for each network (by following the [update policy by network](../maintain-networks-configuration-file/README.md#update-policy-by-network)):

- `testing-preview`
- `pre-release-preview`
- `release-preprod`
- `release-mainnet`

## Step 8: Create an upgrade PR

Create a PR with all the necessary modifications for the upgrade, and make sure that all CI checks are successful.

## Step 9: Update the GitHub environments

Update the Cardano node version to `$CARDANO_NODE_VERSION` in the GitHub environments and redeploy the infrastructure for each network:

- `dev-preview`
- `dev-follower-preview`
- `dev-mainnet`
- `dev-dijkstranet`
- `testing-preview`
- `pre-release-preview`
- `release-preprod`
- `release-mainnet`

> [!NOTE]
> The `pre-release-preview`, `release-preprod`, and `release-mainnet` environments are usually updated in the next distribution cycle rather than immediately, depending on the release schedule.

> [!IMPORTANT]
> The Cardano node release archive does not ship the Dijkstranet configuration: before updating `dev-dijkstranet`, add the configuration files of the new version from the [Dijkstranet environment](https://book.play.dev.cardano.org/environments-pre/dijkstra/) to the `dijkstranet/cardano-node` folder of the new version folder in `mithril-infra/assets/docker/cardano/config` (eg `11.3/dijkstranet/cardano-node`), and keep the previous `dijkstranet` folder until `dev-dijkstranet` runs the new version.

For more information about the CD, please refer to [Release process and versioning](https://mithril.network/doc/adr/3).
