---
title: Mithril repository moving to the `IntersectMBO` organization
authors:
  - name: Mithril Team
tags:
  [
    repository,
    transfer,
    intersectmbo,
    spo,
    signer,
    aggregator,
    client,
    downstream,
    migration,
  ]
---

### The Mithril repository is moving to the `IntersectMBO` GitHub organization

The Mithril repository is moving from the [`input-output-hk`](https://github.com/input-output-hk/mithril) GitHub organization to [`IntersectMBO`](https://github.com/IntersectMBO). The transfer is scheduled for **Monday, July 20, 2026 (D-day)**.

#### Why this move?

The Mithril project is transitioning to the Intersect MBO governance, joining other core Cardano components (such as the Cardano node and the DMQ node) already hosted under [`IntersectMBO`](https://github.com/IntersectMBO). This move reflects the maturity of the project and its growing role in the Cardano ecosystem.

#### What changes?

After the transfer:

- The canonical repository URL becomes `https://github.com/IntersectMBO/mithril`
- New Docker images will be published to `ghcr.io/intersectmbo/mithril-{signer,aggregator,client,relay}`
- Raw verification key and network configuration URLs will be served from `https://raw.githubusercontent.com/IntersectMBO/mithril/...`.

:::info

The move is designed to be **transparent to end users**. GitHub automatically redirects:

- Existing repository URLs and `git clone` URLs
- Issues, pull requests, releases, and release asset URLs
- Raw `raw.githubusercontent.com` URLs for verification keys and configuration files.

:::

##### About Docker images

- All Docker images previously published under `ghcr.io/input-output-hk/...` **remain in place** and stay public indefinitely; existing deployments are not affected
- From D-day onwards, **new Docker images are published only under `ghcr.io/intersectmbo/...`**
- For convenience, the **most recent Docker images are also mirrored to `ghcr.io/intersectmbo/...` on D-day**, so users can switch their image references to the new namespace immediately without waiting for the next release.

#### What do you need to do?

The answer depends on your role. The sections below summarize the action items for each downstream user category.

##### SPOs running a Mithril signer

- **Before D-day (mandatory verification)**: if your signer integration fetches the era verification key (`era.vkey`) from its raw GitHub URL at startup, confirm that your HTTP client follows HTTP redirects. If it does **not**, switch your pinned URL to the `IntersectMBO` namespace ahead of D-day.
- **At your next planned upgrade**:
  - Switch the signer Docker image reference to `ghcr.io/intersectmbo/mithril-signer:<tag>` (digests remain byte-identical for tags released before D-day, and new releases are published only to the new namespace).
  - Refresh any pinned `era.vkey` URL to the `IntersectMBO` namespace.

##### Mithril aggregator operators

- **Before D-day (mandatory verification)**: if your aggregator integration fetches the era verification key (`era.vkey`) from its raw GitHub URL at startup, confirm that your HTTP client follows HTTP redirects. If it does **not**, switch your pinned URL to the `IntersectMBO` namespace ahead of D-day.
- **At your next planned upgrade**:
  - Switch the aggregator Docker image reference to `ghcr.io/intersectmbo/mithril-aggregator:<tag>` (digests remain byte-identical for tags released before D-day, and new releases are published only to the new namespace).
  - Refresh any pinned `era.vkey` URL to the `IntersectMBO` namespace.

##### Mithril client users (CLI, library, WASM)

- **Right after D-day (mandatory verification)**: if your integration fetches the `genesis.vkey` and/or `ancillary.vkey` from their raw GitHub URLs at startup, confirm that your HTTP client follows HTTP redirects. If it does **not**, switch your pinned URLs to the `IntersectMBO` namespace.
- **At your next release**:
  - Refresh any pinned `genesis.vkey` and `ancillary.vkey` URL to the `IntersectMBO` namespace
  - If your build bundles a pinned `networks.json`, refresh it from `https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json`
  - If your install scripts use `curl -s`, harden them to `curl -sSfL` so HTTP redirects are followed and HTTP errors fail loudly.

#### Recommended `curl` flag

When fetching Mithril resources from raw GitHub URLs in scripts, use `-sSfL` rather than `-s` so the request follows HTTP redirects (`-L`) and fails on HTTP errors (`-f`) instead of silently saving an error page:

```bash
curl -sSfL https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json
```

#### Timeline

| Done | Milestone                   | Date          | What happens                                                                         |
| :--: | --------------------------- | ------------- | ------------------------------------------------------------------------------------ |
|  ✅  | Announcement (today)        | July 17, 2026 | This announcement is published                                                       |
|  ✅  | D-day (repository transfer) | July 20, 2026 | Repository transfer is performed, new GHCR images are published under `IntersectMBO` |
|  ✅  | From D+1                    | July 21, 2026 | Documentation cross-references and external references are refreshed                 |

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
