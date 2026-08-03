---
title: Mithril certificate chain security advisory
authors:
  - name: Mithril Team
tags:
  [
    spo,
    mithril client,
    certificate,
    certificate chain,
    mainnet,
    production,
    beta,
    security,
  ]
---

### Mithril certificate chain could be manipulated by an adversarial signer (security advisory)

:::info

The certificate chain of the `release-mainnet` aggregator has been re-genesised at epoch **539**, and the network has resumed producing a valid chain at epoch **540**.

:::

The Mithril team has published a [security advisory](https://github.com/input-output-hk/mithril/security/advisories/GHSA-724h-fpm5-4qvr) for users running the Mithril client on the `mainnet` infrastructure:

- **Identifier**: GHSA-724h-fpm5-4qvr
- **Title**: Mithril certificate chain could be manipulated by an adversarial signer
- **Location**: [GHSA-724h-fpm5-4qvr](https://github.com/input-output-hk/mithril/security/advisories/GHSA-724h-fpm5-4qvr)
- **Severity**: High (5.3/10).

:::danger

We strongly encourage all the `mainnet` users running a **client library, client CLI, or client WASM** to update to the latest versions to prevent the issue:

- The **Mithril client library** has been fixed with version `0.11.1` and is available [here](https://crates.io/crates/mithril-client)
- The **Mithril client WASM** has been fixed with version `0.8.1` and is available [here](https://www.npmjs.com/package/@mithril-dev/mithril-client-wasm/v/0.8.1)
- The **Mithril client CLI** has been fixed with version `0.11.0` and can be downloaded with the following command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-client -d 2506.0 -p "$(pwd)"
```

**Note that all the previous versions must not be used anymore.**

:::

For any inquiries or assistance, feel free to contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
