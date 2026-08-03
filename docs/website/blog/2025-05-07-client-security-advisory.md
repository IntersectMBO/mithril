---
title: Mithril Cardano database snapshots security advisory
authors:
  - name: Mithril Team
tags:
  [spo, mithril client, mainnet, production, beta, security, cardano-database]
---

### Mithril snapshots for Cardano database could be compromised by an adversary

The Mithril team has published a [security advisory](https://github.com/input-output-hk/mithril/security/advisories/GHSA-qv97-5qr8-2266) for users running the Mithril client on the `mainnet` infrastructure:

- **Identifier**: GHSA-qv97-5qr8-2266
- **Title**: Mithril snapshots for Cardano database could be compromised by an adversary
- **Location**: [GHSA-qv97-5qr8-2266](https://github.com/input-output-hk/mithril/security/advisories/GHSA-qv97-5qr8-2266)
- **Severity**: Moderate (4.9/10).

:::danger

We strongly encourage all `mainnet` users running a **client library or client CLI** to update to the latest versions to prevent the issue:

- The **Mithril client library** has been fixed with version `0.12.2` and is available [here](https://crates.io/crates/mithril-client)
- The **Mithril client CLI** has been fixed with version `0.12.1` and can be downloaded with the following command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-client -d 2517.1 -p "$(pwd)"
```

**Note that all the previous versions must not be used anymore.**

:::

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
