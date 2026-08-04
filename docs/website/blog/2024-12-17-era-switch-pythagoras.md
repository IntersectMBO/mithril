---
title: Era switch to Pythagoras
authors:
  - name: Mithril Team
tags: [era, switch, thales, pythagoras]
---

### Era switch to Pythagoras

We have introduced the **Pythagoras era** in the Mithril networks. The switch to `Pythagoras` is a significant milestone that brings new features and improvements to the Mithril protocol.

:::info[Update 2025/02/09]

The `release-mainnet` network has succesfully switched to the `Pythagoras` era at epoch `539`!

:::

:::info[Update 2025/01/31]

The transaction to activate the era switch to `Pythagoras` has been created on the `release-mainnet` network at epoch `537`.
The era switch will be completed at the transition to epoch `539`.

:::

:::danger

**Mithril signer versions** compatible with the new `Pythagoras` era are:

- `0.2.221`
- `0.2.209`
- `0.2.200`.

All other versions are **not** compatible with the new era and must be updated.

:::

:::tip

You can easily update your Mithril signer with this one-line command (it will be downloaded to the current directory by default; you can specify a custom folder with the `-p` option):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-signer -d latest -p "$(pwd)"
```

:::

#### Era switch plan for `Pythagoras`

- **pre-release-preview** network:
  - [x] Create the era switch transaction (done at epoch `757`)
  - [x] Complete the era switch to `Pythagoras` at the transition to epoch `759`

- **release-preprod** network:
  - [x] Create the era switch transaction (done at epoch `184`)
  - [x] Complete the era switch to `Pythagoras` at the transition to epoch `186`

- **release-mainnet** network:
  - [x] Create the era switch transaction (done at epoch `537`)
  - [x] Complete the era switch to `Pythagoras` at the transition to epoch `539`.

:::info

We use the **era switch mechanism** to introduce breaking changes in the Mithril protocol. Because these features are not backward compatible with the previous era, at least **95% of the stake** must be running the new version for `Pythagoras` to activate. Refer to the [Mithril network upgrade strategy](https://mithril.network/doc/adr/4) ADR for more details.

:::

For any inquiries or assistance, don't hesitate to contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
