---
title: Certificate chain cache available in the Mithril client
authors:
  - name: Mithril Team
tags: [client, certificate, cache, unstable, release, distribution, 2642]
---

### Certificate chain cache available in the Mithril client

With the [`2642.0`](https://github.com/IntersectMBO/mithril/releases/tag/2642.0) distribution, the Mithril client library, CLI and WASM library can **cache the verified certificate chain**, so that subsequent verifications are faster.

:::warning

The certificate chain cache is an **unstable** feature: it requires the `unstable` feature of the client library, the `--unstable` flag of the client CLI, or the `unstable` option of the client WASM library.

:::

#### Why a cache?

Verifying a certificate chain requires downloading and verifying every certificate back to the genesis certificate. A client that verifies certificates regularly verifies the same older certificates again and again. The certificate chain cache stores the certificates of a verified chain, so that the next verifications reuse them:

- The certificates are only committed to the cache once the whole chain is validated, so a failed verification never populates the cache
- The cached certificates are bound to the genesis verification key that validated them
- A cached certificate expires after one week by default.

#### Two verification modes

| Mode                      | Verification                                                                                          | Saving                                              |
| ------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| **FullVerification**      | The whole chain is verified back to the genesis certificate, cached certificates included             | Network round-trips only                            |
| **EarlyStopVerification** | The chain is verified until a cached certificate is reached, which is trusted without re-verification | Network round-trips and cryptographic verifications |

:::danger

In the `EarlyStopVerification` mode, the cache is part of the trust base of the client: it must be protected against tampering. Read the [certificate chain cache](https://mithril.network/doc/mithril/advanced/mithril-protocol/certificates#the-certificate-chain-cache) section for more details about the security impact of the modes.

:::

#### How to use it?

- **Client CLI**: use the `--use-certificate-chain-cache`, `--certificate-chain-cache-mode` and `--certificate-chain-cache-path` options, and reset the cache with the `tools cache reset` command (see the [client CLI documentation](https://mithril.network/doc/manual/develop/nodes/mithril-client#certificate-chain-cache))
- **Client library**: build the client with a file system backend of the cache (see the [client library documentation](https://mithril.network/doc/manual/develop/nodes/mithril-client-library#certificate-chain-cache))
- **Client WASM library**: enable the IndexedDB backend of the cache with the `enable_certificate_chain_verification_cache` and `certificate_chain_verification_cache_mode` client options (see the [client WASM library documentation](https://mithril.network/doc/manual/develop/nodes/mithril-client-library-wasm#certificate-chain-cache)).

For example, certify Cardano transactions with the client CLI and the cache in the `EarlyStopVerification` mode:

```bash
./mithril-client --unstable --use-certificate-chain-cache --certificate-chain-cache-mode EarlyStopVerification cardano-transaction certify $TRANSACTIONS_HASHES
```

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
