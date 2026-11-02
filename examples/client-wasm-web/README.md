# Mithril client wasm library example: Web browser

## Description

This example shows how to implement a Mithril client and use its features in a Web browser environment.

In this example, the client interacts by default with a real aggregator on the network `release-preprod` to:

- Mithril Stake Distribution:
  - list the available Mithril Stake Distributions
  - verify the latest Mithril Stake Distribution
  - verify a certificate chain
  - compute a message
  - verify that the certificate signs the computed message
- Cardano transactions
  - get proof of inclusion for a known set of Cardano transactions
  - verify a certificate chain
  - compute a message for
  - verify that the certificate signs the computed message

The certificate chain verifications use the certificate chain cache (unstable), stored in IndexedDB, in the `EarlyStopVerification` mode: the next verifications stop at the first certificate fetched from the cache, even after a page reload.

## Build and run the example

The development server requires Node.js version `22.15+`.

First you need to switch to the latest release tag:

```bash
git checkout tags/$(curl -sSL https://api.github.com/repos/IntersectMBO/mithril/releases/latest | jq -r '.tag_name')
```

Compile the Mithril client Wasm library:

```bash
make -C ../../mithril-client-wasm build
```

Then you can run the example:

```bash
npm install
npm run start
```

Open your browser and navigate to `http://localhost:8080` to see the example running.

## Links

- **Developer documentation**: https://mithril.network/doc/manual/develop/nodes/mithril-client-library-wasm
- **NPM**: https://www.npmjs.com/package/@mithril-dev/mithril-client-wasm
