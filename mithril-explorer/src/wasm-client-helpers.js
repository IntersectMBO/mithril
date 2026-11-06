"use client";
/*
 * Helpers for the wasm client.
 *
 * *IMPORTANT*: Those functions should never be imported directly using `import` since this
 * may cause the wasm client to be included in SSR builds, which will fail with the following error:
 * ```
 * Error: ENOENT: no such file or directory, open '/mithril/mithril-explorer/.next/server/app/mithril_client_wasm_bg.wasm'
 * ```
 * Instead, use `require` to import these functions:
 * ```js
 * const { newMithrilWasmClient } = require("@/wasm-client-helpers");
 * ```
 */

import { MithrilClient } from "@mithril-dev/mithril-client-wasm";

async function newMithrilWasmClient(aggregator, genesisVerificationKey) {
  const client_options = process.env.UNSTABLE
    ? {
        // The following option activates the unstable features of the client.
        // Unstable features will trigger an error if this option is not set.
        unstable: true,
        enable_certificate_chain_verification_cache: true,
        origin_tag: "EXPLORER",
      }
    : {
        enable_certificate_chain_verification_cache: true,
        origin_tag: "EXPLORER",
      };

  return new MithrilClient(aggregator, genesisVerificationKey, client_options);
}

export { newMithrilWasmClient };
