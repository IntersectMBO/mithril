//! Implementation of the 'mithril-client' library in WASM
#![cfg(target_family = "wasm")]
#![cfg_attr(target_family = "wasm", warn(missing_docs))]

mod client_wasm;
mod indexed_db_certificate_verifier_cache;
#[cfg(test)]
mod test_data;

pub use client_wasm::MithrilClient;
pub use indexed_db_certificate_verifier_cache::IndexedDbCertificateVerifierCache;

pub(crate) type WasmResult = Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
