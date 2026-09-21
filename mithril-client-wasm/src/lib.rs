//! Implementation of the 'mithril-client' library in WASM
#![cfg(target_family = "wasm")]
#![cfg_attr(target_family = "wasm", warn(missing_docs))]

mod client_wasm;
#[cfg(test)]
mod test_data;

pub use client_wasm::MithrilClient;

pub(crate) type WasmResult = Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
