//! Test doubles
//!
//! Enable unit testing with controlled inputs and predictable behavior.

mod api_version;
mod certificate_retriever;
mod dummies;
pub mod fake_data;
pub mod fake_keys;
pub(super) mod precomputed_kes_key;

pub use api_version::DummyApiVersionDiscriminantSource;
pub use certificate_retriever::FakeCertificaterRetriever;

/// A trait for giving a type a dummy value.
///
/// Sometimes in tests you need to provide a value for a type, but the actual value doesn't matter.
/// This trait allows defining a "dummy" value for a type, separated from an eventual default
/// value, that can be reused across multiple tests.
///
/// Note: should not be confused with "fake" values, fake values aim to be believable and contain
/// valid cryptography (if they have some), dummies don't aim for those characteristics.
///
/// # Example
/// ```
/// use mithril_common::test::double::Dummy;
///
/// struct MyType(String);
///
/// impl Dummy for MyType {
///     fn dummy() -> Self {
///         MyType("whatever".to_string())
///     }
/// }
///
/// let instance = MyType::dummy();
/// ```
pub trait Dummy: Sized {
    /// Return a dummy value for the type
    ///
    /// Useful for test contexts when the actual value doesn't matter.
    fn dummy() -> Self;
}
