mod devnet;
mod mithril;
pub mod scenario;
pub mod stress_test;
pub mod toolkit;
mod utils;

pub use devnet::*;
pub use mithril::*;
pub use utils::{CompatibilityChecker, CompatibilityCheckerError, NodeVersion};

use clap::ValueEnum;

/// The flavor of DMQ node to use in the tests.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum DmqNodeFlavor {
    /// Haskell implementation of DMQ.
    Haskell,
    /// Fake implementation of DMQ.
    Fake,
}

/// The type of STM aggregate signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AggregateSignatureType {
    /// Concatenation proof system.
    #[value(name = "Concatenation")]
    Concatenation,
    /// SNARK proof system.
    #[value(name = "Snark")]
    Snark,
    /// IVC SNARK proof system.
    #[value(name = "IvcSnark")]
    IvcSnark,
}

impl AggregateSignatureType {
    /// The aggregate signature type whose protocol parameters constraints prevail when a network
    /// mixes several types, the recursive SNARK being the most constraining one
    pub fn most_constraining<'a>(types: impl IntoIterator<Item = &'a Self>) -> Self {
        types
            .into_iter()
            .copied()
            .max_by_key(Self::constraint_rank)
            .unwrap_or(Self::Concatenation)
    }

    fn constraint_rank(&self) -> u8 {
        match self {
            Self::Concatenation => 0,
            Self::Snark => 1,
            Self::IvcSnark => 2,
        }
    }
}

impl std::fmt::Display for AggregateSignatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregateSignatureType::Concatenation => write!(f, "Concatenation"),
            AggregateSignatureType::Snark => write!(f, "Snark"),
            AggregateSignatureType::IvcSnark => write!(f, "IvcSnark"),
        }
    }
}

#[cfg(test)]
mod test {
    mithril_common::define_test_logger!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_constraining_aggregate_signature_type_is_concatenation_when_alone_or_absent() {
        assert_eq!(
            AggregateSignatureType::Concatenation,
            AggregateSignatureType::most_constraining(&[AggregateSignatureType::Concatenation])
        );
        assert_eq!(
            AggregateSignatureType::Concatenation,
            AggregateSignatureType::most_constraining(&[])
        );
    }

    #[test]
    fn most_constraining_aggregate_signature_type_prevails_over_the_others() {
        assert_eq!(
            AggregateSignatureType::Snark,
            AggregateSignatureType::most_constraining(&[
                AggregateSignatureType::Concatenation,
                AggregateSignatureType::Snark,
            ])
        );
        assert_eq!(
            AggregateSignatureType::IvcSnark,
            AggregateSignatureType::most_constraining(&[
                AggregateSignatureType::Snark,
                AggregateSignatureType::IvcSnark,
                AggregateSignatureType::Concatenation,
            ])
        );
    }
}
