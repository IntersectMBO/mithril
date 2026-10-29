use crate::{
    ClosedKeyRegistration, MembershipDigest, proof_system::AggregateVerificationKeyForConcatenation,
};

#[cfg(feature = "snark")]
use crate::proof_system::AggregateVerificationKeyForSnark;

/// Aggregate verification key combining both the concatenation and SNARK proof systems.
///
/// Holds the concatenation aggregate verification key used in the current Mithril protocol,
/// and optionally the SNARK aggregate verification key when the `snark` feature is
/// enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateVerificationKey<D: MembershipDigest> {
    /// Concatenation aggregate verification key.
    concatenation_aggregate_verification_key: AggregateVerificationKeyForConcatenation<D>,
    /// SNARK aggregate verification key (when `snark` feature is enabled).
    #[cfg(feature = "snark")]
    snark_aggregate_verification_key: Option<AggregateVerificationKeyForSnark<D>>,
}

impl<D: MembershipDigest> AggregateVerificationKey<D> {
    /// Create a new aggregate verification key.
    pub fn new(
        concatenation_aggregate_verification_key: AggregateVerificationKeyForConcatenation<D>,
        #[cfg(feature = "snark")] snark_aggregate_verification_key: Option<
            AggregateVerificationKeyForSnark<D>,
        >,
    ) -> Self {
        Self {
            concatenation_aggregate_verification_key,
            #[cfg(feature = "snark")]
            snark_aggregate_verification_key,
        }
    }

    /// Returns the concatenation aggregate verification key.
    pub fn to_concatenation_aggregate_verification_key(
        &self,
    ) -> &AggregateVerificationKeyForConcatenation<D> {
        &self.concatenation_aggregate_verification_key
    }

    /// Returns the SNARK aggregate verification key, if present.
    #[cfg(feature = "snark")]
    pub fn to_snark_aggregate_verification_key(
        &self,
    ) -> Option<&AggregateVerificationKeyForSnark<D>> {
        self.snark_aggregate_verification_key.as_ref()
    }
}

impl<D: MembershipDigest> From<&ClosedKeyRegistration> for AggregateVerificationKey<D> {
    fn from(registration: &ClosedKeyRegistration) -> Self {
        AggregateVerificationKey {
            concatenation_aggregate_verification_key:
                AggregateVerificationKeyForConcatenation::from(
                    registration.get_closed_key_registration_for_concatenation(),
                ),
            #[cfg(feature = "snark")]
            snark_aggregate_verification_key: registration
                .get_closed_key_registration_for_snark()
                .map(AggregateVerificationKeyForSnark::from),
        }
    }
}
