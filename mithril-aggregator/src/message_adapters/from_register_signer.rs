use anyhow::Context;
use mithril_common::{
    StdResult,
    entities::Signer,
    messages::{RegisterSignerMessage, TryFromMessageAdapter},
};

/// Adapter to convert [RegisterSignerMessage] to [Signer] instances.
pub struct FromRegisterSignerAdapter;

impl TryFromMessageAdapter<RegisterSignerMessage, Signer> for FromRegisterSignerAdapter {
    /// Method to trigger the conversion.
    fn try_adapt(register_signer_message: RegisterSignerMessage) -> StdResult<Signer> {
        Ok(Signer {
            party_id: register_signer_message.party_id,
            verification_key_for_concatenation: register_signer_message.verification_key_for_concatenation.try_into().with_context(
                || "'FromRegisterSignerAdapter' can not convert the verification key",
            )?,
            verification_key_signature_for_concatenation: register_signer_message
                .verification_key_signature_for_concatenation
                .map(|verification_key_signature| {
                    verification_key_signature.try_into().with_context(|| {
                        "'FromRegisterSignerAdapter' can not convert the verification key signature"
                    })
                })
                .transpose()?,
            operational_certificate: register_signer_message
                .operational_certificate
                .map(|operational_certificate| {
                    operational_certificate.try_into().with_context(|| {
                        "'FromRegisterSignerAdapter' can not convert the operational certificate"
                    })
                })
                .transpose()?,
            kes_evolutions: register_signer_message.kes_evolutions,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: register_signer_message.verification_key_for_snark.map(|verification_key_for_snark| {
                    verification_key_for_snark.try_into().with_context(|| {
                        "'FromRegisterSignerAdapter' can not convert the snark verification key"
                    })
                })
                .transpose()?,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: register_signer_message
                .verification_key_signature_for_snark.map(|verification_key_signature_for_snark| {
                    verification_key_signature_for_snark.try_into().with_context(|| {
                        "'FromRegisterSignerAdapter' can not convert the snark verification key signature"
                    })
                })
                .transpose()?,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: register_signer_message
                .proof_of_bound_possession_for_snark.map(|proof_of_bound_possession_for_snark| {
                    proof_of_bound_possession_for_snark.try_into().with_context(|| {
                        "'FromRegisterSignerAdapter' can not convert the Proof of Bound Possession for SNARK"
                    })
                })
                .transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::double::Dummy;

    use super::*;

    #[test]
    fn try_adapt_signer_registration_message_to_entity() {
        let register_signer_message = RegisterSignerMessage {
            party_id: "one".to_string(),
            ..RegisterSignerMessage::dummy()
        };

        let signer = FromRegisterSignerAdapter::try_adapt(register_signer_message)
            .expect("Converting message to signer should not fail");

        assert_eq!("one".to_string(), signer.party_id);
    }
}
