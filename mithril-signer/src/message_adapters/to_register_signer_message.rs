use anyhow::Context;
use mithril_common::{
    StdResult,
    entities::{Epoch, Signer},
    messages::{RegisterSignerMessage, TryToMessageAdapter},
};

/// Adapter to create [RegisterSignerMessage] from [Signer] instance.
pub struct ToRegisterSignerMessageAdapter;

impl TryToMessageAdapter<(Epoch, Signer), RegisterSignerMessage>
    for ToRegisterSignerMessageAdapter
{
    /// Method to trigger the conversion.
    fn try_adapt((epoch, signer): (Epoch, Signer)) -> StdResult<RegisterSignerMessage> {
        let message = RegisterSignerMessage {
            epoch,
            party_id: signer.party_id,
            verification_key_for_concatenation: signer.verification_key_for_concatenation.try_into().with_context(|| {
                format!(
                    "'ToRegisterSignerMessageAdapter' can not convert the verification key: '{:?}'",
                    signer.verification_key_for_concatenation
                )
            })?,
            verification_key_signature_for_concatenation: signer.verification_key_signature_for_concatenation.map(TryInto::try_into).transpose().with_context(|| {
                format!(
                        "'ToRegisterSignerMessageAdapter' can not convert the verification key signature: '{:?}'",
                        signer.verification_key_signature_for_concatenation
                    )
            })?,
            operational_certificate:  signer.operational_certificate.map(TryInto::try_into).transpose().with_context(|| {
                "'ToRegisterSignerMessageAdapter' can not convert the operational certificate"
            })?,
            kes_evolutions: signer.kes_evolutions,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: signer.verification_key_for_snark.map(TryInto::try_into).transpose().with_context(|| {
                format!(
                    "'ToRegisterSignerMessageAdapter' can not convert the SNARK verification key: '{:?}'",
                    signer.verification_key_for_snark
                )
            })?,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: signer.verification_key_signature_for_snark.map(TryInto::try_into).transpose().with_context(|| {
                format!(
                    "'ToRegisterSignerMessageAdapter' can not convert the SNARK verification key signature: '{:?}'",
                    signer.verification_key_signature_for_snark
                )
            })?,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: signer.proof_of_bound_possession_for_snark.map(TryInto::try_into).transpose().with_context(|| {
                format!(
                "'ToRegisterSignerMessageAdapter' can not convert the Proof of Bound Possession for SNARK: '{:?}'",
                signer.proof_of_bound_possession_for_snark
                )
            })?,
        };

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::double::fake_data;

    use super::*;

    #[test]
    fn adapt_ok() {
        let epoch = Epoch(1);
        let mut signer = fake_data::signers(1)[0].to_owned();
        signer.party_id = "0".to_string();
        let message = ToRegisterSignerMessageAdapter::try_adapt((epoch, signer)).unwrap();

        assert_eq!("0".to_string(), message.party_id);
    }
}
