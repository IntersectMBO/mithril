use crate::{
    StdResult,
    crypto_helper::ProtocolSigner,
    entities::{PartyId, SingleSignature},
    protocol::ToMessage,
};

/// The SingleSigner is the structure responsible for issuing SingleSignatures.
#[cfg_attr(test, derive(Debug))]
pub struct SingleSigner {
    party_id: PartyId,
    protocol_signer: ProtocolSigner,
}

impl SingleSigner {
    pub(super) fn new(party_id: PartyId, protocol_signer: ProtocolSigner) -> Self {
        Self {
            party_id,
            protocol_signer,
        }
    }

    /// Issue a single signature for the given message.
    ///
    /// If no lottery are won None will be returned.
    pub fn sign<T: ToMessage>(&self, message: &T) -> StdResult<Option<SingleSignature>> {
        let signed_message = message.to_message();
        match self.protocol_signer.sign(signed_message.as_bytes()) {
            Some(signature) => {
                let won_indexes = signature.get_concatenation_signature_indices();

                Ok(Some(SingleSignature::new(
                    self.party_id.to_owned(),
                    signature.into(),
                    won_indexes,
                )))
            }
            None => Ok(None),
        }
    }

    /// Return the partyId associated with this Signer.
    pub fn get_party_id(&self) -> PartyId {
        self.party_id.clone()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    #[cfg(feature = "future_snark")]
    use crate::entities::Epoch;
    use crate::{
        crypto_helper::{KesSigner, KesSignerStandard},
        entities::ProtocolMessage,
        protocol::SignerBuilder,
        test::builder::MithrilFixtureBuilder,
    };

    #[test]
    fn single_signer_should_be_able_to_issue_single_signature() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let signers = fixture.signers_fixture();
        let signer = signers.first().unwrap();
        let kes_signer = Some(Arc::new(KesSignerStandard::new(
            signer.kes_secret_key_path().unwrap().to_path_buf(),
            signer.operational_certificate_path().unwrap().to_path_buf(),
        )) as Arc<dyn KesSigner>);

        let (single_signer, _) = SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
            #[cfg(feature = "future_snark")]
            Epoch::default(),
        )
        .unwrap()
        .build_test_single_signer(signer.signer_with_stake.clone(), kes_signer)
        .unwrap();

        let signature = single_signer
            .sign(&ProtocolMessage::default())
            .expect("Single signer should be able to issue single signature");

        assert!(signature.is_some());
    }
}
