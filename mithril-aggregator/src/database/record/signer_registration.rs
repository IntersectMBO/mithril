use chrono::{DateTime, Utc};

use mithril_common::crypto_helper::KesEvolutions;
use mithril_common::entities::{
    Epoch, HexEncodedOpCert, HexEncodedProofOfBoundPossessionForSnark,
    HexEncodedVerificationKeyForConcatenation, HexEncodedVerificationKeyForSnark,
    HexEncodedVerificationKeySignatureForConcatenation, HexEncodedVerificationKeySignatureForSnark,
    Signer, SignerWithStake, Stake,
};
use mithril_persistence::sqlite::{HydrationError, Projection, SqLiteEntity};

/// SignerRegistration record is the representation of a stored signer_registration.
#[derive(Debug, PartialEq, Clone)]
pub struct SignerRegistrationRecord {
    /// Signer id.
    pub signer_id: String,

    /// Epoch of creation of the signer_registration.
    pub epoch_settings_id: Epoch,

    /// The encoded verification key for the Concatenation proof system
    pub verification_key_for_concatenation: HexEncodedVerificationKeyForConcatenation,

    /// The encoded KES signature over the verification key for Concatenation
    pub verification_key_signature_for_concatenation:
        Option<HexEncodedVerificationKeySignatureForConcatenation>,

    /// The encoded operational certificate of stake pool operator attached to the signer node.
    pub operational_certificate: Option<HexEncodedOpCert>,

    /// The number of evolutions of the KES key since the start KES period of the operational certificate at the time of signature.
    pub kes_evolutions: Option<KesEvolutions>,

    /// The stake associated to the signer
    pub stake: Option<Stake>,

    /// The encoded verification key for the SNARK proof system
    pub verification_key_for_snark: Option<HexEncodedVerificationKeyForSnark>,

    /// The encoded KES signature over the verification key for SNARK
    pub verification_key_signature_for_snark: Option<HexEncodedVerificationKeySignatureForSnark>,

    /// Date and time when the signer_registration was created
    pub created_at: DateTime<Utc>,

    /// The Proof of Bound Possession of the Schnorr signing key for the SNARK proof system.
    pub proof_of_bound_possession_for_snark: Option<HexEncodedProofOfBoundPossessionForSnark>,
}

impl SignerRegistrationRecord {
    pub(crate) fn from_signer_with_stake(other: SignerWithStake, epoch: Epoch) -> Self {
        SignerRegistrationRecord {
            signer_id: other.party_id,
            epoch_settings_id: epoch,
            verification_key_for_concatenation: other
                .verification_key_for_concatenation
                .to_json_hex()
                .unwrap(),
            verification_key_signature_for_concatenation: other
                .verification_key_signature_for_concatenation
                .map(|k| k.to_json_hex().unwrap()),
            operational_certificate: other
                .operational_certificate
                .map(|o| o.to_json_hex().unwrap()),
            kes_evolutions: other.kes_evolutions,
            stake: Some(other.stake),
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: other
                .verification_key_for_snark
                .map(|k| k.to_json_hex().unwrap()),
            #[cfg(not(feature = "future_snark"))]
            verification_key_for_snark: None,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: other
                .verification_key_signature_for_snark
                .map(|s| s.to_json_hex().unwrap()),
            #[cfg(not(feature = "future_snark"))]
            verification_key_signature_for_snark: None,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: other
                .proof_of_bound_possession_for_snark
                .map(|p| p.to_bytes_hex().unwrap()),
            #[cfg(not(feature = "future_snark"))]
            proof_of_bound_possession_for_snark: None,
            created_at: Utc::now(),
        }
    }
}

impl From<SignerRegistrationRecord> for Signer {
    fn from(other: SignerRegistrationRecord) -> Self {
        Self {
            party_id: other.signer_id,
            verification_key_for_concatenation: other
                .verification_key_for_concatenation
                .try_into()
                .unwrap(),
            verification_key_signature_for_concatenation: other
                .verification_key_signature_for_concatenation
                .map(|k| k.try_into().unwrap()),
            operational_certificate: other.operational_certificate.map(|o| o.try_into().unwrap()),
            kes_evolutions: other.kes_evolutions,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: other
                .verification_key_for_snark
                .map(|k| k.try_into().unwrap()),
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: other
                .verification_key_signature_for_snark
                .map(|s| s.try_into().unwrap()),
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: other
                .proof_of_bound_possession_for_snark
                .map(|p| p.try_into().unwrap()),
        }
    }
}

impl From<SignerRegistrationRecord> for SignerWithStake {
    fn from(other: SignerRegistrationRecord) -> Self {
        Self {
            party_id: other.signer_id,
            verification_key_for_concatenation: other
                .verification_key_for_concatenation
                .try_into()
                .unwrap(),
            verification_key_signature_for_concatenation: other
                .verification_key_signature_for_concatenation
                .map(|k| k.try_into().unwrap()),
            operational_certificate: other.operational_certificate.map(|o| o.try_into().unwrap()),
            kes_evolutions: other.kes_evolutions,
            stake: other.stake.unwrap_or_default(),
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: other
                .verification_key_for_snark
                .map(|k| k.try_into().unwrap()),
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: other
                .verification_key_signature_for_snark
                .map(|s| s.try_into().unwrap()),
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: other
                .proof_of_bound_possession_for_snark
                .map(|p| p.try_into().unwrap()),
        }
    }
}

impl SqLiteEntity for SignerRegistrationRecord {
    fn hydrate(row: sqlite::Row) -> Result<Self, HydrationError>
    where
        Self: Sized,
    {
        let signer_id = row.read::<&str, _>(0).to_string();
        let epoch_settings_id_int = row.read::<i64, _>(1);
        let verification_key_for_concatenation = row.read::<&str, _>(2).to_string();
        let verification_key_signature_for_concatenation =
            row.read::<Option<&str>, _>(3).map(|s| s.to_owned());
        let operational_certificate = row.read::<Option<&str>, _>(4).map(|s| s.to_owned());
        let kes_evolutions_int = row.read::<Option<i64>, _>(5);
        let stake_int = row.read::<Option<i64>, _>(6);
        let verification_key_for_snark = row.read::<Option<&str>, _>(7).map(|s| s.to_owned());
        let verification_key_signature_for_snark =
            row.read::<Option<&str>, _>(8).map(|s| s.to_owned());
        let created_at = row.read::<&str, _>(9);
        let proof_of_bound_possession_for_snark =
            row.read::<Option<&str>, _>(10).map(|p| p.to_owned());

        let signer_registration_record = Self {
            signer_id,
            epoch_settings_id: Epoch(epoch_settings_id_int.try_into().map_err(|e| {
                HydrationError::InvalidData(format!(
                    "Could not cast i64 ({epoch_settings_id_int}) to u64. Error: '{e}'"
                ))
            })?),
            verification_key_for_concatenation,
            verification_key_signature_for_concatenation,
            operational_certificate,
            kes_evolutions: match kes_evolutions_int {
                Some(kes_evolutions_int) => Some(kes_evolutions_int.try_into().map_err(|e| {
                    HydrationError::InvalidData(format!(
                        "Could not cast i64 ({kes_evolutions_int}) to u64. Error: '{e}'"
                    ))
                })?),
                None => None,
            },
            stake: match stake_int {
                Some(stake_int) => Some(stake_int.try_into().map_err(|e| {
                    HydrationError::InvalidData(format!(
                        "Could not cast i64 ({stake_int}) to u64. Error: '{e}'"
                    ))
                })?),
                None => None,
            },
            verification_key_for_snark,
            verification_key_signature_for_snark,
            created_at: DateTime::parse_from_rfc3339(created_at)
                .map_err(|e| {
                    HydrationError::InvalidData(format!(
                        "Could not turn string '{created_at}' to rfc3339 Datetime. Error: {e}"
                    ))
                })?
                .with_timezone(&Utc),
            proof_of_bound_possession_for_snark,
        };

        Ok(signer_registration_record)
    }

    fn get_projection() -> Projection {
        let mut projection = Projection::default();
        projection.add_field("signer_id", "{:signer_registration:}.signer_id", "text");
        projection.add_field(
            "epoch_setting_id",
            "{:signer_registration:}.epoch_setting_id",
            "integer",
        );
        projection.add_field(
            "verification_key_for_concatenation",
            "{:signer_registration:}.verification_key",
            "text",
        );
        projection.add_field(
            "verification_key_signature_for_concatenation",
            "{:signer_registration:}.verification_key_signature",
            "text",
        );
        projection.add_field(
            "operational_certificate",
            "{:signer_registration:}.operational_certificate",
            "text",
        );
        // TODO: the naming 'kes_period' lacks clarity and should be renamed to 'kes_evolutions'
        projection.add_field(
            "kes_evolutions",
            "{:signer_registration:}.kes_period",
            "integer",
        );
        projection.add_field("stake", "{:signer_registration:}.stake", "integer");
        projection.add_field(
            "verification_key_for_snark",
            "{:signer_registration:}.verification_key_for_snark",
            "text",
        );
        projection.add_field(
            "verification_key_signature_for_snark",
            "{:signer_registration:}.verification_key_signature_for_snark",
            "text",
        );
        projection.add_field("created_at", "{:signer_registration:}.created_at", "text");
        projection.add_field(
            "proof_of_bound_possession_for_snark",
            "{:signer_registration:}.proof_of_bound_possession_for_snark",
            "text",
        );

        projection
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::builder::MithrilFixtureBuilder;

    use super::*;

    #[test]
    fn test_convert_signer_registrations() {
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let signer_with_stakes = fixture.signers_with_stake();

        let mut signer_registration_records: Vec<SignerRegistrationRecord> = Vec::new();
        for signer_with_stake in signer_with_stakes.clone() {
            signer_registration_records.push(SignerRegistrationRecord::from_signer_with_stake(
                signer_with_stake,
                Epoch(1),
            ));
        }
        let mut signer_with_stakes_new: Vec<SignerWithStake> = Vec::new();
        for signer_registration_record in signer_registration_records {
            signer_with_stakes_new.push(signer_registration_record.into());
        }
        assert_eq!(signer_with_stakes, signer_with_stakes_new);
    }
}
