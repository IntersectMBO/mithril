#[cfg(feature = "future_snark")]
use crate::crypto_helper::{
    ProtocolSignerProofOfBoundPossessionForSnark, ProtocolSignerVerificationKeyForSnark,
    ProtocolSignerVerificationKeySignatureForSnark,
};
use crate::{
    crypto_helper::{
        KesEvolutions, ProtocolOpCert, ProtocolSignerVerificationKeyForConcatenation,
        ProtocolSignerVerificationKeySignatureForConcatenation,
    },
    entities::{PartyId, Stake},
};
use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signer represents a signing participant in the network
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct Signer {
    /// The unique identifier of the signer
    ///
    /// Used only for testing when SPO pool id is not certified
    pub party_id: PartyId,

    /// The verification key for the Concatenation proof system
    #[serde(rename = "verification_key")]
    pub verification_key_for_concatenation: ProtocolSignerVerificationKeyForConcatenation,

    /// The KES signature over the verification key for Concatenation
    ///
    /// None is used only for testing when SPO pool id is not certified
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "verification_key_signature"
    )]
    pub verification_key_signature_for_concatenation:
        Option<ProtocolSignerVerificationKeySignatureForConcatenation>,

    /// The operational certificate of stake pool operator attached to the signer node
    ///
    /// None is used only for testing when SPO pool id is not certified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operational_certificate: Option<ProtocolOpCert>,

    /// The number of evolutions of the KES key since the start KES period of the operational certificate at the time of signature.
    #[serde(rename = "kes_period", skip_serializing_if = "Option::is_none")]
    pub kes_evolutions: Option<KesEvolutions>,

    /// The verification key for the SNARK proof system
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verification_key_for_snark: Option<ProtocolSignerVerificationKeyForSnark>,

    /// The KES signature over the verification key for SNARK
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verification_key_signature_for_snark:
        Option<ProtocolSignerVerificationKeySignatureForSnark>,

    /// The Proof of Bound Possession of the Schnorr signing key for the SNARK proof system.
    /// Can be verified using the [`Signer::verification_key_for_snark`]
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof_of_bound_possession_for_snark: Option<ProtocolSignerProofOfBoundPossessionForSnark>,
}

impl PartialEq for Signer {
    fn eq(&self, other: &Self) -> bool {
        self.party_id.eq(&other.party_id)
    }
}

impl PartialOrd for Signer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.party_id.cmp(&other.party_id)
    }
}

impl Signer {
    /// Convert the given values to a vec of signers.
    pub fn vec_from<T: Into<Signer>>(from: Vec<T>) -> Vec<Self> {
        from.into_iter().map(|f| f.into()).collect()
    }

    /// Computes the hash of Signer
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.party_id.as_bytes());
        hasher.update(
            self.verification_key_for_concatenation
                .to_json_hex()
                .unwrap()
                .as_bytes(),
        );

        if let Some(verification_key_signature) = &self.verification_key_signature_for_concatenation
        {
            hasher.update(verification_key_signature.to_json_hex().unwrap().as_bytes());
        }
        if let Some(operational_certificate) = &self.operational_certificate {
            hasher.update(operational_certificate.to_json_hex().unwrap().as_bytes());
        }

        #[cfg(feature = "future_snark")]
        if let Some(verification_key_for_snark) = &self.verification_key_for_snark {
            hasher.update(verification_key_for_snark.to_json_hex().unwrap().as_bytes());
        }
        #[cfg(feature = "future_snark")]
        if let Some(verification_key_signature_for_snark) =
            &self.verification_key_signature_for_snark
        {
            hasher.update(verification_key_signature_for_snark.to_json_hex().unwrap().as_bytes());
        }
        #[cfg(feature = "future_snark")]
        if let Some(proof_of_bound_possession_for_snark) = &self.proof_of_bound_possession_for_snark
        {
            hasher.update(proof_of_bound_possession_for_snark.to_bytes_hex().unwrap().as_bytes());
        }

        hex::encode(hasher.finalize())
    }
}

impl Debug for Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("Signer");
        debug.field("party_id", &self.party_id);

        match should_be_exhaustive {
            true => {
                debug
                    .field(
                        "verification_key_for_concatenation",
                        &format_args!("{:?}", self.verification_key_for_concatenation),
                    )
                    .field(
                        "verification_key_signature_for_concatenation",
                        &format_args!("{:?}", self.verification_key_signature_for_concatenation),
                    )
                    .field(
                        "operational_certificate",
                        &format_args!("{:?}", self.operational_certificate),
                    )
                    .field("kes_evolutions", &format_args!("{:?}", self.kes_evolutions));

                #[cfg(feature = "future_snark")]
                {
                    debug
                        .field(
                            "verification_key_for_snark",
                            &format_args!("{:?}", self.verification_key_for_snark),
                        )
                        .field(
                            "verification_key_signature_for_snark",
                            &format_args!("{:?}", self.verification_key_signature_for_snark),
                        )
                        .field(
                            "proof_of_bound_possession_for_snark",
                            &format_args!("{:?}", self.proof_of_bound_possession_for_snark),
                        );
                }

                debug.finish()
            }
            false => debug.finish_non_exhaustive(),
        }
    }
}

impl From<SignerWithStake> for Signer {
    fn from(other: SignerWithStake) -> Self {
        Self {
            party_id: other.party_id,
            verification_key_for_concatenation: other.verification_key_for_concatenation,
            verification_key_signature_for_concatenation: other
                .verification_key_signature_for_concatenation,
            operational_certificate: other.operational_certificate,
            kes_evolutions: other.kes_evolutions,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: other.verification_key_for_snark,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: other.verification_key_signature_for_snark,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: other.proof_of_bound_possession_for_snark,
        }
    }
}

/// Signer represents a signing party in the network (including its stakes)
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct SignerWithStake {
    /// The unique identifier of the signer
    ///
    /// Used only for testing when SPO pool id is not certified
    pub party_id: PartyId,

    /// The verification key for the Concatenation proof system
    #[serde(rename = "verification_key")]
    pub verification_key_for_concatenation: ProtocolSignerVerificationKeyForConcatenation,

    /// The KES signature over the verification key for Concatenation
    ///
    /// None is used only for testing when SPO pool id is not certified
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "verification_key_signature"
    )]
    pub verification_key_signature_for_concatenation:
        Option<ProtocolSignerVerificationKeySignatureForConcatenation>,

    /// The operational certificate of stake pool operator attached to the signer node
    ///
    /// None is used only for testing when SPO pool id is not certified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operational_certificate: Option<ProtocolOpCert>,

    /// The number of evolutions of the KES key since the start KES period of the operational certificate at the time of signature.
    #[serde(rename = "kes_period", skip_serializing_if = "Option::is_none")]
    pub kes_evolutions: Option<KesEvolutions>,

    /// The signer stake
    pub stake: Stake,

    /// The verification key for the SNARK proof system
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verification_key_for_snark: Option<ProtocolSignerVerificationKeyForSnark>,

    /// The KES signature over the verification key for SNARK (hex encoded)
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verification_key_signature_for_snark:
        Option<ProtocolSignerVerificationKeySignatureForSnark>,

    /// The Proof of Bound Possession of the Schnorr signing key for the SNARK proof system.
    /// Can be verified using the [`SignerWithStake::verification_key_for_snark`]
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof_of_bound_possession_for_snark: Option<ProtocolSignerProofOfBoundPossessionForSnark>,
}

impl PartialEq for SignerWithStake {
    fn eq(&self, other: &Self) -> bool {
        self.party_id.eq(&other.party_id)
    }
}

impl PartialOrd for SignerWithStake {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignerWithStake {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.party_id.cmp(&other.party_id)
    }
}

impl SignerWithStake {
    /// Turn a [Signer] into a [SignerWithStake].
    pub fn from_signer(signer: Signer, stake: Stake) -> Self {
        Self {
            party_id: signer.party_id,
            verification_key_for_concatenation: signer.verification_key_for_concatenation,
            verification_key_signature_for_concatenation: signer
                .verification_key_signature_for_concatenation,
            operational_certificate: signer.operational_certificate,
            kes_evolutions: signer.kes_evolutions,
            stake,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: signer.verification_key_for_snark,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: signer.verification_key_signature_for_snark,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: signer.proof_of_bound_possession_for_snark,
        }
    }

    /// Remove SNARK-related fields for backward compatibility with older eras.
    ///
    /// This clears the SNARK verification key and its KES signature, which is needed
    /// during eras that do not support SNARK proofs (e.g. Pythagoras) to ensure
    /// consistency between the signer's initializer and the key registration entries.
    #[cfg(feature = "future_snark")]
    pub fn without_snark_fields(mut self) -> Self {
        self.verification_key_for_snark = None;
        self.verification_key_signature_for_snark = None;
        self.proof_of_bound_possession_for_snark = None;
        self
    }

    /// Remove SNARK-related fields from a list of signers with stake for backward compatibility.
    #[cfg(feature = "future_snark")]
    pub fn strip_snark_fields(signers: Vec<Self>) -> Vec<Self> {
        signers.into_iter().map(Self::without_snark_fields).collect()
    }

    /// Computes the hash of SignerWithStake
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.party_id.as_bytes());
        hasher.update(
            self.verification_key_for_concatenation
                .to_json_hex()
                .unwrap()
                .as_bytes(),
        );

        if let Some(verification_key_signature) = &self.verification_key_signature_for_concatenation
        {
            hasher.update(verification_key_signature.to_json_hex().unwrap().as_bytes());
        }
        if let Some(operational_certificate) = &self.operational_certificate {
            hasher.update(operational_certificate.to_json_hex().unwrap().as_bytes());
        }
        hasher.update(self.stake.to_be_bytes());

        #[cfg(feature = "future_snark")]
        if let Some(verification_key_for_snark) = &self.verification_key_for_snark {
            hasher.update(verification_key_for_snark.to_json_hex().unwrap().as_bytes());
        }
        #[cfg(feature = "future_snark")]
        if let Some(verification_key_signature_for_snark) =
            &self.verification_key_signature_for_snark
        {
            hasher.update(verification_key_signature_for_snark.to_json_hex().unwrap().as_bytes());
        }
        #[cfg(feature = "future_snark")]
        if let Some(proof_of_bound_possession_for_snark) = &self.proof_of_bound_possession_for_snark
        {
            hasher.update(proof_of_bound_possession_for_snark.to_bytes_hex().unwrap().as_bytes());
        }

        hex::encode(hasher.finalize())
    }
}

impl Debug for SignerWithStake {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("SignerWithStake");
        debug.field("party_id", &self.party_id).field("stake", &self.stake);

        match should_be_exhaustive {
            true => {
                debug
                    .field(
                        "verification_key_for_concatenation",
                        &format_args!("{:?}", self.verification_key_for_concatenation),
                    )
                    .field(
                        "verification_key_signature_for_concatenation",
                        &format_args!("{:?}", self.verification_key_signature_for_concatenation),
                    )
                    .field(
                        "operational_certificate",
                        &format_args!("{:?}", self.operational_certificate),
                    )
                    .field("kes_evolutions", &format_args!("{:?}", self.kes_evolutions));

                #[cfg(feature = "future_snark")]
                {
                    debug
                        .field(
                            "verification_key_for_snark",
                            &format_args!("{:?}", self.verification_key_for_snark),
                        )
                        .field(
                            "verification_key_signature_for_snark",
                            &format_args!("{:?}", self.verification_key_signature_for_snark),
                        )
                        .field(
                            "proof_of_bound_possession_for_snark",
                            &format_args!("{:?}", self.proof_of_bound_possession_for_snark),
                        );
                }

                debug.finish()
            }
            false => debug.finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::{builder::MithrilFixtureBuilder, double::fake_keys};

    use super::*;

    #[test]
    fn test_stake_signers_from_into() {
        let verification_key = MithrilFixtureBuilder::default()
            .with_signers(1)
            .build()
            .signers_with_stake()[0]
            .verification_key_for_concatenation;
        let signer_expected = Signer {
            party_id: "1".to_string(),
            verification_key_for_concatenation: verification_key,
            verification_key_signature_for_concatenation: None,
            operational_certificate: None,
            kes_evolutions: None,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: None,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: None,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: None,
        };
        let signer_with_stake = SignerWithStake {
            party_id: "1".to_string(),
            verification_key_for_concatenation: verification_key,
            verification_key_signature_for_concatenation: None,
            operational_certificate: None,
            kes_evolutions: None,
            stake: 100,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: None,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: None,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: None,
        };

        let signer_into: Signer = signer_with_stake.into();
        assert_eq!(signer_expected, signer_into);
    }

    #[test]
    fn test_signer_compute_hash() {
        const HASH_EXPECTED: &str =
            "02778791113dcd8647b019366e223bfe3aa8a054fa6d9d1918b6b669de485f1c";

        let build_signer = |party_id: &str, key_index: usize| Signer {
            party_id: party_id.to_string(),
            verification_key_for_concatenation: fake_keys::signer_verification_key()[key_index]
                .try_into()
                .unwrap(),
            verification_key_signature_for_concatenation: None,
            operational_certificate: None,
            kes_evolutions: None,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: None,
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: None,
            #[cfg(feature = "future_snark")]
            proof_of_bound_possession_for_snark: None,
        };

        assert_eq!(HASH_EXPECTED, build_signer("1", 3).compute_hash());
        assert_ne!(HASH_EXPECTED, build_signer("0", 3).compute_hash());
        assert_ne!(HASH_EXPECTED, build_signer("1", 0).compute_hash());
    }

    #[test]
    fn test_signer_with_stake_compute_hash() {
        #[cfg(not(feature = "future_snark"))]
        const EXPECTED_HASH: &str =
            "9a832baccd04aabfc419f57319e3831a1655a95bf3bf5ed96a1167d1e81b5085";
        #[cfg(feature = "future_snark")]
        const EXPECTED_HASH: &str =
            "6158c4f514b1e15dc745845dac9014e710ee6b2f0c5b2b1023d5207cf6b75db9";
        let signers = MithrilFixtureBuilder::default()
            .with_signers(2)
            .build()
            .signers_with_stake();
        let signer = signers[0].clone();

        assert_eq!(EXPECTED_HASH, signer.compute_hash());

        {
            let mut signer_different_party_id = signer.clone();
            signer_different_party_id.party_id = "whatever".to_string();

            assert_ne!(EXPECTED_HASH, signer_different_party_id.compute_hash());
        }
        {
            let mut signer_different_verification_key = signer.clone();
            signer_different_verification_key.verification_key_for_concatenation =
                signers[1].verification_key_for_concatenation;

            assert_ne!(
                EXPECTED_HASH,
                signer_different_verification_key.compute_hash()
            );
        }
        {
            let mut signer_different_stake = signer.clone();
            signer_different_stake.stake += 20;

            assert_ne!(EXPECTED_HASH, signer_different_stake.compute_hash());
        }

        #[cfg(feature = "future_snark")]
        {
            let mut signer_different_verification_key_for_snark = signer.clone();
            signer_different_verification_key_for_snark.verification_key_for_snark =
                signers[1].verification_key_for_snark;

            assert_ne!(
                EXPECTED_HASH,
                signer_different_verification_key_for_snark.compute_hash()
            );
        }

        #[cfg(feature = "future_snark")]
        {
            let mut signer_different_verification_key_signature_for_snark = signer.clone();
            signer_different_verification_key_signature_for_snark
                .verification_key_signature_for_snark =
                signers[1].verification_key_signature_for_snark;

            assert_ne!(
                EXPECTED_HASH,
                signer_different_verification_key_signature_for_snark.compute_hash()
            );
        }
    }

    #[cfg(feature = "future_snark")]
    mod strip_snark_fields {
        use super::*;

        #[test]
        fn snark_fields_are_cleared_by_without_snark_fields() {
            let signers = MithrilFixtureBuilder::default()
                .with_signers(1)
                .build()
                .signers_with_stake();
            let signer = signers[0].clone();
            assert!(signer.verification_key_for_snark.is_some());
            assert!(signer.verification_key_signature_for_snark.is_some());

            let stripped = signer.without_snark_fields();

            assert!(stripped.verification_key_for_snark.is_none());
            assert!(stripped.verification_key_signature_for_snark.is_none());
        }

        #[test]
        fn without_snark_fields_preserves_non_snark_data() {
            let signers = MithrilFixtureBuilder::default()
                .with_signers(1)
                .build()
                .signers_with_stake();
            let signer = signers[0].clone();

            let stripped = signer.clone().without_snark_fields();

            assert_eq!(signer.party_id, stripped.party_id);
            assert_eq!(
                signer.verification_key_for_concatenation,
                stripped.verification_key_for_concatenation
            );
            assert_eq!(signer.stake, stripped.stake);
        }

        #[test]
        fn without_snark_fields_preserves_none_values() {
            let signers = MithrilFixtureBuilder::default()
                .with_signers(1)
                .build()
                .signers_with_stake();
            let mut signer = signers[0].clone();
            signer.verification_key_for_snark = None;
            signer.verification_key_signature_for_snark = None;

            let stripped = signer.without_snark_fields();

            assert!(stripped.verification_key_for_snark.is_none());
            assert!(stripped.verification_key_signature_for_snark.is_none());
        }

        #[test]
        fn strip_snark_fields_clears_all_entries() {
            let signers = MithrilFixtureBuilder::default()
                .with_signers(3)
                .build()
                .signers_with_stake();
            assert!(signers.iter().all(|s| s.verification_key_for_snark.is_some()));

            let stripped = SignerWithStake::strip_snark_fields(signers);

            assert!(stripped.iter().all(|s| s.verification_key_for_snark.is_none()));
            assert!(
                stripped
                    .iter()
                    .all(|s| s.verification_key_signature_for_snark.is_none())
            );
        }

        #[test]
        fn strip_snark_fields_handles_empty_list() {
            let stripped = SignerWithStake::strip_snark_fields(vec![]);
            assert!(stripped.is_empty());
        }
    }
}
