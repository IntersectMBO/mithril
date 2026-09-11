//! Module to (de)serialise, OpCert using the same structure as used in Cardano.  

use anyhow::anyhow;
use blake2::{Blake2b, Digest, digest::consts::U28};
use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSecretKey, Verifier,
    VerifyingKey as EdVerificationKey,
};
use kes_summed_ed25519::PublicKey as KesPublicKey;
use nom::AsBytes;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use thiserror::Error;

use crate::StdResult;
use crate::crypto_helper::cardano::ProtocolRegistrationErrorWrapper;
use crate::crypto_helper::{KesPeriod, ProtocolPartyId, encode_bech32};

use super::SerDeShelleyFileFormat;

/// Operational certificate error
#[derive(Error, Debug, PartialEq, Eq)]
pub enum OpCertError {
    /// Error raised when a pool address encoding fails
    #[error("pool address encoding error")]
    PoolAddressEncoding,
}

/// Raw Fields of the operational certificates (without including the cold VK)
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct RawOpCertWithoutColdVerificationKey(
    #[serde(with = "serde_bytes")] Vec<u8>,
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

/// Raw Operational Certificate
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct RawOpCert(RawOpCertWithoutColdVerificationKey, EdVerificationKey);

/// Parsed Operational Certificate without cold verification key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpCertWithoutColdVerificationKey {
    pub(crate) kes_vk: KesPublicKey,
    pub(crate) issue_number: u64,
    /// KES period at which KES key is initalized
    pub start_kes_period: KesPeriod,
    pub(crate) cert_sig: EdSignature,
}

impl OpCertWithoutColdVerificationKey {
    /// OpCertWithoutColdVerificationKey factory
    pub fn try_new(
        kes_vk: &[u8],
        issue_number: u64,
        start_kes_period: KesPeriod,
        cert_sig: &[u8],
    ) -> StdResult<Self> {
        Ok(Self {
            kes_vk: KesPublicKey::from_bytes(kes_vk)
                .map_err(|e| anyhow!("{e:?}").context("KES vk serialisation error"))?,
            issue_number,
            start_kes_period,
            cert_sig: EdSignature::from_slice(cert_sig)
                .map_err(|e| anyhow!("{e:?}").context("ed25519 signature serialisation error"))?,
        })
    }

    /// Get the KES verification key
    pub fn kes_vk(&self) -> KesPublicKey {
        self.kes_vk
    }

    /// Get the issue number
    pub fn issue_number(&self) -> u64 {
        self.issue_number
    }

    /// Get the start KES period
    pub fn start_kes_period(&self) -> KesPeriod {
        self.start_kes_period
    }

    /// Get the certificate signature
    pub fn cert_sig(&self) -> EdSignature {
        self.cert_sig
    }
}

impl SerDeShelleyFileFormat for OpCertWithoutColdVerificationKey {
    const TYPE: &'static str = "NodeOperationalCertificateWithoutColdVerificationKey";
    const DESCRIPTION: &'static str = "";
}

impl Serialize for OpCertWithoutColdVerificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw_cert = RawOpCertWithoutColdVerificationKey(
            self.kes_vk.as_bytes().to_vec(),
            self.issue_number,
            self.start_kes_period.into(),
            self.cert_sig.to_bytes().to_vec(),
        );

        raw_cert.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpCertWithoutColdVerificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw_cert = RawOpCertWithoutColdVerificationKey::deserialize(deserializer)?;

        Ok(Self {
            kes_vk: KesPublicKey::from_bytes(&raw_cert.0)
                .map_err(|_| Error::custom("KES vk serialisation error"))?,
            issue_number: raw_cert.1,
            start_kes_period: KesPeriod(raw_cert.2),
            cert_sig: EdSignature::from_slice(&raw_cert.3)
                .map_err(|_| Error::custom("ed25519 signature serialisation error"))?,
        })
    }
}

impl From<&OpCertWithoutColdVerificationKey> for RawOpCertWithoutColdVerificationKey {
    fn from(opcert: &OpCertWithoutColdVerificationKey) -> Self {
        RawOpCertWithoutColdVerificationKey(
            opcert.kes_vk.as_bytes().to_vec(),
            opcert.issue_number,
            opcert.start_kes_period.into(),
            opcert.cert_sig.to_bytes().to_vec(),
        )
    }
}

/// Parsed Operational Certificate
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpCert {
    pub(crate) opcert_without_vk: OpCertWithoutColdVerificationKey,
    pub(crate) cold_vk: EdVerificationKey,
}

impl SerDeShelleyFileFormat for OpCert {
    const TYPE: &'static str = "NodeOperationalCertificate";
    const DESCRIPTION: &'static str = "";
}

impl OpCert {
    /// OpCert factory / test only
    pub fn new(
        kes_vk: KesPublicKey,
        issue_number: u64,
        start_kes_period: KesPeriod,
        cold_secret_key: EdSecretKey,
    ) -> Self {
        let cold_vk: EdVerificationKey = cold_secret_key.verifying_key();
        let cert_sig = cold_secret_key.sign(&Self::compute_message_to_sign(
            &kes_vk,
            issue_number,
            start_kes_period,
        ));

        Self {
            opcert_without_vk: OpCertWithoutColdVerificationKey {
                kes_vk,
                issue_number,
                start_kes_period,
                cert_sig,
            },
            cold_vk,
        }
    }

    /// Get the KES verification key
    pub fn get_kes_verification_key(&self) -> KesPublicKey {
        self.opcert_without_vk.kes_vk
    }

    /// Get the issue number
    pub fn get_issue_number(&self) -> u64 {
        self.opcert_without_vk.issue_number
    }

    /// Get the start KES period
    pub fn get_start_kes_period(&self) -> KesPeriod {
        self.opcert_without_vk.start_kes_period
    }

    /// Get the certificate signature
    pub fn get_certificate_signature(&self) -> EdSignature {
        self.opcert_without_vk.cert_sig
    }

    /// Get the OpCert without cold verification key
    pub fn get_opcert_without_cold_verification_key(&self) -> OpCertWithoutColdVerificationKey {
        self.opcert_without_vk.clone()
    }

    /// Get the cold verification key
    pub fn get_cold_verification_key(&self) -> EdVerificationKey {
        self.cold_vk
    }

    /// Compute message to sign
    pub(crate) fn compute_message_to_sign(
        kes_vk: &KesPublicKey,
        issue_number: u64,
        start_kes_period: KesPeriod,
    ) -> [u8; 48] {
        let mut msg = [0u8; 48];
        msg[..32].copy_from_slice(kes_vk.as_bytes());
        msg[32..40].copy_from_slice(&issue_number.to_be_bytes());
        msg[40..48].copy_from_slice(&u64::from(start_kes_period).to_be_bytes());
        msg
    }

    /// Validate a certificate
    pub fn validate(&self) -> Result<(), ProtocolRegistrationErrorWrapper> {
        if self
            .cold_vk
            .verify(
                &Self::compute_message_to_sign(
                    &self.opcert_without_vk.kes_vk,
                    self.opcert_without_vk.issue_number,
                    self.opcert_without_vk.start_kes_period,
                ),
                &self.opcert_without_vk.cert_sig,
            )
            .is_ok()
        {
            return Ok(());
        }

        Err(ProtocolRegistrationErrorWrapper::OpCertInvalid)
    }

    /// Compute protocol party id as pool id bech 32
    pub fn compute_protocol_party_id(&self) -> Result<ProtocolPartyId, OpCertError> {
        let mut hasher = Blake2b::<U28>::new();
        hasher.update(self.cold_vk.as_bytes());
        let mut pool_id = [0u8; 28];
        pool_id.copy_from_slice(hasher.finalize().as_bytes());
        encode_bech32("pool", &pool_id).map_err(|_| OpCertError::PoolAddressEncoding)
    }

    /// Compute protocol party id as hash
    pub fn compute_protocol_party_id_as_hash(&self) -> String {
        let mut hasher = Blake2b::<U28>::new();
        hasher.update(self.cold_vk.as_bytes());
        hex::encode(hasher.finalize())
    }

    // /// Compute protocol party id as bytes
    // pub fn compute_protocol_party_id_as_bytes(&self) -> [0u8; 28] {
    //     let mut hasher = Blake2b::<U28>::new();
    //     hasher.update(self.cold_vk.as_bytes());
    //     hasher.finalize().as_bytes()
    // }

    /// Compute the hash of an OpCert
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.opcert_without_vk.kes_vk.as_bytes());
        hasher.update(self.opcert_without_vk.issue_number.to_be_bytes());
        hasher.update(self.opcert_without_vk.start_kes_period.to_be_bytes());
        hasher.update(self.opcert_without_vk.cert_sig.to_bytes());
        hasher.update(self.cold_vk.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Serialize for OpCert {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw_opcert_without_vk: RawOpCertWithoutColdVerificationKey =
            (&self.opcert_without_vk).into();
        let raw_cert = RawOpCert(raw_opcert_without_vk, self.cold_vk);

        raw_cert.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpCert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw_cert = RawOpCert::deserialize(deserializer)?;
        let raw_opcert_without_vk = &raw_cert.0;

        Ok(Self {
            opcert_without_vk: OpCertWithoutColdVerificationKey {
                kes_vk: KesPublicKey::from_bytes(&raw_opcert_without_vk.0)
                    .map_err(|_| Error::custom("KES vk serialisation error"))?,
                issue_number: raw_opcert_without_vk.1,
                start_kes_period: KesPeriod(raw_opcert_without_vk.2),
                cert_sig: EdSignature::from_slice(&raw_opcert_without_vk.3)
                    .map_err(|_| Error::custom("ed25519 signature serialisation error"))?,
            },
            cold_vk: raw_cert.1,
        })
    }
}

impl From<(OpCertWithoutColdVerificationKey, EdVerificationKey)> for OpCert {
    fn from(
        (opcert_without_vk, cold_vk): (OpCertWithoutColdVerificationKey, EdVerificationKey),
    ) -> Self {
        Self {
            opcert_without_vk,
            cold_vk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_helper::cardano::ColdKeyGenerator;
    use crate::test::{TempDir, crypto_helper::SerDeShelleyFileFormatTestExtension};

    use kes_summed_ed25519::{kes::Sum6Kes, traits::KesSk};
    use std::path::PathBuf;

    fn setup_temp_directory(test_name: &str) -> PathBuf {
        TempDir::create("mithril_cardano_opcert", test_name)
    }

    #[test]
    fn test_vector_opcert() {
        let temp_dir = setup_temp_directory("test_vector_opcert");
        let keypair = ColdKeyGenerator::create_deterministic_keypair([0u8; 32]);
        let mut dummy_key_buffer = [0u8; Sum6Kes::SIZE + 4];
        let mut dummy_seed = [0u8; 32];
        let (_, kes_verification_key) = Sum6Kes::keygen(&mut dummy_key_buffer, &mut dummy_seed);
        let operational_certificate = OpCert::new(kes_verification_key, 0, KesPeriod(0), keypair);
        assert!(operational_certificate.validate().is_ok());

        let operation_certificate_file = temp_dir.join("node.cert");
        operational_certificate
            .to_file(&operation_certificate_file)
            .expect("operational certificate file export should not fail");

        let operational_certificate: OpCert = OpCert::from_file(&operation_certificate_file)
            .expect("operational certificate file import should not fail");
        assert!(operational_certificate.validate().is_ok());

        let party_id = operational_certificate
            .compute_protocol_party_id()
            .expect("compute protocol party_id should not fail");
        assert_eq!(
            "pool1mxyec46067n3querj9cxkk0g0zlag93pf3ya9vuyr3wgkq2e6t7".to_string(),
            party_id
        );

        let party_id_as_hash = operational_certificate.compute_protocol_party_id_as_hash();
        assert_eq!(
            "d9899c574fd7a710732391706b59e878bfd416214c49d2b3841c5c8b".to_string(),
            party_id_as_hash
        );

        let operational_certificate_bytes_without_cold_vk = operational_certificate
            .get_opcert_without_cold_verification_key()
            .to_cbor_bytes()
            .expect("compute CBOR bytes should not fail");
        assert_eq!(
            "845820e650d7531509bb6cffd7998c28c68e4ec8fa621a0952206ea11eb03fcd7dcb2900005840d4abce27da05ff03c1342cc6ab53135072e1babf9cc05492f59f1ff009f70457aaa862c7158b13be0cfb41d7a91a562589bc110eb2cdaf5d2756048abbea5f05",
            hex::encode(operational_certificate_bytes_without_cold_vk)
        );
    }
}
