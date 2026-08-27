use std::{collections::HashMap, fmt::Display, hash::Hash, str::FromStr};

use anyhow::anyhow;
#[cfg(feature = "future_snark")]
use midnight_proofs::transcript::Blake2b256;
use serde::{Deserialize, Serialize};

use crate::{
    MembershipDigest, Parameters, StmError, StmResult, codec,
    membership_commitment::MerkleBatchPath, proof_system::ConcatenationProof,
};
#[cfg(feature = "future_snark")]
use crate::{
    circuits::halo2_ivc::state::Global,
    proof_system::{
        SnarkProof, SnarkVerifierSetup,
        ivc_halo2_snark::{proof::IvcProof, verifier_setup::IvcVerifierSetup},
    },
};

use super::{
    AggregateSignatureError, AggregateVerificationKey, AncillaryVerifierData,
    GenesisVerificationKeyBundle,
};

/// The type of STM aggregate signature.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AggregateSignatureType {
    /// Concatenation proof system.
    #[default]
    Concatenation,
    /// SNARK proof system.
    #[cfg(feature = "future_snark")]
    Snark,
    /// IVC SNARK proof system.
    #[cfg(feature = "future_snark")]
    IvcSnark,
}

impl AggregateSignatureType {
    /// The prefix byte used in the byte representation of the aggregate signature type.
    ///
    /// IMPORTANT: This value is used in serialization/deserialization. Changing it will break compatibility.
    pub fn get_byte_encoding_prefix(&self) -> u8 {
        match self {
            AggregateSignatureType::Concatenation => 0,
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => 1,
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => 2,
        }
    }

    /// Create an aggregate signature type from a prefix byte.
    ///
    /// IMPORTANT: This value is used in serialization/deserialization. Changing it will break compatibility.
    pub fn from_byte_encoding_prefix(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(AggregateSignatureType::Concatenation),
            #[cfg(feature = "future_snark")]
            1 => Some(AggregateSignatureType::Snark),
            #[cfg(feature = "future_snark")]
            2 => Some(AggregateSignatureType::IvcSnark),
            _ => None,
        }
    }

    /// Whether a valid certificate carrying this aggregate signature type certifies the full
    /// certificate chain back to the genesis certificate on its own.
    ///
    /// Returns `false` for the current proof systems. Recursive proof systems (e.g. IVC) return
    /// `true`, which lets certificate chain verification stop at the first valid such certificate
    /// instead of walking back to the genesis certificate.
    pub fn certifies_full_certificate_chain(&self) -> bool {
        match self {
            AggregateSignatureType::Concatenation => false,
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => false,
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => true,
        }
    }
}

impl<D: MembershipDigest> From<&AggregateSignature<D>> for AggregateSignatureType {
    fn from(aggr_sig: &AggregateSignature<D>) -> Self {
        match aggr_sig {
            AggregateSignature::Concatenation(_) => AggregateSignatureType::Concatenation,
            #[cfg(feature = "future_snark")]
            AggregateSignature::Snark(_) => AggregateSignatureType::Snark,
            #[cfg(feature = "future_snark")]
            AggregateSignature::IvcSnark(_) => AggregateSignatureType::IvcSnark,
        }
    }
}

impl FromStr for AggregateSignatureType {
    type Err = StmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Concatenation" => Ok(AggregateSignatureType::Concatenation),
            #[cfg(feature = "future_snark")]
            "Snark" => Ok(AggregateSignatureType::Snark),
            #[cfg(feature = "future_snark")]
            "IvcSnark" => Ok(AggregateSignatureType::IvcSnark),
            _ => Err(anyhow!(AggregateSignatureError::UnknownProofSystem(
                s.to_string()
            ))),
        }
    }
}

impl Display for AggregateSignatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregateSignatureType::Concatenation => write!(f, "Concatenation"),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => write!(f, "Snark"),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => write!(f, "IvcSnark"),
        }
    }
}

/// CBOR-friendly envelope for aggregate signature serialization.
///
/// Used as an intermediate representation because `AggregateSignature` uses
/// `#[serde(untagged)]` which is incompatible with ciborium's CBOR deserialization.
#[derive(Serialize, Deserialize)]
struct AggregateSignatureCborEnvelope {
    signature_type: u8,
    #[serde(with = "serde_bytes")]
    proof_bytes: Vec<u8>,
}

/// An STM aggregate signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "MerkleBatchPath<D::ConcatenationHash>: Serialize",
    deserialize = "MerkleBatchPath<D::ConcatenationHash>: Deserialize<'de>"
))]
pub enum AggregateSignature<D: MembershipDigest> {
    /// SNARK proof system.
    #[cfg(feature = "future_snark")]
    Snark(Box<SnarkProof<D>>),

    /// IVC SNARK proof system.
    #[cfg(feature = "future_snark")]
    IvcSnark(Box<IvcProof<Blake2b256>>),

    /// Concatenation proof system.
    // The 'untagged' attribute is required for backward compatibility.
    // It implies that this variant is placed at the end of the enum.
    // It will be removed when the support for JSON hex encoding is dropped in the calling crates.
    #[serde(untagged)]
    Concatenation(Box<ConcatenationProof<D>>),
}

impl<D: MembershipDigest> AggregateSignature<D> {
    /// Verify an aggregate signature.
    pub fn verify(
        &self,
        msg: &[u8],
        avk: &AggregateVerificationKey<D>,
        parameters: &Parameters,
        ancillary_verifier_data: Option<AncillaryVerifierData>,
        genesis_verification_key_bundle: Option<GenesisVerificationKeyBundle>,
    ) -> StmResult<()> {
        let _ = &ancillary_verifier_data;
        let _ = &genesis_verification_key_bundle;
        match self {
            AggregateSignature::Concatenation(concatenation_proof) => concatenation_proof.verify(
                msg,
                avk.to_concatenation_aggregate_verification_key(),
                parameters,
            ),
            #[cfg(feature = "future_snark")]
            AggregateSignature::Snark(snark_proof) => {
                let snark_avk = avk.to_snark_aggregate_verification_key().ok_or_else(|| {
                    anyhow!(AggregateSignatureError::MissingSnarkAggregateVerificationKey)
                })?;
                let snark_verifier_data = ancillary_verifier_data
                    .as_ref()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingAncillaryVerifierData))?
                    .as_snark_verifier_data()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingSnarkVerifierData))?;
                let verifier_setup = SnarkVerifierSetup::try_new()?;
                snark_proof.verify(
                    msg,
                    snark_avk,
                    snark_verifier_data,
                    &verifier_setup.verifier_params,
                )
            }
            #[cfg(feature = "future_snark")]
            AggregateSignature::IvcSnark(ivc_proof) => {
                let ivc_verifier_data = ancillary_verifier_data
                    .as_ref()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingAncillaryVerifierData))?
                    .as_ivc_verifier_data()
                    .ok_or_else(|| anyhow!(AggregateSignatureError::MissingIvcVerifierData))?;

                let genesis_verification_key_bundle =
                    genesis_verification_key_bundle.ok_or_else(|| {
                        anyhow!(AggregateSignatureError::MissingGenesisVerificationKeyBundle)
                    })?;

                let global = Global::new(
                    ivc_verifier_data.genesis_message(),
                    genesis_verification_key_bundle.schnorr,
                    ivc_verifier_data.certificate_circuit_verification_key(),
                    ivc_verifier_data.ivc_circuit_verification_key(),
                )?;

                let verifier_setup = IvcVerifierSetup::try_new(
                    ivc_verifier_data.certificate_circuit_verification_key(),
                    ivc_verifier_data.ivc_circuit_verification_key(),
                )?;

                ivc_proof.verify(msg, &global, &verifier_setup)
            }
        }
    }

    /// Batch verify a set of aggregate signatures.
    pub fn batch_verify(
        aggregate_signatures: &[Self],
        msgs: &[Vec<u8>],
        avks: &[AggregateVerificationKey<D>],
        parameters: &[Parameters],
        ancillary_verifier_datas: &[Option<AncillaryVerifierData>],
        genesis_verification_key_bundles: &[Option<GenesisVerificationKeyBundle>],
    ) -> StmResult<()> {
        type AggregateEntriesForAggregateSignatureType<D> = (
            AggregateSignature<D>,
            AggregateVerificationKey<D>,
            Vec<u8>,
            Parameters,
            Option<AncillaryVerifierData>,
            Option<GenesisVerificationKeyBundle>,
        );

        fn check_input_lengths(
            expected_length: usize,
            labeled_lengths: &[(&str, usize)],
        ) -> StmResult<()> {
            for (name, length) in labeled_lengths {
                if *length != expected_length {
                    return Err(anyhow!(AggregateSignatureError::BatchInvalid).context(format!(
                        "the number of {name} ({length}) does not match the number of aggregate signatures ({expected_length})"
                    )));
                }
            }
            Ok(())
        }

        check_input_lengths(
            aggregate_signatures.len(),
            &[
                ("messages", msgs.len()),
                ("aggregate verification keys", avks.len()),
                ("parameters", parameters.len()),
                ("ancillary verifier data", ancillary_verifier_datas.len()),
                (
                    "genesis verification key bundles",
                    genesis_verification_key_bundles.len(),
                ),
            ],
        )?;

        let aggregate_entries_by_aggregate_signature_type: HashMap<
            AggregateSignatureType,
            Vec<AggregateEntriesForAggregateSignatureType<D>>,
        > = aggregate_signatures
            .iter()
            .zip(msgs.iter())
            .zip(avks.iter())
            .zip(parameters.iter())
            .zip(ancillary_verifier_datas.iter())
            .zip(genesis_verification_key_bundles.iter())
            .fold(
                HashMap::new(),
                |mut acc,
                 (
                    ((((aggregate_signature, msg), avk), parameters), ancillary_verifier_data),
                    genesis_verification_key_bundle,
                )| {
                    let signature_type = AggregateSignatureType::from(aggregate_signature);
                    acc.entry(signature_type).or_default().push((
                        aggregate_signature.clone(),
                        avk.clone(),
                        msg.clone(),
                        *parameters,
                        ancillary_verifier_data.clone(),
                        genesis_verification_key_bundle.clone(),
                    ));
                    acc
                },
            );

        aggregate_entries_by_aggregate_signature_type
            .into_iter()
            .try_for_each(|(aggregate_signature_type, aggregate_entries)| {
                match aggregate_signature_type {
                    AggregateSignatureType::Concatenation => {
                        let avks = aggregate_entries
                            .iter()
                            .map(|(_, avk, _, _, _, _)| {
                                avk.to_concatenation_aggregate_verification_key()
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        let concatenation_proofs = aggregate_entries
                            .iter()
                            .filter_map(|(aggregate_signature, _, _, _, _, _)| {
                                aggregate_signature.to_concatenation_proof().cloned()
                            })
                            .collect::<Vec<_>>();
                        let msgs = aggregate_entries
                            .iter()
                            .map(|(_, _, msg, _, _, _)| msg.clone())
                            .collect::<Vec<_>>();
                        let parameters = aggregate_entries
                            .iter()
                            .map(|(_, _, _, parameters, _, _)| *parameters)
                            .collect::<Vec<_>>();
                        check_input_lengths(
                            concatenation_proofs.len(),
                            &[
                                ("messages", msgs.len()),
                                ("aggregate verification keys", avks.len()),
                                ("parameters", parameters.len()),
                            ],
                        )?;
                        ConcatenationProof::batch_verify(
                            &concatenation_proofs,
                            &msgs,
                            &avks,
                            &parameters,
                        )
                    }
                    #[cfg(feature = "future_snark")]
                    AggregateSignatureType::Snark => {
                        for (
                            aggregate_signature,
                            avk,
                            msg,
                            parameters,
                            ancillary_verifier_data,
                            genesis_verification_key_bundle,
                        ) in aggregate_entries
                        {
                            aggregate_signature.verify(
                                &msg,
                                &avk,
                                &parameters,
                                ancillary_verifier_data,
                                genesis_verification_key_bundle,
                            )?;
                        }

                        Ok(())
                    }
                    #[cfg(feature = "future_snark")]
                    AggregateSignatureType::IvcSnark => {
                        for (
                            aggregate_signature,
                            avk,
                            msg,
                            parameters,
                            ancillary_verifier_data,
                            genesis_verification_key_bundle,
                        ) in aggregate_entries
                        {
                            aggregate_signature.verify(
                                &msg,
                                &avk,
                                &parameters,
                                ancillary_verifier_data,
                                genesis_verification_key_bundle,
                            )?;
                        }

                        Ok(())
                    }
                }
            })
    }

    /// Convert an aggregate signature to CBOR bytes with a version prefix.
    ///
    /// Uses a type-discriminated envelope to work around the `#[serde(untagged)]`
    /// attribute which is incompatible with ciborium's CBOR deserialization.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        let aggregate_signature_type: AggregateSignatureType = self.into();
        let proof_bytes = match self {
            AggregateSignature::Concatenation(concatenation_proof) => {
                concatenation_proof.to_bytes()?
            }
            #[cfg(feature = "future_snark")]
            AggregateSignature::Snark(snark_proof) => snark_proof.to_bytes()?,
            #[cfg(feature = "future_snark")]
            AggregateSignature::IvcSnark(ivc_proof) => ivc_proof.to_bytes()?,
        };
        let envelope = AggregateSignatureCborEnvelope {
            signature_type: aggregate_signature_type.get_byte_encoding_prefix(),
            proof_bytes,
        };
        codec::to_cbor_bytes(&envelope)
    }

    /// Extract an aggregate signature from a byte slice.
    ///
    /// Supports both the legacy type-prefix byte format and the new
    /// versioned CBOR format. Because the legacy `Snark` type prefix is `0x01`
    /// (same as the CBOR version byte), this method uses try-CBOR-then-fallback
    /// when the first byte is `0x01`.
    ///
    /// Note: if a valid CBOR payload is corrupted in transit, CBOR decoding
    /// will fail and the legacy decoder may accept the corrupted bytes as a
    /// structurally valid (but semantically garbage) proof. This is acceptable
    /// because the resulting proof will always fail cryptographic verification.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            Self::from_bytes_cbor(&bytes[1..]).or_else(|_| Self::from_bytes_legacy(bytes))
        } else {
            Self::from_bytes_legacy(bytes)
        }
    }

    /// Decode from CBOR envelope bytes (without version prefix).
    ///
    /// The `signature_type` field in the envelope selects which inner decoder
    /// to call. A mismatch between `signature_type` and the actual content of
    /// `proof_bytes` is caught implicitly: the inner `from_bytes` call will
    /// fail because the byte layout of each proof type is incompatible.
    fn from_bytes_cbor(bytes: &[u8]) -> StmResult<Self> {
        let envelope: AggregateSignatureCborEnvelope = codec::from_cbor_bytes(bytes)?;
        let proof_type = AggregateSignatureType::from_byte_encoding_prefix(envelope.signature_type)
            .ok_or(AggregateSignatureError::SerializationError)?;
        match proof_type {
            AggregateSignatureType::Concatenation => Ok(AggregateSignature::Concatenation(
                Box::new(ConcatenationProof::from_bytes(&envelope.proof_bytes)?),
            )),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => Ok(AggregateSignature::Snark(Box::new(
                SnarkProof::from_bytes(&envelope.proof_bytes)?,
            ))),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => Ok(AggregateSignature::IvcSnark(Box::new(
                IvcProof::from_bytes(&envelope.proof_bytes)?,
            ))),
        }
    }

    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Self> {
        let proof_type_byte = bytes.first().ok_or(AggregateSignatureError::SerializationError)?;
        let proof_bytes = &bytes[1..];
        let proof_type = AggregateSignatureType::from_byte_encoding_prefix(*proof_type_byte)
            .ok_or(AggregateSignatureError::SerializationError)?;

        match proof_type {
            AggregateSignatureType::Concatenation => Ok(AggregateSignature::Concatenation(
                Box::new(ConcatenationProof::from_bytes(proof_bytes)?),
            )),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => Ok(AggregateSignature::Snark(Box::new(
                SnarkProof::from_bytes(proof_bytes)?,
            ))),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => Ok(AggregateSignature::IvcSnark(Box::new(
                IvcProof::from_bytes(proof_bytes)?,
            ))),
        }
    }

    /// If the aggregate signature is a concatenation proof, return it.
    pub fn to_concatenation_proof(&self) -> Option<&ConcatenationProof<D>> {
        match self {
            AggregateSignature::Concatenation(proof) => Some(proof),
            #[cfg(feature = "future_snark")]
            AggregateSignature::Snark(_) => None,
            #[cfg(feature = "future_snark")]
            AggregateSignature::IvcSnark(_) => None,
        }
    }

    /// If the aggregate signature is a SNARK proof, return it.
    #[cfg(feature = "future_snark")]
    pub fn get_snark_proof(&self) -> Option<&SnarkProof<D>> {
        match self {
            AggregateSignature::Snark(proof) => Some(proof),
            AggregateSignature::Concatenation(_) => None,
            AggregateSignature::IvcSnark(_) => None,
        }
    }

    /// If the aggregate signature is an IVC proof, return it.
    #[cfg(feature = "future_snark")]
    pub fn get_ivc_proof(&self) -> Option<&IvcProof<Blake2b256>> {
        match self {
            AggregateSignature::IvcSnark(proof) => Some(proof),
            AggregateSignature::Concatenation(_) => None,
            AggregateSignature::Snark(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "future_snark")]
    mod ivc_proof {
        use midnight_proofs::transcript::Blake2b256;

        use crate::{Clerk, Parameters, protocol::aggregate_signature::tests::setup_equal_parties};

        use crate::{
            AggregateSignature, AggregateSignatureError, AncillaryVerifierData,
            MithrilMembershipDigest,
            circuits::halo2_ivc::{
                tests::common::asset_readers::{
                    load_embedded_next_epoch_step_output_asset,
                    load_embedded_verification_context_asset,
                },
                types::MessageHash,
            },
            proof_system::ivc_halo2_snark::{proof::IvcProof, verifier_setup::IvcVerifierData},
        };

        const LOADED_CONTEXT_MSG: [u8; 32] = [
            22, 148, 87, 37, 149, 0, 124, 10, 156, 94, 108, 6, 78, 59, 239, 80, 126, 213, 158, 211,
            191, 213, 128, 70, 128, 30, 235, 80, 192, 191, 159, 67,
        ];

        #[test]
        fn ivc_verify_fails_without_genesis_verification_key_bundle() {
            let step_output = load_embedded_next_epoch_step_output_asset()
                .expect("recursive step output asset should load");
            let context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");

            let params = Parameters {
                m: 10,
                k: 3,
                phi_f: 0.9,
            };
            let ps = setup_equal_parties(params, 5);
            let avk = Clerk::new_clerk_from_signer(&ps[0]).compute_aggregate_verification_key();

            let ancillary = AncillaryVerifierData::IvcSnark(IvcVerifierData::new(
                MessageHash::ZERO,
                context.certificate_verifying_key,
                context.recursive_verifying_key,
            ));
            let proof = IvcProof::<Blake2b256>::new(
                step_output.ivc_proof,
                step_output.next_state,
                step_output.next_accumulator,
            );
            let ivc_proof =
                AggregateSignature::<MithrilMembershipDigest>::IvcSnark(Box::new(proof));

            let error = ivc_proof
                .verify(&LOADED_CONTEXT_MSG, &avk, &params, Some(ancillary), None)
                .expect_err(
                    "verification must fail when the genesis verification key bundle is absent",
                );
            assert_eq!(
                error.downcast_ref::<AggregateSignatureError>(),
                Some(&AggregateSignatureError::MissingGenesisVerificationKeyBundle),
                "an absent genesis verification key bundle must be rejected, got: {error}"
            );
        }

        #[test]
        fn ivc_verify_fails_without_ancillary_verifier_data() {
            let step_output = load_embedded_next_epoch_step_output_asset()
                .expect("recursive step output asset should load");

            let nparties = 5;
            let m = 10;
            let k = 3;
            let params = Parameters { m, k, phi_f: 0.9 };
            let ps = setup_equal_parties(params, nparties);
            let clerk = Clerk::new_clerk_from_signer(&ps[0]);
            let avk = clerk.compute_aggregate_verification_key();

            let proof = IvcProof::<Blake2b256>::new(
                step_output.ivc_proof,
                step_output.next_state,
                step_output.next_accumulator,
            );

            let ivc_proof =
                AggregateSignature::<MithrilMembershipDigest>::IvcSnark(Box::new(proof));

            let err = ivc_proof
                .verify(&LOADED_CONTEXT_MSG, &avk, &params, None, None)
                .expect_err("Should fail without ancillary verifier data.");
            assert_eq!(
                err.downcast_ref::<AggregateSignatureError>(),
                Some(&AggregateSignatureError::MissingAncillaryVerifierData),
                "missing ancillary verifier data must be rejected, got: {err}"
            );
        }
    }

    #[cfg(feature = "future_snark")]
    mod snark_proof_verify {
        use crate::{
            AggregateSignature, AggregateSignatureError, AggregateSignatureType,
            AggregateVerificationKey, AncillaryVerifierData, Clerk, MithrilMembershipDigest,
            Parameters, SnarkProof,
            circuits::halo2_ivc::{
                tests::common::asset_readers::load_embedded_verification_context_asset,
                types::MessageHash,
            },
            proof_system::{
                MERKLE_TREE_DEPTH_FOR_SNARK, ivc_halo2_snark::verifier_setup::IvcVerifierData,
            },
            protocol::aggregate_signature::tests::setup_equal_parties,
        };

        type D = MithrilMembershipDigest;

        fn snark_capable_avk_and_params() -> (AggregateVerificationKey<D>, Parameters) {
            let params = Parameters {
                m: 10,
                k: 3,
                phi_f: 0.9,
            };
            let ps = setup_equal_parties(params, 5);
            let avk = Clerk::new_clerk_from_signer(&ps[0]).compute_aggregate_verification_key();
            (avk, params)
        }

        // A dummy Snark proof suffices: the ancillary-data checks fire before any cryptographic
        // verification, so the proof bytes are never inspected.
        fn dummy_snark_aggregate_signature(params: Parameters) -> AggregateSignature<D> {
            let proof = SnarkProof::<D>::new(vec![], params, MERKLE_TREE_DEPTH_FOR_SNARK);
            AggregateSignature::Snark(Box::new(proof))
        }

        #[test]
        fn snark_verify_fails_without_ancillary_verifier_data() {
            let (avk, params) = snark_capable_avk_and_params();
            let snark = dummy_snark_aggregate_signature(params);

            let err = snark
                .verify(&[0u8; 32], &avk, &params, None, None)
                .expect_err("Snark verify must fail without ancillary verifier data");
            assert_eq!(
                err.downcast_ref::<AggregateSignatureError>(),
                Some(&AggregateSignatureError::MissingAncillaryVerifierData),
                "missing ancillary verifier data must be rejected, got: {err}"
            );
        }

        #[test]
        fn snark_verify_fails_with_ivc_ancillary_verifier_data() {
            let (avk, params) = snark_capable_avk_and_params();
            let snark = dummy_snark_aggregate_signature(params);
            let context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");
            let wrong_typed_ancillary = AncillaryVerifierData::IvcSnark(IvcVerifierData::new(
                MessageHash::ZERO,
                context.certificate_verifying_key,
                context.recursive_verifying_key,
            ));

            let err = snark
                .verify(&[0u8; 32], &avk, &params, Some(wrong_typed_ancillary), None)
                .expect_err("Snark verify must fail with wrong-typed (IvcSnark) ancillary data");
            assert_eq!(
                err.downcast_ref::<AggregateSignatureError>(),
                Some(&AggregateSignatureError::MissingSnarkVerifierData),
                "wrong-typed ancillary verifier data must be rejected, got: {err}"
            );
        }

        #[test]
        fn legacy_outer_envelope_wraps_new_cbor_snark_proof() {
            let params = Parameters {
                m: 10,
                k: 3,
                phi_f: 0.9,
            };
            let proof = SnarkProof::<D>::new(vec![1, 2, 3], params, MERKLE_TREE_DEPTH_FOR_SNARK);
            let inner = proof.to_bytes().expect("proof serialization should not fail");

            // Legacy outer type-prefix framing wrapping a new-format (versioned CBOR) inner proof
            // must still decode through the retained outer legacy dispatch.
            let mut legacy_outer = vec![AggregateSignatureType::Snark.get_byte_encoding_prefix()];
            legacy_outer.extend_from_slice(&inner);

            let decoded = AggregateSignature::<D>::from_bytes(&legacy_outer)
                .expect("legacy outer envelope wrapping a new CBOR proof should decode");
            assert!(matches!(decoded, AggregateSignature::Snark(_)));
        }
    }

    mod envelope_compatibility {
        use super::*;
        use crate::codec;

        #[test]
        fn forward_compatible_with_extra_fields() {
            #[derive(Serialize)]
            struct EvolvedEnvelope {
                signature_type: u8,
                proof_bytes: Vec<u8>,
                extra_field: String,
            }

            let evolved = EvolvedEnvelope {
                signature_type: 0,
                proof_bytes: vec![1, 2, 3],
                extra_field: "future".to_string(),
            };
            let bytes =
                codec::to_cbor_bytes(&evolved).expect("evolved serialization should not fail");

            let envelope: AggregateSignatureCborEnvelope = codec::from_cbor_bytes(&bytes[1..])
                .expect("decoding with extra field should succeed");
            assert_eq!(0, envelope.signature_type);
            assert_eq!(vec![1, 2, 3], envelope.proof_bytes);
        }

        #[test]
        fn backward_compatible_with_missing_optional_fields() {
            #[derive(Serialize, Deserialize)]
            struct MinimalEnvelope {
                signature_type: u8,
                proof_bytes: Vec<u8>,
            }

            let minimal = MinimalEnvelope {
                signature_type: 0,
                proof_bytes: vec![4, 5, 6],
            };
            let bytes =
                codec::to_cbor_bytes(&minimal).expect("minimal serialization should not fail");

            let envelope: AggregateSignatureCborEnvelope =
                codec::from_cbor_bytes(&bytes[1..]).expect("decoding from minimal should succeed");
            assert_eq!(0, envelope.signature_type);
            assert_eq!(vec![4, 5, 6], envelope.proof_bytes);
        }
    }

    mod batch_verify {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::*;
        use crate::{
            Initializer, KeyRegistration, MithrilMembershipDigest, Parameters, RegistrationEntry,
        };

        type D = MithrilMembershipDigest;

        fn assert_batch_invalid_error(result: StmResult<()>) {
            let error = result.expect_err("Expected a BatchInvalid error");
            assert!(
                matches!(
                    error.downcast_ref::<AggregateSignatureError>(),
                    Some(AggregateSignatureError::BatchInvalid)
                ),
                "Expected BatchInvalid error, got: {error}"
            );
        }

        fn build_aggregate_verification_key() -> AggregateVerificationKey<D> {
            let params = Parameters {
                k: 1,
                m: 10,
                phi_f: 1.0,
            };
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut kr = KeyRegistration::initialize();
            let p = Initializer::new(params, 1, &mut rng);
            let entry: RegistrationEntry = p.clone().try_into().unwrap();
            kr.register_by_entry(&entry).unwrap();
            let closed_reg = kr.close_registration(&params).unwrap();
            AggregateVerificationKey::from(&closed_reg)
        }

        #[test]
        fn returns_error_when_messages_length_differs_from_signatures() {
            let result =
                AggregateSignature::<D>::batch_verify(&[], &[vec![1u8]], &[], &[], &[], &[]);

            assert_batch_invalid_error(result);
        }

        #[test]
        fn returns_error_when_avks_length_differs_from_signatures() {
            let avk = build_aggregate_verification_key();
            let result = AggregateSignature::<D>::batch_verify(&[], &[], &[avk], &[], &[], &[]);

            assert_batch_invalid_error(result);
        }

        #[test]
        fn returns_error_when_parameters_length_differs_from_signatures() {
            let result = AggregateSignature::<D>::batch_verify(
                &[],
                &[],
                &[],
                &[Parameters {
                    k: 1,
                    m: 100,
                    phi_f: 0.2,
                }],
                &[],
                &[],
            );

            assert_batch_invalid_error(result);
        }

        #[test]
        fn returns_error_when_ancillary_verifier_datas_length_differs_from_signatures() {
            let result = AggregateSignature::<D>::batch_verify(&[], &[], &[], &[], &[None], &[]);

            assert_batch_invalid_error(result);
        }

        #[test]
        fn returns_error_when_genesis_verification_key_bundles_length_differs_from_signatures() {
            let result = AggregateSignature::<D>::batch_verify(&[], &[], &[], &[], &[], &[None]);

            assert_batch_invalid_error(result);
        }

        #[test]
        fn succeeds_when_all_inputs_are_empty() {
            let result = AggregateSignature::<D>::batch_verify(&[], &[], &[], &[], &[], &[]);

            assert!(result.is_ok());
        }
    }

    mod aggregate_signature_type_golden {
        use super::*;

        #[test]
        fn golden_bytes_encoding_prefix_for_concatenation() {
            assert_eq!(
                0u8,
                AggregateSignatureType::Concatenation.get_byte_encoding_prefix()
            );
            assert_eq!(
                AggregateSignatureType::from_byte_encoding_prefix(0u8),
                Some(AggregateSignatureType::Concatenation)
            );
        }

        #[cfg(feature = "future_snark")]
        #[test]
        fn golden_bytes_encoding_prefix_for_snark() {
            assert_eq!(
                1u8,
                AggregateSignatureType::Snark.get_byte_encoding_prefix()
            );
            assert_eq!(
                AggregateSignatureType::from_byte_encoding_prefix(1u8),
                Some(AggregateSignatureType::Snark)
            );
        }
    }

    #[test]
    fn golden_certifies_full_certificate_chain_per_aggregate_signature_type() {
        fn assert_golden_value(aggregate_signature_type: AggregateSignatureType, expected: bool) {
            assert_eq!(
                expected,
                aggregate_signature_type.certifies_full_certificate_chain(),
                "golden 'certifies_full_certificate_chain' value changed for {aggregate_signature_type}, this alters certificate chain verification semantics"
            );
        }

        assert_golden_value(AggregateSignatureType::Concatenation, false);
        #[cfg(feature = "future_snark")]
        assert_golden_value(AggregateSignatureType::Snark, false);
    }

    mod aggregate_signature_golden_concatenation {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::{AggregateSignature, AggregateSignatureType};
        use crate::{
            AncillaryProofInput, Clerk, KeyRegistration, MithrilMembershipDigest, Parameters,
            RegistrationEntry, Signer, VerificationKeyProofOfPossessionForConcatenation,
            proof_system::ConcatenationProofSigner, signature_scheme::BlsSigningKey,
        };

        type D = MithrilMembershipDigest;

        const GOLDEN_JSON: &str = r#"
        {
            "signatures": [
                [
                {
                    "sigma": [
                    149, 157, 201, 187, 140, 54, 0, 128, 209, 88, 16, 203, 61, 78, 77, 98,
                    161, 133, 58, 152, 29, 74, 217, 113, 64, 100, 10, 161, 186, 167, 133,
                    114, 211, 153, 218, 56, 223, 84, 105, 242, 41, 54, 224, 170, 208, 185,
                    126, 83
                    ],
                    "indexes": [1, 4, 5, 8],
                    "signer_index": 0
                },
                [
                    [
                    143, 161, 255, 48, 78, 57, 204, 220, 25, 221, 164, 252, 248, 14, 56,
                    126, 186, 135, 228, 188, 145, 181, 52, 200, 97, 99, 213, 46, 0, 199,
                    193, 89, 187, 88, 29, 135, 173, 244, 86, 36, 83, 54, 67, 164, 6, 137,
                    94, 72, 6, 105, 128, 128, 93, 48, 176, 11, 4, 246, 138, 48, 180, 133,
                    90, 142, 192, 24, 193, 111, 142, 31, 76, 111, 110, 234, 153, 90, 208,
                    192, 31, 124, 95, 102, 49, 158, 99, 52, 220, 165, 94, 251, 68, 69,
                    121, 16, 224, 194
                    ],
                    1
                ]
                ],
                [
                {
                    "sigma": [
                    149, 169, 22, 201, 216, 97, 163, 188, 115, 210, 217, 236, 233, 161,
                    201, 13, 42, 132, 12, 63, 5, 31, 120, 22, 78, 177, 125, 134, 208, 205,
                    73, 58, 247, 141, 59, 62, 187, 81, 213, 30, 153, 218, 41, 42, 110,
                    156, 161, 205
                    ],
                    "indexes": [0, 3, 6],
                    "signer_index": 1
                },
                [
                    [
                    145, 56, 175, 32, 122, 187, 214, 226, 251, 148, 88, 9, 1, 103, 159,
                    146, 80, 166, 107, 243, 251, 236, 41, 28, 111, 128, 207, 164, 132,
                    147, 228, 83, 246, 228, 170, 68, 89, 78, 60, 28, 123, 130, 88, 234,
                    38, 97, 42, 65, 1, 100, 53, 18, 78, 131, 8, 61, 122, 131, 238, 84,
                    233, 223, 154, 118, 118, 73, 28, 27, 101, 78, 80, 233, 123, 206, 220,
                    174, 134, 205, 71, 110, 112, 180, 97, 98, 0, 113, 69, 145, 231, 168,
                    43, 173, 172, 56, 104, 208
                    ],
                    1
                ]
                ]
            ],
            "batch_proof": { "values": [], "indices": [0, 1], "hasher": null }
        }
        "#;

        fn golden_value() -> AggregateSignature<D> {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let msg = [0u8; 16];
            let params = Parameters {
                m: 10,
                k: 5,
                phi_f: 0.8,
            };
            let sk_1 = BlsSigningKey::generate(&mut rng);
            let sk_2 = BlsSigningKey::generate(&mut rng);
            let pk_1 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_1);
            let pk_2 = VerificationKeyProofOfPossessionForConcatenation::from(&sk_2);

            let mut key_reg = KeyRegistration::initialize();
            let entry1 = RegistrationEntry::new(
                pk_1,
                1,
                #[cfg(feature = "future_snark")]
                None,
            )
            .unwrap();
            let entry2 = RegistrationEntry::new(
                pk_2,
                1,
                #[cfg(feature = "future_snark")]
                None,
            )
            .unwrap();

            key_reg.register_by_entry(&entry1).unwrap();
            key_reg.register_by_entry(&entry2).unwrap();
            let closed_key_reg = key_reg.close_registration(&params).unwrap();

            let clerk = Clerk::new_clerk_from_closed_key_registration(&params, &closed_key_reg);

            let signer_1: Signer<D> = Signer::new(
                0,
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_1,
                    pk_1.vk,
                    closed_key_reg.to_merkle_tree().to_merkle_tree_batch_commitment(),
                ),
                closed_key_reg.clone(),
                params,
                1,
                #[cfg(feature = "future_snark")]
                None,
            );

            let signer_2: Signer<D> = Signer::new(
                1,
                ConcatenationProofSigner::new(
                    1,
                    2,
                    params,
                    sk_2,
                    pk_2.vk,
                    closed_key_reg.to_merkle_tree().to_merkle_tree_batch_commitment(),
                ),
                closed_key_reg.clone(),
                params,
                1,
                #[cfg(feature = "future_snark")]
                None,
            );
            let signature_1 = signer_1.create_single_signature(&msg).unwrap();
            let signature_2 = signer_2.create_single_signature(&msg).unwrap();

            let (signature, _ancillary_proof_output) = clerk
                .aggregate_signatures_with_type(
                    &[signature_1, signature_2],
                    &msg,
                    AggregateSignatureType::Concatenation,
                    AncillaryProofInput::dummy(),
                )
                .unwrap();
            signature
        }

        #[test]
        fn golden_conversions() {
            let value: AggregateSignature<D> = serde_json::from_str(GOLDEN_JSON)
                .expect("This JSON deserialization should not fail");

            let serialized =
                serde_json::to_string(&value).expect("This JSON serialization should not fail");
            let golden_serialized = serde_json::to_string(&golden_value())
                .expect("This JSON serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }

        const GOLDEN_CBOR_BYTES: &[u8; 3007] = &[
            1, 162, 110, 115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 116, 121, 112, 101, 0,
            107, 112, 114, 111, 111, 102, 95, 98, 121, 116, 101, 115, 89, 11, 158, 1, 162, 111,
            115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 98, 121, 116, 101, 115, 130, 153, 2,
            218, 1, 24, 162, 24, 111, 24, 115, 24, 105, 24, 103, 24, 110, 24, 97, 24, 116, 24, 117,
            24, 114, 24, 101, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 131,
            1, 24, 24, 24, 191, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 105, 24, 24, 24, 103,
            24, 24, 24, 109, 24, 24, 24, 97, 24, 24, 24, 152, 24, 24, 24, 48, 24, 24, 24, 24, 24,
            24, 24, 149, 24, 24, 24, 24, 24, 24, 24, 157, 24, 24, 24, 24, 24, 24, 24, 201, 24, 24,
            24, 24, 24, 24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 140, 24, 24, 24, 24, 24, 24, 24,
            54, 0, 24, 24, 24, 24, 24, 24, 24, 128, 24, 24, 24, 24, 24, 24, 24, 209, 24, 24, 24,
            24, 24, 24, 24, 88, 16, 24, 24, 24, 24, 24, 24, 24, 203, 24, 24, 24, 24, 24, 24, 24,
            61, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 77, 24, 24, 24, 24, 24,
            24, 24, 98, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24, 24, 24, 133, 24, 24,
            24, 24, 24, 24, 24, 58, 24, 24, 24, 24, 24, 24, 24, 152, 24, 24, 24, 24, 24, 24, 24,
            29, 24, 24, 24, 24, 24, 24, 24, 74, 24, 24, 24, 24, 24, 24, 24, 217, 24, 24, 24, 24,
            24, 24, 24, 113, 24, 24, 24, 24, 24, 24, 24, 64, 24, 24, 24, 24, 24, 24, 24, 100, 10,
            24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24, 24, 24, 186, 24, 24, 24, 24, 24,
            24, 24, 167, 24, 24, 24, 24, 24, 24, 24, 133, 24, 24, 24, 24, 24, 24, 24, 114, 24, 24,
            24, 24, 24, 24, 24, 211, 24, 24, 24, 24, 24, 24, 24, 153, 24, 24, 24, 24, 24, 24, 24,
            218, 24, 24, 24, 24, 24, 24, 24, 56, 24, 24, 24, 24, 24, 24, 24, 223, 24, 24, 24, 24,
            24, 24, 24, 84, 24, 24, 24, 24, 24, 24, 24, 105, 24, 24, 24, 24, 24, 24, 24, 242, 24,
            24, 24, 24, 24, 24, 24, 41, 24, 24, 24, 24, 24, 24, 24, 54, 24, 24, 24, 24, 24, 24, 24,
            224, 24, 24, 24, 24, 24, 24, 24, 170, 24, 24, 24, 24, 24, 24, 24, 208, 24, 24, 24, 24,
            24, 24, 24, 185, 24, 24, 24, 24, 24, 24, 24, 126, 24, 24, 24, 24, 24, 24, 24, 83, 24,
            24, 24, 103, 24, 24, 24, 105, 24, 24, 24, 110, 24, 24, 24, 100, 24, 24, 24, 101, 24,
            24, 24, 120, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 132, 1, 4, 5, 8, 24, 24, 24,
            108, 24, 24, 24, 115, 24, 24, 24, 105, 24, 24, 24, 103, 24, 24, 24, 110, 24, 24, 24,
            101, 24, 24, 24, 114, 24, 24, 24, 95, 24, 24, 24, 105, 24, 24, 24, 110, 24, 24, 24,
            100, 24, 24, 24, 101, 24, 24, 24, 120, 0, 24, 24, 24, 255, 24, 120, 24, 24, 24, 114,
            24, 101, 24, 103, 24, 105, 24, 115, 24, 116, 24, 114, 24, 97, 24, 116, 24, 105, 24,
            111, 24, 110, 24, 95, 24, 101, 24, 110, 24, 116, 24, 114, 24, 121, 24, 95, 24, 98, 24,
            121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 219, 1, 24, 24, 24, 162, 24, 24, 24, 118,
            24, 24, 24, 118, 24, 24, 24, 101, 24, 24, 24, 114, 24, 24, 24, 105, 24, 24, 24, 102,
            24, 24, 24, 105, 24, 24, 24, 99, 24, 24, 24, 97, 24, 24, 24, 116, 24, 24, 24, 105, 24,
            24, 24, 111, 24, 24, 24, 110, 24, 24, 24, 95, 24, 24, 24, 107, 24, 24, 24, 101, 24, 24,
            24, 121, 24, 24, 24, 95, 24, 24, 24, 98, 24, 24, 24, 121, 24, 24, 24, 116, 24, 24, 24,
            101, 24, 24, 24, 115, 24, 24, 24, 152, 24, 24, 24, 96, 24, 24, 24, 24, 24, 24, 24, 143,
            24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24, 24, 24, 255, 24, 24, 24, 24, 24,
            24, 24, 48, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 57, 24, 24, 24,
            24, 24, 24, 24, 204, 24, 24, 24, 24, 24, 24, 24, 220, 24, 24, 24, 24, 24, 24, 24, 25,
            24, 24, 24, 24, 24, 24, 24, 221, 24, 24, 24, 24, 24, 24, 24, 164, 24, 24, 24, 24, 24,
            24, 24, 252, 24, 24, 24, 24, 24, 24, 24, 248, 14, 24, 24, 24, 24, 24, 24, 24, 56, 24,
            24, 24, 24, 24, 24, 24, 126, 24, 24, 24, 24, 24, 24, 24, 186, 24, 24, 24, 24, 24, 24,
            24, 135, 24, 24, 24, 24, 24, 24, 24, 228, 24, 24, 24, 24, 24, 24, 24, 188, 24, 24, 24,
            24, 24, 24, 24, 145, 24, 24, 24, 24, 24, 24, 24, 181, 24, 24, 24, 24, 24, 24, 24, 52,
            24, 24, 24, 24, 24, 24, 24, 200, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24, 24,
            24, 24, 99, 24, 24, 24, 24, 24, 24, 24, 213, 24, 24, 24, 24, 24, 24, 24, 46, 0, 24, 24,
            24, 24, 24, 24, 24, 199, 24, 24, 24, 24, 24, 24, 24, 193, 24, 24, 24, 24, 24, 24, 24,
            89, 24, 24, 24, 24, 24, 24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 88, 24, 24, 24, 24,
            24, 24, 24, 29, 24, 24, 24, 24, 24, 24, 24, 135, 24, 24, 24, 24, 24, 24, 24, 173, 24,
            24, 24, 24, 24, 24, 24, 244, 24, 24, 24, 24, 24, 24, 24, 86, 24, 24, 24, 24, 24, 24,
            24, 36, 24, 24, 24, 24, 24, 24, 24, 83, 24, 24, 24, 24, 24, 24, 24, 54, 24, 24, 24, 24,
            24, 24, 24, 67, 24, 24, 24, 24, 24, 24, 24, 164, 6, 24, 24, 24, 24, 24, 24, 24, 137,
            24, 24, 24, 24, 24, 24, 24, 94, 24, 24, 24, 24, 24, 24, 24, 72, 6, 24, 24, 24, 24, 24,
            24, 24, 105, 24, 24, 24, 24, 24, 24, 24, 128, 24, 24, 24, 24, 24, 24, 24, 128, 24, 24,
            24, 24, 24, 24, 24, 93, 24, 24, 24, 24, 24, 24, 24, 48, 24, 24, 24, 24, 24, 24, 24,
            176, 11, 4, 24, 24, 24, 24, 24, 24, 24, 246, 24, 24, 24, 24, 24, 24, 24, 138, 24, 24,
            24, 24, 24, 24, 24, 48, 24, 24, 24, 24, 24, 24, 24, 180, 24, 24, 24, 24, 24, 24, 24,
            133, 24, 24, 24, 24, 24, 24, 24, 90, 24, 24, 24, 24, 24, 24, 24, 142, 24, 24, 24, 24,
            24, 24, 24, 192, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 193, 24,
            24, 24, 24, 24, 24, 24, 111, 24, 24, 24, 24, 24, 24, 24, 142, 24, 24, 24, 24, 24, 24,
            24, 31, 24, 24, 24, 24, 24, 24, 24, 76, 24, 24, 24, 24, 24, 24, 24, 111, 24, 24, 24,
            24, 24, 24, 24, 110, 24, 24, 24, 24, 24, 24, 24, 234, 24, 24, 24, 24, 24, 24, 24, 153,
            24, 24, 24, 24, 24, 24, 24, 90, 24, 24, 24, 24, 24, 24, 24, 208, 24, 24, 24, 24, 24,
            24, 24, 192, 24, 24, 24, 24, 24, 24, 24, 31, 24, 24, 24, 24, 24, 24, 24, 124, 24, 24,
            24, 24, 24, 24, 24, 95, 24, 24, 24, 24, 24, 24, 24, 102, 24, 24, 24, 24, 24, 24, 24,
            49, 24, 24, 24, 24, 24, 24, 24, 158, 24, 24, 24, 24, 24, 24, 24, 99, 24, 24, 24, 24,
            24, 24, 24, 52, 24, 24, 24, 24, 24, 24, 24, 220, 24, 24, 24, 24, 24, 24, 24, 165, 24,
            24, 24, 24, 24, 24, 24, 94, 24, 24, 24, 24, 24, 24, 24, 251, 24, 24, 24, 24, 24, 24,
            24, 68, 24, 24, 24, 24, 24, 24, 24, 69, 24, 24, 24, 24, 24, 24, 24, 121, 16, 24, 24,
            24, 24, 24, 24, 24, 224, 24, 24, 24, 24, 24, 24, 24, 194, 24, 24, 24, 101, 24, 24, 24,
            115, 24, 24, 24, 116, 24, 24, 24, 97, 24, 24, 24, 107, 24, 24, 24, 101, 1, 153, 2, 214,
            1, 24, 162, 24, 111, 24, 115, 24, 105, 24, 103, 24, 110, 24, 97, 24, 116, 24, 117, 24,
            114, 24, 101, 24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 128, 1,
            24, 24, 24, 191, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 105, 24, 24, 24, 103,
            24, 24, 24, 109, 24, 24, 24, 97, 24, 24, 24, 152, 24, 24, 24, 48, 24, 24, 24, 24, 24,
            24, 24, 149, 24, 24, 24, 24, 24, 24, 24, 169, 22, 24, 24, 24, 24, 24, 24, 24, 201, 24,
            24, 24, 24, 24, 24, 24, 216, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24, 24, 24,
            24, 163, 24, 24, 24, 24, 24, 24, 24, 188, 24, 24, 24, 24, 24, 24, 24, 115, 24, 24, 24,
            24, 24, 24, 24, 210, 24, 24, 24, 24, 24, 24, 24, 217, 24, 24, 24, 24, 24, 24, 24, 236,
            24, 24, 24, 24, 24, 24, 24, 233, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24, 24, 24,
            24, 24, 201, 13, 24, 24, 24, 24, 24, 24, 24, 42, 24, 24, 24, 24, 24, 24, 24, 132, 12,
            24, 24, 24, 24, 24, 24, 24, 63, 5, 24, 24, 24, 24, 24, 24, 24, 31, 24, 24, 24, 24, 24,
            24, 24, 120, 22, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 177, 24,
            24, 24, 24, 24, 24, 24, 125, 24, 24, 24, 24, 24, 24, 24, 134, 24, 24, 24, 24, 24, 24,
            24, 208, 24, 24, 24, 24, 24, 24, 24, 205, 24, 24, 24, 24, 24, 24, 24, 73, 24, 24, 24,
            24, 24, 24, 24, 58, 24, 24, 24, 24, 24, 24, 24, 247, 24, 24, 24, 24, 24, 24, 24, 141,
            24, 24, 24, 24, 24, 24, 24, 59, 24, 24, 24, 24, 24, 24, 24, 62, 24, 24, 24, 24, 24, 24,
            24, 187, 24, 24, 24, 24, 24, 24, 24, 81, 24, 24, 24, 24, 24, 24, 24, 213, 24, 24, 24,
            24, 24, 24, 24, 30, 24, 24, 24, 24, 24, 24, 24, 153, 24, 24, 24, 24, 24, 24, 24, 218,
            24, 24, 24, 24, 24, 24, 24, 41, 24, 24, 24, 24, 24, 24, 24, 42, 24, 24, 24, 24, 24, 24,
            24, 110, 24, 24, 24, 24, 24, 24, 24, 156, 24, 24, 24, 24, 24, 24, 24, 161, 24, 24, 24,
            24, 24, 24, 24, 205, 24, 24, 24, 103, 24, 24, 24, 105, 24, 24, 24, 110, 24, 24, 24,
            100, 24, 24, 24, 101, 24, 24, 24, 120, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24,
            131, 0, 3, 6, 24, 24, 24, 108, 24, 24, 24, 115, 24, 24, 24, 105, 24, 24, 24, 103, 24,
            24, 24, 110, 24, 24, 24, 101, 24, 24, 24, 114, 24, 24, 24, 95, 24, 24, 24, 105, 24, 24,
            24, 110, 24, 24, 24, 100, 24, 24, 24, 101, 24, 24, 24, 120, 1, 24, 24, 24, 255, 24,
            120, 24, 24, 24, 114, 24, 101, 24, 103, 24, 105, 24, 115, 24, 116, 24, 114, 24, 97, 24,
            116, 24, 105, 24, 111, 24, 110, 24, 95, 24, 101, 24, 110, 24, 116, 24, 114, 24, 121,
            24, 95, 24, 98, 24, 121, 24, 116, 24, 101, 24, 115, 24, 152, 24, 220, 1, 24, 24, 24,
            162, 24, 24, 24, 118, 24, 24, 24, 118, 24, 24, 24, 101, 24, 24, 24, 114, 24, 24, 24,
            105, 24, 24, 24, 102, 24, 24, 24, 105, 24, 24, 24, 99, 24, 24, 24, 97, 24, 24, 24, 116,
            24, 24, 24, 105, 24, 24, 24, 111, 24, 24, 24, 110, 24, 24, 24, 95, 24, 24, 24, 107, 24,
            24, 24, 101, 24, 24, 24, 121, 24, 24, 24, 95, 24, 24, 24, 98, 24, 24, 24, 121, 24, 24,
            24, 116, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 152, 24, 24, 24, 96, 24, 24, 24,
            24, 24, 24, 24, 145, 24, 24, 24, 24, 24, 24, 24, 56, 24, 24, 24, 24, 24, 24, 24, 175,
            24, 24, 24, 24, 24, 24, 24, 32, 24, 24, 24, 24, 24, 24, 24, 122, 24, 24, 24, 24, 24,
            24, 24, 187, 24, 24, 24, 24, 24, 24, 24, 214, 24, 24, 24, 24, 24, 24, 24, 226, 24, 24,
            24, 24, 24, 24, 24, 251, 24, 24, 24, 24, 24, 24, 24, 148, 24, 24, 24, 24, 24, 24, 24,
            88, 9, 1, 24, 24, 24, 24, 24, 24, 24, 103, 24, 24, 24, 24, 24, 24, 24, 159, 24, 24, 24,
            24, 24, 24, 24, 146, 24, 24, 24, 24, 24, 24, 24, 80, 24, 24, 24, 24, 24, 24, 24, 166,
            24, 24, 24, 24, 24, 24, 24, 107, 24, 24, 24, 24, 24, 24, 24, 243, 24, 24, 24, 24, 24,
            24, 24, 251, 24, 24, 24, 24, 24, 24, 24, 236, 24, 24, 24, 24, 24, 24, 24, 41, 24, 24,
            24, 24, 24, 24, 24, 28, 24, 24, 24, 24, 24, 24, 24, 111, 24, 24, 24, 24, 24, 24, 24,
            128, 24, 24, 24, 24, 24, 24, 24, 207, 24, 24, 24, 24, 24, 24, 24, 164, 24, 24, 24, 24,
            24, 24, 24, 132, 24, 24, 24, 24, 24, 24, 24, 147, 24, 24, 24, 24, 24, 24, 24, 228, 24,
            24, 24, 24, 24, 24, 24, 83, 24, 24, 24, 24, 24, 24, 24, 246, 24, 24, 24, 24, 24, 24,
            24, 228, 24, 24, 24, 24, 24, 24, 24, 170, 24, 24, 24, 24, 24, 24, 24, 68, 24, 24, 24,
            24, 24, 24, 24, 89, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 60, 24,
            24, 24, 24, 24, 24, 24, 28, 24, 24, 24, 24, 24, 24, 24, 123, 24, 24, 24, 24, 24, 24,
            24, 130, 24, 24, 24, 24, 24, 24, 24, 88, 24, 24, 24, 24, 24, 24, 24, 234, 24, 24, 24,
            24, 24, 24, 24, 38, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24, 24, 24, 24, 42, 24,
            24, 24, 24, 24, 24, 24, 65, 1, 24, 24, 24, 24, 24, 24, 24, 100, 24, 24, 24, 24, 24, 24,
            24, 53, 18, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 131, 8, 24, 24,
            24, 24, 24, 24, 24, 61, 24, 24, 24, 24, 24, 24, 24, 122, 24, 24, 24, 24, 24, 24, 24,
            131, 24, 24, 24, 24, 24, 24, 24, 238, 24, 24, 24, 24, 24, 24, 24, 84, 24, 24, 24, 24,
            24, 24, 24, 233, 24, 24, 24, 24, 24, 24, 24, 223, 24, 24, 24, 24, 24, 24, 24, 154, 24,
            24, 24, 24, 24, 24, 24, 118, 24, 24, 24, 24, 24, 24, 24, 118, 24, 24, 24, 24, 24, 24,
            24, 73, 24, 24, 24, 24, 24, 24, 24, 28, 24, 24, 24, 24, 24, 24, 24, 27, 24, 24, 24, 24,
            24, 24, 24, 101, 24, 24, 24, 24, 24, 24, 24, 78, 24, 24, 24, 24, 24, 24, 24, 80, 24,
            24, 24, 24, 24, 24, 24, 233, 24, 24, 24, 24, 24, 24, 24, 123, 24, 24, 24, 24, 24, 24,
            24, 206, 24, 24, 24, 24, 24, 24, 24, 220, 24, 24, 24, 24, 24, 24, 24, 174, 24, 24, 24,
            24, 24, 24, 24, 134, 24, 24, 24, 24, 24, 24, 24, 205, 24, 24, 24, 24, 24, 24, 24, 71,
            24, 24, 24, 24, 24, 24, 24, 110, 24, 24, 24, 24, 24, 24, 24, 112, 24, 24, 24, 24, 24,
            24, 24, 180, 24, 24, 24, 24, 24, 24, 24, 97, 24, 24, 24, 24, 24, 24, 24, 98, 0, 24, 24,
            24, 24, 24, 24, 24, 113, 24, 24, 24, 24, 24, 24, 24, 69, 24, 24, 24, 24, 24, 24, 24,
            145, 24, 24, 24, 24, 24, 24, 24, 231, 24, 24, 24, 24, 24, 24, 24, 168, 24, 24, 24, 24,
            24, 24, 24, 43, 24, 24, 24, 24, 24, 24, 24, 173, 24, 24, 24, 24, 24, 24, 24, 172, 24,
            24, 24, 24, 24, 24, 24, 56, 24, 24, 24, 24, 24, 24, 24, 104, 24, 24, 24, 24, 24, 24,
            24, 208, 24, 24, 24, 101, 24, 24, 24, 115, 24, 24, 24, 116, 24, 24, 24, 97, 24, 24, 24,
            107, 24, 24, 24, 101, 1, 113, 98, 97, 116, 99, 104, 95, 112, 114, 111, 111, 102, 95,
            98, 121, 116, 101, 115, 152, 29, 1, 24, 163, 24, 102, 24, 118, 24, 97, 24, 108, 24,
            117, 24, 101, 24, 115, 24, 128, 24, 103, 24, 105, 24, 110, 24, 100, 24, 105, 24, 99,
            24, 101, 24, 115, 24, 130, 0, 1, 24, 102, 24, 104, 24, 97, 24, 115, 24, 104, 24, 101,
            24, 114, 24, 246,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = AggregateSignature::<D>::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            let re_encoded = decoded.to_bytes().expect("re-encode should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), re_encoded.as_slice());
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = golden_value()
                .to_bytes()
                .expect("AggregateSignature serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }

    #[cfg(feature = "future_snark")]
    mod aggregate_signature_golden_snark {
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::AggregateSignature;
        use crate::{
            Clerk, Initializer, KeyRegistration, MithrilMembershipDigest, Parameters,
            SingleSignature,
            proof_system::{SnarkProver, SnarkProverSetup},
        };

        type D = MithrilMembershipDigest;

        const GOLDEN_BYTES: &[u8] = &[
            1, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 0, 0, 0, 0, 5, 63, 233, 153, 153, 153, 153, 153,
            154, 4, 0, 0, 0, 16, 14, 0, 0, 0, 0, 0, 0, 151, 148, 199, 209, 50, 194, 34, 206, 155,
            114, 128, 191, 38, 204, 163, 187, 211, 118, 95, 87, 7, 21, 207, 247, 101, 178, 84, 63,
            189, 229, 105, 58, 57, 176, 118, 14, 204, 71, 148, 143, 9, 65, 219, 161, 180, 31, 116,
            255, 171, 71, 198, 72, 193, 223, 155, 182, 100, 251, 52, 4, 155, 212, 189, 37, 125, 46,
            228, 16, 98, 227, 5, 156, 182, 238, 19, 212, 13, 114, 17, 211, 139, 92, 47, 110, 51,
            179, 144, 163, 231, 188, 178, 19, 114, 73, 210, 170, 162, 197, 220, 51, 113, 76, 99,
            92, 37, 80, 93, 31, 160, 46, 102, 100, 229, 177, 210, 104, 52, 153, 185, 41, 219, 208,
            74, 11, 153, 50, 61, 95, 140, 130, 115, 148, 43, 105, 129, 119, 60, 153, 132, 134, 142,
            99, 34, 24, 163, 203, 249, 196, 252, 157, 194, 25, 230, 120, 12, 102, 66, 227, 218,
            198, 154, 198, 71, 208, 78, 31, 161, 181, 178, 101, 194, 55, 112, 189, 222, 16, 70, 68,
            116, 85, 103, 78, 202, 209, 232, 45, 198, 63, 180, 239, 10, 147, 171, 91, 113, 75, 79,
            192, 2, 140, 225, 244, 229, 162, 103, 182, 217, 253, 232, 28, 134, 84, 54, 242, 24,
            118, 48, 169, 234, 91, 100, 160, 223, 126, 97, 167, 60, 213, 148, 51, 87, 83, 16, 241,
            179, 76, 96, 12, 2, 214, 137, 235, 193, 116, 64, 122, 204, 117, 8, 34, 8, 90, 134, 55,
            195, 121, 96, 51, 183, 11, 119, 207, 190, 5, 178, 100, 155, 72, 183, 101, 252, 118, 35,
            140, 250, 115, 131, 127, 216, 99, 90, 219, 109, 137, 86, 224, 175, 149, 183, 36, 190,
            148, 243, 221, 203, 176, 216, 127, 18, 95, 95, 138, 46, 185, 67, 135, 31, 115, 226,
            191, 75, 165, 122, 16, 48, 94, 66, 164, 211, 98, 9, 61, 152, 137, 52, 111, 214, 113,
            58, 220, 82, 159, 155, 99, 200, 36, 163, 145, 50, 239, 231, 51, 130, 8, 23, 177, 245,
            175, 151, 182, 233, 194, 56, 206, 23, 211, 0, 113, 223, 72, 117, 201, 158, 123, 39,
            225, 128, 151, 103, 56, 74, 179, 132, 209, 102, 77, 66, 111, 252, 201, 244, 21, 100,
            107, 162, 222, 12, 195, 246, 87, 204, 96, 17, 92, 97, 230, 205, 137, 126, 186, 84, 44,
            225, 104, 80, 131, 220, 182, 191, 255, 190, 112, 211, 147, 136, 102, 137, 201, 216,
            154, 197, 17, 36, 8, 6, 129, 149, 166, 116, 145, 193, 174, 130, 195, 94, 192, 135, 7,
            247, 154, 148, 158, 232, 151, 87, 104, 164, 216, 114, 50, 45, 162, 213, 103, 67, 172,
            14, 41, 240, 206, 92, 160, 123, 59, 170, 64, 99, 28, 105, 105, 195, 237, 42, 166, 167,
            36, 216, 128, 32, 10, 183, 17, 33, 253, 224, 145, 53, 98, 58, 167, 155, 98, 65, 11,
            157, 96, 31, 132, 232, 60, 181, 142, 202, 146, 18, 78, 28, 189, 56, 44, 234, 166, 192,
            39, 88, 114, 83, 137, 68, 20, 206, 151, 53, 21, 79, 86, 29, 244, 146, 211, 64, 210, 93,
            252, 0, 144, 62, 100, 204, 44, 136, 126, 215, 172, 90, 79, 83, 186, 97, 218, 159, 255,
            29, 86, 8, 0, 232, 88, 160, 102, 32, 190, 194, 60, 151, 191, 1, 234, 228, 11, 78, 250,
            158, 19, 114, 100, 169, 2, 83, 158, 11, 21, 213, 101, 160, 88, 39, 93, 113, 105, 208,
            134, 247, 235, 116, 76, 210, 165, 76, 45, 165, 154, 222, 231, 179, 157, 184, 233, 134,
            208, 62, 64, 163, 62, 72, 187, 103, 255, 62, 109, 86, 227, 214, 192, 139, 158, 2, 28,
            30, 202, 91, 53, 176, 71, 185, 100, 205, 45, 158, 135, 241, 161, 199, 232, 31, 203,
            173, 178, 182, 143, 38, 152, 140, 203, 254, 100, 195, 36, 4, 170, 171, 215, 81, 160,
            246, 202, 183, 157, 159, 231, 48, 100, 183, 98, 234, 235, 30, 84, 72, 49, 111, 135,
            128, 165, 95, 110, 26, 218, 30, 247, 212, 251, 16, 131, 183, 170, 234, 227, 12, 47,
            224, 198, 25, 101, 225, 91, 28, 101, 175, 93, 164, 53, 89, 113, 162, 54, 32, 142, 181,
            211, 148, 248, 143, 17, 92, 202, 74, 106, 5, 64, 187, 1, 244, 249, 154, 149, 253, 194,
            249, 155, 232, 219, 165, 48, 61, 44, 52, 165, 86, 170, 166, 150, 85, 193, 2, 67, 103,
            201, 232, 237, 148, 139, 112, 108, 164, 159, 103, 220, 128, 24, 73, 254, 72, 247, 63,
            51, 229, 251, 85, 51, 155, 254, 122, 47, 10, 227, 156, 205, 118, 156, 179, 62, 117, 42,
            121, 241, 135, 83, 107, 209, 198, 47, 172, 112, 156, 176, 229, 251, 10, 102, 210, 244,
            29, 141, 100, 88, 161, 39, 210, 146, 228, 129, 226, 38, 33, 72, 245, 217, 64, 231, 159,
            17, 104, 114, 127, 22, 98, 130, 170, 139, 57, 94, 212, 58, 211, 236, 167, 136, 139, 71,
            107, 112, 141, 19, 160, 147, 68, 14, 7, 180, 173, 1, 124, 12, 163, 59, 14, 221, 29,
            119, 7, 117, 45, 230, 62, 116, 12, 81, 152, 32, 144, 64, 54, 200, 177, 53, 181, 215,
            246, 251, 113, 52, 246, 242, 217, 190, 68, 71, 120, 215, 69, 145, 129, 252, 180, 236,
            188, 248, 141, 139, 186, 206, 185, 201, 218, 63, 147, 153, 55, 2, 78, 51, 216, 47, 223,
            148, 254, 127, 63, 255, 180, 66, 189, 189, 131, 239, 16, 17, 247, 221, 177, 107, 213,
            102, 73, 118, 21, 191, 254, 249, 159, 38, 247, 107, 41, 175, 234, 35, 117, 47, 134,
            219, 109, 199, 24, 89, 46, 167, 185, 183, 238, 185, 240, 102, 41, 215, 223, 247, 180,
            44, 17, 84, 207, 240, 89, 229, 194, 105, 196, 202, 231, 34, 159, 80, 240, 113, 210,
            174, 41, 217, 111, 69, 21, 245, 15, 71, 199, 181, 182, 224, 32, 40, 168, 254, 39, 128,
            114, 117, 121, 234, 49, 167, 73, 240, 240, 207, 225, 84, 249, 124, 54, 4, 22, 242, 74,
            163, 186, 50, 160, 136, 233, 103, 243, 34, 198, 222, 5, 232, 164, 73, 176, 97, 7, 17,
            112, 111, 174, 101, 97, 63, 252, 240, 250, 233, 248, 62, 177, 69, 236, 53, 115, 249,
            57, 176, 100, 245, 59, 102, 119, 153, 154, 142, 102, 210, 251, 46, 133, 244, 188, 63,
            202, 156, 226, 197, 12, 218, 235, 80, 177, 141, 193, 214, 111, 212, 183, 10, 56, 223,
            85, 2, 161, 61, 46, 221, 87, 8, 15, 222, 211, 77, 75, 6, 19, 113, 177, 34, 105, 31,
            115, 12, 5, 12, 59, 83, 87, 138, 227, 81, 98, 77, 56, 152, 30, 136, 25, 54, 27, 127,
            235, 149, 61, 224, 165, 36, 235, 176, 218, 161, 68, 220, 93, 240, 153, 192, 193, 211,
            29, 210, 204, 143, 121, 154, 165, 205, 21, 50, 63, 161, 37, 233, 38, 229, 151, 101, 77,
            225, 43, 57, 145, 211, 255, 50, 42, 248, 185, 202, 247, 41, 190, 215, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 193, 155,
            213, 148, 253, 240, 179, 94, 105, 219, 35, 107, 237, 208, 126, 202, 79, 153, 213, 27,
            81, 149, 154, 93, 238, 15, 66, 3, 164, 53, 102, 78, 216, 251, 76, 190, 85, 72, 6, 221,
            21, 87, 252, 205, 73, 238, 90, 55, 42, 64, 188, 216, 254, 23, 201, 64, 230, 22, 72,
            149, 203, 220, 219, 24, 204, 134, 156, 102, 130, 117, 79, 78, 179, 121, 1, 36, 28, 220,
            139, 205, 215, 213, 139, 239, 78, 8, 128, 100, 34, 249, 164, 174, 118, 47, 75, 115, 85,
            208, 210, 146, 185, 107, 68, 226, 121, 100, 195, 66, 19, 248, 232, 40, 226, 84, 70,
            219, 121, 118, 239, 83, 136, 223, 128, 37, 91, 65, 218, 111, 27, 118, 141, 121, 134,
            49, 81, 46, 189, 119, 74, 93, 40, 200, 139, 132, 109, 89, 55, 202, 58, 169, 55, 147,
            126, 96, 215, 153, 33, 185, 220, 85, 80, 34, 164, 122, 132, 4, 8, 2, 47, 94, 88, 225,
            0, 206, 212, 214, 142, 171, 198, 71, 30, 10, 88, 145, 140, 165, 102, 130, 84, 98, 28,
            35, 36, 68, 164, 34, 148, 219, 56, 73, 61, 194, 13, 151, 124, 172, 210, 189, 190, 73,
            32, 138, 204, 245, 72, 203, 195, 174, 217, 186, 238, 97, 79, 103, 119, 92, 170, 43,
            229, 43, 165, 223, 52, 119, 44, 182, 249, 76, 153, 33, 82, 224, 175, 118, 151, 14, 70,
            198, 8, 105, 14, 140, 52, 76, 56, 107, 110, 164, 13, 112, 68, 47, 246, 49, 44, 117,
            162, 184, 180, 202, 155, 218, 182, 116, 139, 109, 67, 151, 108, 123, 124, 180, 30, 203,
            163, 102, 203, 101, 59, 186, 11, 197, 67, 92, 214, 98, 201, 21, 171, 208, 181, 212,
            245, 93, 75, 245, 243, 244, 43, 160, 37, 85, 226, 68, 27, 87, 136, 252, 87, 99, 234,
            26, 238, 42, 194, 122, 18, 221, 50, 189, 242, 219, 6, 237, 186, 1, 188, 217, 168, 129,
            46, 22, 11, 61, 153, 25, 86, 241, 86, 169, 1, 15, 189, 24, 122, 181, 26, 247, 226, 1,
            207, 235, 165, 109, 150, 249, 205, 109, 162, 141, 63, 152, 160, 212, 23, 42, 240, 139,
            83, 5, 166, 114, 140, 39, 29, 4, 157, 161, 183, 195, 118, 80, 26, 109, 105, 233, 224,
            112, 226, 103, 196, 193, 115, 237, 157, 239, 31, 244, 196, 199, 43, 152, 86, 95, 129,
            9, 178, 245, 229, 9, 65, 221, 187, 81, 64, 64, 184, 82, 163, 87, 190, 167, 63, 39, 174,
            216, 56, 206, 173, 158, 77, 25, 245, 186, 23, 168, 22, 108, 48, 238, 160, 164, 224,
            218, 95, 118, 211, 150, 163, 148, 126, 240, 254, 46, 216, 38, 115, 137, 44, 91, 195,
            229, 228, 15, 133, 13, 52, 70, 62, 31, 133, 218, 226, 249, 243, 222, 84, 61, 63, 112,
            199, 171, 162, 94, 5, 212, 128, 190, 154, 125, 49, 219, 57, 162, 234, 141, 120, 139,
            145, 241, 158, 34, 7, 110, 90, 153, 97, 159, 164, 99, 41, 187, 111, 73, 16, 31, 252,
            241, 26, 114, 79, 176, 35, 3, 97, 133, 250, 15, 117, 180, 194, 17, 10, 93, 183, 137,
            72, 203, 188, 4, 41, 212, 89, 58, 206, 140, 195, 48, 186, 30, 121, 111, 247, 42, 170,
            178, 53, 70, 166, 8, 129, 4, 174, 162, 3, 19, 125, 223, 93, 124, 123, 29, 219, 55, 197,
            120, 156, 118, 185, 185, 101, 62, 163, 121, 135, 228, 61, 201, 176, 74, 43, 102, 247,
            167, 206, 76, 235, 35, 254, 162, 194, 170, 6, 214, 233, 52, 209, 137, 98, 230, 144,
            129, 213, 86, 130, 200, 39, 15, 121, 65, 144, 211, 0, 101, 212, 1, 2, 253, 132, 31,
            146, 245, 34, 133, 79, 194, 139, 194, 78, 13, 57, 202, 135, 94, 83, 172, 124, 78, 112,
            42, 49, 225, 161, 124, 208, 99, 251, 200, 163, 76, 173, 75, 18, 232, 128, 6, 249, 13,
            27, 232, 247, 174, 59, 249, 20, 201, 123, 217, 51, 198, 68, 124, 6, 175, 236, 134, 21,
            104, 251, 47, 188, 255, 183, 44, 146, 13, 27, 89, 190, 149, 192, 58, 33, 108, 85, 187,
            242, 225, 241, 104, 53, 28, 95, 125, 18, 176, 127, 189, 181, 233, 152, 182, 247, 255,
            213, 80, 204, 212, 197, 44, 196, 195, 29, 177, 0, 181, 173, 60, 223, 6, 195, 131, 31,
            154, 147, 246, 27, 69, 238, 110, 221, 156, 169, 240, 243, 157, 147, 67, 173, 195, 208,
            95, 104, 14, 185, 40, 168, 145, 127, 108, 55, 184, 252, 193, 47, 7, 119, 6, 213, 185,
            232, 252, 26, 209, 211, 168, 98, 71, 174, 1, 125, 91, 10, 67, 226, 115, 42, 8, 125, 58,
            96, 31, 99, 165, 208, 126, 204, 166, 134, 71, 160, 142, 182, 197, 142, 205, 61, 201,
            183, 2, 147, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 197, 186, 121, 65, 217, 105, 78, 200, 236, 79, 119, 233, 43,
            239, 188, 176, 37, 44, 59, 68, 77, 45, 141, 106, 105, 208, 202, 113, 153, 106, 169, 1,
            31, 48, 79, 113, 156, 119, 23, 135, 209, 162, 37, 12, 38, 83, 103, 26, 206, 65, 23,
            152, 249, 165, 44, 49, 219, 127, 109, 20, 92, 72, 240, 80, 183, 80, 252, 112, 247, 246,
            150, 230, 103, 148, 223, 190, 215, 211, 53, 15, 235, 242, 119, 93, 125, 33, 255, 123,
            160, 170, 176, 100, 2, 209, 76, 69, 26, 234, 96, 92, 96, 205, 255, 75, 136, 194, 81,
            93, 50, 166, 157, 124, 79, 37, 35, 54, 58, 100, 252, 149, 213, 156, 55, 36, 216, 199,
            86, 83, 19, 192, 3, 187, 66, 169, 2, 239, 117, 172, 156, 214, 149, 61, 200, 188, 122,
            229, 185, 105, 187, 3, 211, 122, 15, 211, 82, 159, 28, 227, 66, 48, 132, 67, 109, 44,
            140, 34, 30, 207, 106, 248, 157, 7, 85, 168, 93, 97, 103, 145, 1, 103, 96, 106, 124,
            32, 214, 239, 129, 94, 216, 108, 117, 78, 96, 75, 4, 29, 32, 166, 20, 98, 119, 137,
            255, 245, 74, 2, 24, 231, 147, 227, 129, 89, 202, 203, 253, 219, 41, 10, 130, 153, 178,
            76, 205, 25, 34, 177, 242, 18, 0, 41, 241, 131, 19, 231, 21, 99, 233, 107, 90, 215,
            151, 136, 57, 88, 105, 97, 230, 202, 123, 10, 219, 25, 108, 89, 100, 49, 13, 160, 59,
            49, 142, 245, 215, 121, 131, 4, 102, 72, 198, 89, 253, 23, 5, 248, 125, 170, 159, 174,
            75, 188, 139, 20, 17, 33, 81, 105, 192, 35, 61, 10, 48, 81, 21, 148, 96, 155, 206, 1,
            204, 241, 106, 248, 77, 18, 53, 82, 176, 131, 236, 171, 201, 0, 178, 22, 145, 178, 13,
            156, 15, 57, 16, 176, 200, 85, 55, 112, 10, 72, 82, 114, 145, 137, 253, 249, 4, 197,
            152, 139, 74, 231, 29, 78, 61, 177, 99, 41, 153, 235, 210, 197, 148, 107, 37, 132, 231,
            43, 72, 174, 92, 102, 97, 119, 240, 178, 204, 84, 182, 16, 169, 139, 162, 19, 6, 213,
            59, 199, 191, 32, 22, 40, 7, 163, 119, 83, 108, 71, 77, 152, 56, 28, 97, 235, 18, 164,
            194, 196, 185, 45, 40, 2, 138, 184, 10, 6, 197, 154, 120, 14, 34, 177, 218, 51, 62, 91,
            235, 46, 249, 50, 31, 39, 19, 114, 190, 154, 7, 138, 109, 253, 203, 34, 127, 184, 79,
            155, 176, 74, 31, 24, 225, 14, 174, 2, 99, 101, 192, 235, 65, 108, 123, 53, 102, 99,
            185, 212, 171, 215, 182, 208, 28, 113, 169, 69, 55, 122, 151, 76, 70, 123, 173, 3, 89,
            32, 137, 125, 76, 190, 20, 95, 136, 107, 167, 220, 18, 140, 128, 34, 34, 166, 13, 236,
            52, 54, 95, 225, 90, 172, 81, 95, 22, 73, 160, 96, 183, 254, 130, 156, 250, 186, 44,
            76, 154, 41, 240, 149, 89, 204, 23, 192, 167, 161, 54, 88, 162, 27, 182, 140, 163, 142,
            123, 178, 191, 179, 13, 99, 7, 77, 9, 150, 26, 205, 162, 197, 106, 29, 78, 241, 39, 26,
            171, 50, 205, 6, 69, 169, 148, 166, 81, 25, 94, 208, 13, 188, 2, 176, 120, 64, 230, 59,
            47, 50, 37, 46, 98, 161, 138, 34, 74, 12, 218, 145, 127, 46, 88, 63, 40, 225, 115, 113,
            129, 131, 88, 197, 84, 104, 199, 87, 211, 195, 40, 241, 100, 73, 60, 221, 3, 220, 82,
            40, 5, 211, 193, 68, 74, 213, 138, 130, 187, 23, 88, 69, 98, 64, 233, 217, 177, 105,
            18, 190, 187, 109, 7, 44, 202, 95, 100, 212, 9, 221, 66, 75, 209, 148, 199, 76, 75,
            109, 255, 7, 206, 33, 61, 229, 10, 198, 194, 192, 135, 14, 251, 7, 90, 18, 250, 119,
            159, 220, 201, 113, 25, 122, 74, 38, 134, 223, 239, 174, 105, 55, 131, 90, 199, 65, 38,
            50, 135, 162, 132, 112, 61, 236, 104, 114, 246, 201, 128, 98, 145, 144, 253, 182, 135,
            26, 44, 61, 59, 215, 104, 230, 49, 185, 250, 102, 21, 139, 116, 216, 197, 22, 138, 172,
            235, 193, 171, 246, 51, 65, 22, 47, 198, 243, 166, 198, 108, 151, 48, 4, 207, 177, 180,
            181, 33, 165, 103, 134, 21, 40, 68, 209, 51, 172, 201, 72, 99, 38, 231, 83, 48, 78,
            182, 126, 228, 36, 92, 218, 198, 240, 219, 30, 208, 84, 83, 215, 41, 249, 233, 205, 0,
            90, 203, 49, 251, 1, 244, 33, 75, 216, 0, 250, 71, 27, 17, 153, 107, 110, 218, 141,
            190, 192, 178, 98, 171, 60, 162, 39, 13, 76, 98, 56, 195, 157, 180, 13, 205, 109, 226,
            35, 206, 208, 76, 148, 50, 70, 249, 104, 71, 104, 139, 145, 6, 98, 21, 39, 44, 166,
            207, 229, 245, 126, 237, 243, 236, 5, 42, 235, 144, 233, 120, 194, 108, 53, 185, 80,
            184, 255, 144, 166, 158, 194, 141, 78, 142, 241, 10, 63, 179, 47, 251, 116, 230, 53,
            224, 231, 75, 135, 48, 82, 113, 189, 230, 38, 136, 95, 164, 74, 14, 105, 168, 220, 149,
            124, 95, 32, 5, 194, 244, 81, 254, 66, 84, 101, 60, 208, 203, 137, 157, 132, 72, 246,
            67, 210, 214, 198, 152, 225, 224, 177, 239, 115, 158, 170, 20, 44, 87, 243, 23, 84, 27,
            106, 99, 182, 57, 60, 43, 111, 124, 145, 136, 64, 237, 137, 107, 187, 67, 85, 88, 1,
            120, 79, 193, 248, 74, 180, 246, 215, 216, 15, 23, 251, 229, 103, 18, 154, 119, 85,
            225, 188, 145, 222, 99, 232, 59, 70, 119, 7, 235, 218, 164, 222, 24, 242, 142, 227,
            233, 48, 25, 208, 240, 115, 215, 76, 166, 91, 25, 155, 174, 155, 224, 78, 166, 179,
            123, 102, 160, 22, 186, 128, 14, 6, 172, 251, 98, 161, 105, 69, 248, 69, 85, 240, 58,
            150, 75, 196, 111, 74, 155, 25, 150, 221, 205, 35, 26, 142, 181, 133, 34, 250, 200, 17,
            233, 53, 51, 161, 247, 122, 243, 234, 50, 127, 88, 64, 107, 192, 187, 53, 174, 5, 32,
            199, 78, 53, 81, 126, 39, 208, 74, 74, 137, 130, 184, 6, 137, 144, 168, 48, 78, 33,
            149, 140, 243, 230, 140, 134, 227, 60, 0, 61, 47, 83, 89, 16, 219, 51, 90, 39, 240, 25,
            111, 82, 65, 167, 238, 22, 127, 108, 124, 152, 228, 171, 54, 84, 15, 165, 142, 87, 154,
            180, 33, 171, 23, 31, 169, 182, 41, 233, 65, 138, 245, 182, 62, 197, 98, 170, 245, 124,
            80, 228, 98, 52, 216, 154, 97, 97, 169, 91, 162, 148, 82, 177, 125, 103, 31, 84, 84,
            250, 232, 92, 69, 62, 45, 35, 139, 146, 139, 81, 27, 219, 206, 42, 128, 50, 126, 178,
            230, 194, 115, 244, 96, 70, 244, 64, 92, 183, 140, 102, 226, 97, 30, 169, 210, 25, 32,
            94, 243, 3, 187, 57, 220, 214, 119, 59, 128, 107, 101, 159, 65, 101, 44, 1, 92, 163,
            218, 42, 29, 39, 51, 14, 124, 216, 91, 55, 60, 62, 162, 12, 161, 234, 153, 69, 204,
            199, 176, 97, 235, 234, 210, 167, 178, 204, 138, 57, 60, 176, 110, 200, 245, 80, 10,
            22, 80, 94, 64, 240, 16, 7, 194, 93, 18, 2, 250, 254, 101, 185, 123, 131, 13, 10, 156,
            70, 40, 143, 87, 216, 65, 232, 66, 17, 139, 45, 109, 111, 170, 217, 78, 229, 12, 161,
            253, 232, 185, 185, 119, 254, 132, 149, 184, 177, 102, 209, 207, 21, 241, 244, 143, 54,
            175, 40, 85, 209, 230, 55, 2, 177, 204, 74, 219, 10, 97, 240, 50, 55, 194, 101, 102,
            238, 1, 254, 195, 170, 82, 254, 192, 115, 54, 187, 84, 224, 47, 218, 189, 101, 96, 136,
            150, 129, 57, 20, 14, 85, 199, 238, 250, 247, 7, 137, 30, 241, 242, 249, 233, 60, 31,
            146, 74, 0, 20, 89, 231, 151, 67, 66, 236, 182, 17, 46, 232, 2, 113, 31, 208, 203, 108,
            39, 12, 215, 227, 133, 216, 5, 229, 136, 165, 93, 221, 67, 182, 188, 254, 72, 86, 105,
            195, 76, 45, 23, 195, 43, 6, 26, 64, 164, 41, 196, 211, 97, 76, 83, 244, 197, 143, 208,
            223, 252, 191, 19, 249, 223, 188, 117, 242, 64, 5, 88, 153, 213, 189, 252, 122, 226,
            58, 186, 172, 197, 175, 133, 107, 39, 220, 7, 35, 149, 225, 137, 229, 28, 87, 86, 180,
            233, 176, 109, 66, 47, 128, 70, 231, 70, 166, 149, 217, 217, 125, 80, 159, 50, 138,
            175, 125, 9, 150, 148, 121, 28, 84, 204, 49, 110, 129, 128, 146, 90, 239, 68, 74, 117,
            79, 254, 155, 196, 63, 144, 110, 116, 128, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 2, 8, 2, 0, 0, 0, 3, 14, 22, 0, 0, 0, 25, 174, 47, 83, 192, 214, 13, 208, 45, 3,
            207, 117, 105, 130, 76, 32, 221, 2, 158, 125, 34, 25, 19, 164, 43, 56, 191, 149, 129,
            103, 33, 235, 140, 98, 81, 29, 229, 57, 226, 120, 143, 239, 229, 134, 2, 79, 21, 210,
            15, 49, 97, 119, 151, 113, 64, 59, 182, 27, 25, 214, 74, 213, 191, 123, 110, 34, 210,
            45, 249, 222, 168, 122, 133, 34, 29, 169, 35, 109, 54, 80, 19, 175, 241, 108, 243, 54,
            115, 160, 14, 155, 77, 0, 137, 128, 51, 80, 17, 217, 217, 152, 96, 174, 142, 158, 156,
            31, 249, 231, 183, 17, 204, 238, 40, 2, 241, 178, 98, 92, 49, 13, 157, 18, 94, 20, 158,
            14, 171, 251, 139, 28, 180, 197, 150, 213, 103, 89, 215, 95, 26, 65, 223, 150, 49, 47,
            24, 30, 83, 158, 82, 99, 81, 53, 74, 27, 124, 83, 226, 16, 157, 226, 103, 68, 43, 161,
            230, 65, 129, 78, 170, 87, 14, 91, 70, 137, 93, 255, 18, 52, 43, 248, 156, 240, 231,
            227, 255, 224, 73, 25, 21, 160, 42, 215, 21, 60, 64, 56, 96, 212, 126, 52, 99, 215,
            190, 60, 75, 151, 2, 120, 133, 11, 79, 246, 35, 46, 180, 254, 171, 242, 37, 138, 97,
            251, 156, 201, 86, 255, 32, 243, 239, 192, 250, 181, 177, 232, 213, 50, 15, 93, 165,
            204, 8, 97, 216, 150, 51, 106, 75, 24, 149, 219, 228, 139, 236, 159, 55, 78, 82, 28,
            57, 66, 15, 112, 228, 204, 117, 131, 70, 5, 195, 17, 137, 95, 8, 85, 188, 56, 128, 207,
            33, 254, 9, 169, 220, 183, 65, 31, 45, 253, 17, 104, 107, 38, 61, 137, 23, 84, 231,
            129, 180, 35, 12, 11, 117, 98, 15, 69, 239, 101, 68, 122, 6, 139, 2, 157, 162, 3, 177,
            23, 189, 79, 245, 57, 7, 122, 60, 8, 5, 102, 147, 76, 177, 61, 78, 53, 52, 115, 8, 69,
            40, 112, 134, 94, 200, 93, 85, 134, 222, 47, 248, 5, 141, 149, 109, 241, 110, 214, 207,
            78, 254, 11, 125, 156, 61, 130, 203, 94, 254, 239, 4, 19, 206, 182, 162, 221, 250, 86,
            118, 79, 101, 219, 213, 2, 133, 8, 18, 204, 135, 83, 13, 125, 56, 143, 19, 55, 177,
            221, 96, 52, 50, 39, 159, 146, 184, 58, 7, 31, 235, 25, 195, 97, 139, 5, 115, 69, 94,
            140, 238, 252, 98, 128, 32, 165, 242, 214, 129, 101, 148, 80, 17, 113, 206, 206, 3,
            190, 164, 43, 1, 62, 29, 165, 61, 150, 154, 166, 191, 56, 204, 149, 35, 247, 99, 64,
            175, 156, 129, 178, 50, 242, 163, 46, 100, 92, 37, 30, 2, 33, 133, 143, 129, 81, 10, 9,
            217, 98, 15, 105, 70, 237, 242, 136, 10, 172, 31, 184, 23, 144, 75, 161, 109, 121, 96,
            106, 116, 236, 81, 122, 210, 18, 0, 106, 3, 148, 191, 18, 228, 221, 52, 171, 214, 37,
            199, 145, 222, 77, 69, 31, 248, 2, 67, 153, 229, 23, 132, 25, 206, 54, 6, 63, 1, 144,
            247, 178, 63, 47, 229, 15, 145, 193, 20, 111, 103, 171, 188, 199, 192, 23, 251, 196,
            161, 106, 151, 153, 16, 85, 196, 49, 217, 44, 181, 202, 122, 82, 64, 142, 63, 142, 246,
            245, 19, 115, 102, 2, 77, 76, 72, 114, 9, 194, 119, 203, 66, 6, 186, 165, 197, 150, 20,
            128, 128, 218, 2, 207, 138, 26, 161, 36, 199, 175, 203, 78, 111, 100, 50, 70, 18, 51,
            49, 149, 41, 227, 251, 26, 8, 114, 187, 110, 185, 242, 40, 49, 239, 22, 151, 41, 16,
            62, 85, 184, 218, 114, 71, 10, 173, 198, 43, 215, 183, 209, 103, 212, 15, 127, 48, 1,
            68, 70, 82, 91, 6, 100, 216, 48, 97, 208, 145, 157, 211, 63, 169, 51, 55, 139, 215, 49,
            36, 145, 246, 128, 130, 137, 136, 148, 19, 153, 71, 157, 148, 102, 235, 42, 90, 46, 92,
            58, 157, 109, 210, 119, 49, 43, 122, 9, 47, 150, 65, 123, 246, 193, 80, 37, 181, 158,
            191, 45, 118, 146, 231, 93, 62, 210, 145, 105, 246, 130, 212, 241, 53, 119, 166, 249,
            0, 191, 132, 159, 143, 98, 213, 203, 78, 135, 30, 16, 136, 48, 26, 57, 169, 230, 249,
            56, 83, 236, 20, 181, 73, 81, 93, 140, 28, 204, 244, 193, 172, 53, 213, 210, 113, 77,
            228, 17, 100, 147, 128, 47, 67, 129, 52, 133, 18, 151, 0, 99, 185, 121, 122, 176, 198,
            8, 98, 168, 184, 83, 128, 54, 1, 175, 232, 157, 58, 209, 56, 180, 162, 108, 9, 55, 194,
            117, 42, 245, 7, 47, 84, 83, 14, 235, 164, 95, 235, 146, 153, 10, 255, 242, 146, 254,
            14, 139, 42, 130, 59, 33, 223, 81, 205, 44, 139, 49, 171, 221, 64, 164, 171, 173, 37,
            127, 238, 6, 46, 174, 163, 234, 157, 252, 115, 212, 87, 72, 223, 160, 84, 224, 227,
            249, 0, 197, 236, 150, 203, 172, 89, 63, 166, 58, 20, 172, 185, 44, 50, 182, 102, 151,
            103, 232, 220, 115, 163, 117, 134, 111, 100, 173, 247, 154, 205, 190, 25, 17, 216, 164,
            162, 156, 122, 247, 175, 50, 207, 156, 145, 144, 205, 106, 178, 18, 90, 148, 64, 130,
            221, 200, 237, 116, 16, 176, 198, 39, 95, 76, 233, 49, 28, 57, 109, 160, 183, 150, 121,
            211, 183, 152, 127, 235, 115, 106, 52, 115, 224, 181, 6, 156, 187, 103, 209, 240, 90,
            235, 116, 16, 174, 20, 90, 208, 28, 50, 23, 141, 20, 40, 67, 30, 12, 105, 233, 178,
            154, 102, 11, 251, 246, 233, 122, 6, 80, 146, 19, 142, 204, 248, 218, 77, 186, 83, 92,
            86, 153, 0, 230, 136, 215, 16, 158, 3, 255, 189, 194, 51, 237, 106, 110, 78, 153, 190,
            155, 59, 222, 84, 96, 133, 14, 229, 127, 109, 161, 239, 169, 132, 4, 142, 58, 120, 222,
            117, 217, 207, 131, 231, 193, 65, 104, 10, 127, 115, 217, 233, 161, 65, 226, 61, 79,
            242, 237, 120, 90, 52, 106, 87, 78, 69, 166, 247, 175, 52, 86, 27, 115, 234, 14, 109,
            146, 152, 134, 232, 47, 213, 9, 204, 255, 228, 166, 48, 184, 58, 121, 60, 176, 196,
            228, 252, 19, 176, 241, 146, 52, 47, 235, 134, 77, 140, 162, 2, 112, 69, 4, 97, 222,
            27, 200, 69, 201, 16, 122, 5, 50, 218, 4, 176, 141, 129, 118, 91, 232, 6, 158, 224,
            133, 255, 131, 30, 166, 124, 149, 59, 34, 30, 37, 199, 148, 113, 245, 79, 244, 171, 66,
            198, 173, 71, 183, 33, 160, 145, 248, 167, 65, 80, 168, 1, 1, 72, 50, 66, 124, 3, 23,
            39, 165, 170, 248, 142, 102, 213, 142, 2, 189, 203, 31, 33, 232, 114, 205, 127, 166,
            165, 222, 250, 16, 74, 219, 124, 13, 103, 125, 194, 169, 141, 126, 111, 97, 75, 173,
            162, 89, 163, 47, 193, 201, 89, 211, 160, 102, 143, 5, 96, 76, 28, 124, 195, 71, 58,
            192, 213, 41, 221, 49, 189, 239, 246, 60, 121, 223, 68, 254, 221, 216, 167, 25, 47,
            217, 121, 89, 213, 92, 157, 58, 174, 89, 79, 191, 185, 44, 149, 180, 206, 251, 232,
            106, 77, 154, 64, 8, 1, 46, 106, 185, 100, 45, 92, 105, 27, 40, 189, 41, 15, 31, 181,
            221, 236, 41, 125, 69, 76, 95, 97, 207, 119, 33, 69, 210, 138, 156, 147, 58, 15, 212,
            75, 89, 245, 144, 111, 99, 67, 37, 148, 8, 176, 115, 222, 11, 51, 30, 225, 237, 103,
            166, 102, 186, 38, 25, 18, 176, 183, 59, 86, 70, 125, 245, 242, 160, 51, 37, 171, 74,
            60, 112, 142, 189, 32, 17, 122, 178, 4, 77, 151, 185, 203, 152, 213, 128, 192, 138, 98,
            209, 113, 241, 86, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 202, 35, 194, 94, 221, 247, 176,
            97, 140, 65, 70, 17, 129, 29, 151, 185, 126, 238, 97, 125, 154, 126, 184, 7, 109, 231,
            195, 214, 107, 79, 118, 139, 71, 125, 106, 42, 36, 37, 255, 209, 74, 98, 96, 253, 215,
            218, 210, 8, 50, 207, 128, 121, 178, 243, 159, 248, 44, 173, 233, 184, 251, 32, 89,
            102, 6, 99, 173, 71, 93, 86, 213, 131, 114, 143, 246, 104, 124, 158, 161, 246, 35, 136,
            62, 80, 89, 13, 9, 61, 250, 49, 81, 238, 127, 149, 117, 19, 29, 117, 37, 10, 240, 18,
            44, 215, 204, 216, 80, 74, 85, 79, 0, 169, 9, 167, 60, 217, 173, 61, 89, 17, 1, 50,
            239, 215, 142, 178, 90, 19, 236, 43, 118, 153, 228, 165, 152, 146, 47, 20, 231, 180,
            49, 99, 164, 2, 212, 154, 237, 151, 35, 26, 111, 127, 102, 10, 147, 254, 193, 142, 249,
            171, 68, 155, 139, 17, 183, 2, 96, 101, 81, 187, 31, 20, 38, 203, 165, 243, 150, 59,
            139, 133, 99, 123, 37, 176, 67, 45, 149, 85, 69, 142, 106, 7, 184, 37, 1, 179, 154, 57,
            217, 21, 89, 140, 34, 116, 45, 93, 61, 80, 164, 217, 51, 101, 15, 76, 252, 58, 10, 26,
            178, 249, 90, 55, 103, 14, 228, 229, 167, 162, 72, 97, 189, 196, 26, 172, 20, 175, 148,
            157, 125, 9, 215, 119, 112, 152, 212, 225, 126, 160, 104, 66, 75, 207, 56, 22, 169,
            253, 53, 26, 199, 55, 174, 104, 226, 186, 217, 175, 190, 141, 52, 183, 115, 255, 94,
            116, 43, 57, 123, 66, 37, 193, 177, 233, 96, 95, 19, 203, 168, 1, 89, 180, 54, 18, 43,
            68, 235, 205, 30, 245, 102, 227, 249, 226, 62, 242, 25, 9, 137, 102, 89, 36, 137, 140,
            7, 8, 153, 4, 143, 32, 87, 82, 203, 45, 133, 43, 134, 121, 135, 48, 228, 207, 205, 159,
            84, 113, 191, 22, 17, 221, 20, 195, 241, 29, 11, 66, 16, 182, 178, 214, 227, 212, 144,
            225, 75, 196, 131, 112, 25, 183, 24, 70, 253, 242, 89, 30, 118, 121, 54, 190, 84, 231,
            2, 24, 239, 124, 188, 3, 144, 204, 80, 101, 220, 92, 57, 19, 254, 42, 143, 47, 246,
            237, 56, 153, 220, 100, 101, 218, 231, 101, 131, 125, 107, 58, 174, 249, 135, 169, 82,
            96, 230, 234, 104, 254, 27, 167, 242, 142, 41, 241, 176, 87, 143, 19, 130, 141, 97,
            139, 253, 147, 102, 178, 165, 24, 149, 218, 58, 96, 187, 162, 143, 192, 106, 79, 154,
            108, 100, 0, 214, 95, 171, 225, 157, 221, 186, 39, 210, 255, 208, 88, 33, 215, 113,
            105, 91, 215, 165, 196, 196, 55, 90, 164, 81, 191, 230, 56, 190, 122, 247, 236, 157,
            12, 154, 124, 197, 66, 245, 240, 30, 28, 34, 106, 115, 241, 67, 148, 122, 13, 221, 102,
            243, 232, 22, 101, 221, 101, 242, 60, 67, 42, 160, 223, 226, 50, 3, 182, 79, 243, 133,
            62, 85, 64, 127, 247, 227, 5, 177, 182, 120, 9, 14, 220, 124, 146, 153, 113, 137, 31,
            58, 218, 154, 63, 246, 58, 217, 205, 115, 109, 222, 82, 237, 89, 81, 3, 23, 105, 218,
            149, 193, 252, 111, 153, 238, 159, 57, 195, 174, 45, 60, 179, 248, 26, 120, 177, 254,
            159, 15, 4, 242, 248, 106, 199, 93, 18, 228, 248, 107, 180, 251, 108, 211, 245, 226,
            29, 112, 212, 194, 83, 55, 107, 67, 149, 197, 199, 224, 170, 134, 167, 3, 223, 145, 91,
            210, 146, 57, 136, 149, 172, 166, 34, 237, 85, 145, 86, 75, 25, 85, 251, 78, 201, 134,
            111, 135, 223, 89, 91, 114, 149, 234, 92, 47, 154, 216, 49, 157, 136, 57, 109, 8, 244,
            31, 113, 39, 127, 92, 28, 63, 130, 147, 10, 124, 119, 150, 202, 84, 159, 131, 3, 5,
            185, 167, 79, 49, 25, 43, 52, 164, 185, 147, 31, 229, 48, 202, 227, 221, 65, 30, 127,
            154, 1, 31, 221, 93, 86, 226, 35, 249, 10, 5, 28, 104, 161, 110, 182, 128, 121, 76, 5,
            61, 10, 104, 198, 25, 61, 59, 128, 57, 251, 103, 221, 204, 14, 87, 220, 183, 68, 170,
            29, 93, 47, 51, 25, 73, 254, 154, 171, 119, 47, 142, 13, 97, 169, 111, 100, 220, 121,
            117, 69, 153, 50, 126, 54, 100, 89, 48, 203, 211, 145, 177, 94, 178, 6, 116, 49, 199,
            215, 205, 24, 215, 20, 221, 189, 99, 121, 208, 217, 156, 154, 196, 206, 41, 1, 62, 218,
            187, 211, 141, 44, 30, 200, 111, 76, 207, 121, 170, 43, 93, 62, 109, 54, 214, 227, 207,
            18, 112, 249, 52, 239, 117, 73, 107, 3, 189, 148, 124, 188, 242, 3, 99, 63, 222, 221,
            168, 98, 87, 216, 199, 32, 255, 61, 118, 202, 207, 74, 53, 252, 66, 83, 125, 68, 201,
            52, 83, 203, 134, 185, 167, 46, 187, 11, 108, 15, 10, 31, 5, 190, 234, 201, 203, 249,
            208, 253, 249, 8, 233, 5, 88, 186, 70, 99, 119, 123, 0, 247, 212, 3, 102, 84, 23, 25,
            87, 75, 212, 13, 21, 102, 48, 135, 137, 197, 176, 205, 54, 131, 94, 117, 224, 88, 34,
            124, 98, 66, 128, 81, 215, 106, 242, 124, 210, 248, 172, 90, 55, 21, 204, 82, 255, 136,
            168, 189, 16, 91, 133, 211, 161, 119, 85, 179, 162, 110, 218, 48, 219, 3, 35, 80, 10,
            247, 203, 152, 108, 51, 201, 58, 170, 247, 83, 183, 28, 58, 209, 74, 12, 95, 163, 51,
            2, 61, 234, 156, 235, 3, 235, 69, 156, 126, 106, 163, 145, 71, 65, 12, 54, 166, 27,
            115, 168, 235, 193, 40, 237, 169, 203, 186, 146, 104, 167, 69, 215, 125, 219, 16, 67,
            26, 137, 90, 127, 248, 53, 55, 105, 136, 75, 183, 167, 150, 90, 144, 59, 5, 155, 41,
            184, 26, 205, 249, 219, 67, 184, 106, 175, 148, 41, 115, 7, 84, 4, 85, 85, 158, 254,
            206, 240, 180, 57, 57, 242, 150, 194, 126, 100, 224, 24, 61, 232, 109, 139, 214, 87,
            191, 18, 54, 208, 181, 157, 165, 128, 2, 18, 207, 27, 169, 11, 102, 100, 224, 112, 91,
            46, 23, 227, 48, 73, 109, 135, 149, 180, 215, 69, 158, 248, 231, 88, 237, 216, 41, 161,
            87, 187, 139, 248, 41, 59, 111, 253, 195, 253, 147, 212, 66, 23, 195, 9, 115, 118, 2,
            216, 112, 42, 248, 121, 206, 68, 212, 51, 197, 0, 18, 251, 176, 227, 109, 103, 177, 22,
            145, 211, 111, 14, 104, 78, 247, 63, 121, 121, 179, 101, 140, 251, 246, 244, 227, 33,
            248, 76, 22, 50, 16, 182, 189, 100, 144, 26, 13, 24, 236, 152, 50, 100, 106, 247, 71,
            156, 242, 75, 94, 138, 171, 32, 215, 107, 42, 80, 5, 1, 234, 158, 38, 119, 220, 13, 84,
            216, 199, 106, 25, 181, 213, 79, 75, 146, 68, 244, 155, 159, 101, 153, 153, 127, 233,
            109, 0, 108, 74, 148, 148, 250, 21, 68, 226, 100, 77, 103, 182, 101, 115, 9, 3, 28,
            212, 218, 141, 250, 50, 20, 18, 174, 1, 79, 165, 244, 210, 37, 83, 122, 172, 195, 10,
            151, 35, 57, 232, 169, 207, 187, 193, 1, 84, 105, 1, 106, 219, 3, 219, 156, 189, 192,
            69, 96, 125, 155, 221, 178, 104, 234, 4, 38, 139, 69, 64, 46, 17, 227, 0, 62, 237, 48,
            223, 25, 228, 168, 60, 159, 59, 57, 50, 140, 240, 61, 144, 112, 103, 248, 85, 228, 251,
            169, 20, 209, 161, 237, 113, 208, 27, 110, 178, 16, 198, 12, 127, 86, 135, 123, 106,
            134, 50, 58, 42, 186, 67, 130, 158, 2, 106, 8, 6, 227, 184, 249, 194, 165, 148, 132,
            168, 144, 161, 201, 80, 51, 138, 194, 189, 89, 77, 23, 19, 15, 230, 153, 131, 60, 169,
            122, 238, 191, 242, 179, 171, 252, 83, 157, 221, 253, 8, 162, 109, 65, 186, 157, 71,
            46, 61, 242, 157, 189, 157, 74, 232, 112, 27, 191, 208, 194, 162, 36, 237, 230, 192,
            213, 154, 69, 223, 87, 6, 16, 160, 207, 238, 154, 177, 109, 195, 201, 201, 173, 77,
            197, 64, 92, 66, 156, 102, 213, 189, 174, 57, 145, 74, 173, 209, 141, 189, 56, 159, 86,
            94, 15, 239, 214, 248, 44, 90, 218, 241, 60, 5, 177, 18, 50, 22, 55, 3, 119, 156, 199,
            194, 89, 56, 116, 105, 156, 242, 139, 85, 184, 77, 9, 208, 48, 63, 82, 198, 243, 65,
            14, 14, 119, 70, 197, 242, 125, 245, 193, 197, 149, 70, 73, 69, 15, 74, 145, 155, 39,
            50, 33, 48, 126, 2, 95, 1, 178, 102, 120, 226, 81, 219, 146, 227, 117, 147, 245, 89,
            59, 44, 11, 69, 217, 74, 140, 177, 133, 208, 224, 180, 69, 126, 199, 162, 160, 237, 65,
            175, 130, 137, 112, 3, 34, 43, 126, 149, 232, 182, 45, 105, 4, 217, 33, 10, 74, 104,
            75, 114, 93, 42, 163, 162, 222, 177, 68, 246, 160, 231, 58, 59, 48, 129, 188, 243, 37,
            95, 46, 107, 139, 78, 42, 29, 148, 69, 245, 107, 100, 239, 19, 18, 236, 103, 16, 192,
            210, 40, 36, 220, 169, 98, 12, 5, 47, 197, 30, 235, 182, 19, 176, 178, 8, 19, 82, 33,
            161, 7, 113, 67, 141, 72, 236, 85, 84, 251, 52, 202, 255, 144, 229, 173, 133, 68, 241,
            8, 132, 224, 122, 9, 117, 89, 193, 86, 26, 198, 210, 101, 158, 242, 14,
        ];

        #[allow(dead_code)]
        fn golden_value() -> AggregateSignature<D> {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let params = Parameters {
                m: 200,
                k: 5,
                phi_f: 0.8,
            };
            let nparties = 10;
            let message = [0u8; 32];
            let prover_seed = [0u8; 32];

            let mut key_reg = KeyRegistration::initialize();
            let mut initializers = Vec::with_capacity(nparties);
            for _ in 0..nparties {
                let init = Initializer::new(params, 1, &mut rng);
                key_reg.register_by_entry(&init.clone().try_into().unwrap()).unwrap();
                initializers.push(init);
            }
            let closed_reg = key_reg.close_registration(&params).unwrap();
            let signers = initializers
                .into_iter()
                .map(|init| init.try_create_signer::<D>(&closed_reg).unwrap())
                .collect::<Vec<_>>();

            let signatures = signers
                .iter()
                .filter_map(|signer| {
                    let concatenation_signature = signer
                        .concatenation_proof_signer
                        .create_single_signature(&message)
                        .ok()?;
                    let snark_signature =
                        signer.snark_proof_signer.as_ref().and_then(|snark_signer| {
                            snark_signer.create_single_signature(&message, &mut rng).ok()
                        });
                    Some(SingleSignature {
                        concatenation_signature,
                        signer_index: signer.signer_index,
                        snark_signature,
                    })
                })
                .collect::<Vec<_>>();

            let clerk: Clerk<D> =
                Clerk::new_clerk_from_closed_key_registration(&params, &closed_reg);
            let snark_clerk = clerk.get_snark_clerk().expect("SnarkClerk must be present");
            let merkle_tree_depth = snark_clerk
                .closed_key_registration
                .number_of_registered_parties()
                .next_power_of_two()
                .trailing_zeros();

            let setup = SnarkProverSetup::try_new(&params, merkle_tree_depth)
                .expect("SnarkProverSetup creation must succeed");
            let snark_proof = SnarkProver::try_new_deterministic(prover_seed, setup)
                .expect("SnarkProver creation must succeed")
                .aggregate_signatures::<D>(snark_clerk, &signatures, &message)
                .expect("SNARK signature aggregation must succeed");

            AggregateSignature::Snark(Box::new(snark_proof))
        }

        #[test]
        fn legacy_fixed_layout_snark_proof_is_rejected() {
            // The pre-versioned fixed-offset layout embedded the certificate verifying key inline.
            // The slimmer proof drops that key, so the fixed-offset layout is no longer decodable;
            // only versioned CBOR is supported.
            assert!(
                AggregateSignature::<D>::from_bytes(GOLDEN_BYTES).is_err(),
                "legacy fixed-offset Snark proof must be rejected"
            );
        }

        const GOLDEN_CBOR_BYTES: &[u8; 3701] = &[
            1, 162, 110, 115, 105, 103, 110, 97, 116, 117, 114, 101, 95, 116, 121, 112, 101, 1,
            107, 112, 114, 111, 111, 102, 95, 98, 121, 116, 101, 115, 89, 14, 84, 1, 163, 109, 99,
            105, 114, 99, 117, 105, 116, 95, 112, 114, 111, 111, 102, 89, 14, 16, 151, 148, 199,
            209, 50, 194, 34, 206, 155, 114, 128, 191, 38, 204, 163, 187, 211, 118, 95, 87, 7, 21,
            207, 247, 101, 178, 84, 63, 189, 229, 105, 58, 57, 176, 118, 14, 204, 71, 148, 143, 9,
            65, 219, 161, 180, 31, 116, 255, 171, 71, 198, 72, 193, 223, 155, 182, 100, 251, 52, 4,
            155, 212, 189, 37, 125, 46, 228, 16, 98, 227, 5, 156, 182, 238, 19, 212, 13, 114, 17,
            211, 139, 92, 47, 110, 51, 179, 144, 163, 231, 188, 178, 19, 114, 73, 210, 170, 162,
            197, 220, 51, 113, 76, 99, 92, 37, 80, 93, 31, 160, 46, 102, 100, 229, 177, 210, 104,
            52, 153, 185, 41, 219, 208, 74, 11, 153, 50, 61, 95, 140, 130, 115, 148, 43, 105, 129,
            119, 60, 153, 132, 134, 142, 99, 34, 24, 163, 203, 249, 196, 252, 157, 194, 25, 230,
            120, 12, 102, 66, 227, 218, 198, 154, 198, 71, 208, 78, 31, 161, 181, 178, 101, 194,
            55, 112, 189, 222, 16, 70, 68, 116, 85, 103, 78, 202, 209, 232, 45, 198, 63, 180, 239,
            10, 147, 171, 91, 113, 75, 79, 192, 2, 140, 225, 244, 229, 162, 103, 182, 217, 253,
            232, 28, 134, 84, 54, 242, 24, 118, 48, 169, 234, 91, 100, 160, 223, 126, 97, 167, 60,
            213, 148, 51, 87, 83, 16, 241, 179, 76, 96, 12, 2, 214, 137, 235, 193, 116, 64, 122,
            204, 117, 8, 34, 8, 90, 134, 55, 195, 121, 96, 51, 183, 11, 119, 207, 190, 5, 178, 100,
            155, 72, 183, 101, 252, 118, 35, 140, 250, 115, 131, 127, 216, 99, 90, 219, 109, 137,
            86, 224, 175, 149, 183, 36, 190, 148, 243, 221, 203, 176, 216, 127, 18, 95, 95, 138,
            46, 185, 67, 135, 31, 115, 226, 191, 75, 165, 122, 16, 48, 94, 66, 164, 211, 98, 9, 61,
            152, 137, 52, 111, 214, 113, 58, 220, 82, 159, 155, 99, 200, 36, 163, 145, 50, 239,
            231, 51, 130, 8, 23, 177, 245, 175, 151, 182, 233, 194, 56, 206, 23, 211, 0, 113, 223,
            72, 117, 201, 158, 123, 39, 225, 128, 151, 103, 56, 74, 179, 132, 209, 102, 77, 66,
            111, 252, 201, 244, 21, 100, 107, 162, 222, 12, 195, 246, 87, 204, 96, 17, 92, 97, 230,
            205, 137, 126, 186, 84, 44, 225, 104, 80, 131, 220, 182, 191, 255, 190, 112, 211, 147,
            136, 102, 137, 201, 216, 154, 197, 17, 36, 8, 6, 129, 149, 166, 116, 145, 193, 174,
            130, 195, 94, 192, 135, 7, 247, 154, 148, 158, 232, 151, 87, 104, 164, 216, 114, 50,
            45, 162, 213, 103, 67, 172, 14, 41, 240, 206, 92, 160, 123, 59, 170, 64, 99, 28, 105,
            105, 195, 237, 42, 166, 167, 36, 216, 128, 32, 10, 183, 17, 33, 253, 224, 145, 53, 98,
            58, 167, 155, 98, 65, 11, 157, 96, 31, 132, 232, 60, 181, 142, 202, 146, 18, 78, 28,
            189, 56, 44, 234, 166, 192, 39, 88, 114, 83, 137, 68, 20, 206, 151, 53, 21, 79, 86, 29,
            244, 146, 211, 64, 210, 93, 252, 0, 144, 62, 100, 204, 44, 136, 126, 215, 172, 90, 79,
            83, 186, 97, 218, 159, 255, 29, 86, 8, 0, 232, 88, 160, 102, 32, 190, 194, 60, 151,
            191, 1, 234, 228, 11, 78, 250, 158, 19, 114, 100, 169, 2, 83, 158, 11, 21, 213, 101,
            160, 88, 39, 93, 113, 105, 208, 134, 247, 235, 116, 76, 210, 165, 76, 45, 165, 154,
            222, 231, 179, 157, 184, 233, 134, 208, 62, 64, 163, 62, 72, 187, 103, 255, 62, 109,
            86, 227, 214, 192, 139, 158, 2, 28, 30, 202, 91, 53, 176, 71, 185, 100, 205, 45, 158,
            135, 241, 161, 199, 232, 31, 203, 173, 178, 182, 143, 38, 152, 140, 203, 254, 100, 195,
            36, 4, 170, 171, 215, 81, 160, 246, 202, 183, 157, 159, 231, 48, 100, 183, 98, 234,
            235, 30, 84, 72, 49, 111, 135, 128, 165, 95, 110, 26, 218, 30, 247, 212, 251, 16, 131,
            183, 170, 234, 227, 12, 47, 224, 198, 25, 101, 225, 91, 28, 101, 175, 93, 164, 53, 89,
            113, 162, 54, 32, 142, 181, 211, 148, 248, 143, 17, 92, 202, 74, 106, 5, 64, 187, 1,
            244, 249, 154, 149, 253, 194, 249, 155, 232, 219, 165, 48, 61, 44, 52, 165, 86, 170,
            166, 150, 85, 193, 2, 67, 103, 201, 232, 237, 148, 139, 112, 108, 164, 159, 103, 220,
            128, 24, 73, 254, 72, 247, 63, 51, 229, 251, 85, 51, 155, 254, 122, 47, 10, 227, 156,
            205, 118, 156, 179, 62, 117, 42, 121, 241, 135, 83, 107, 209, 198, 47, 172, 112, 156,
            176, 229, 251, 10, 102, 210, 244, 29, 141, 100, 88, 161, 39, 210, 146, 228, 129, 226,
            38, 33, 72, 245, 217, 64, 231, 159, 17, 104, 114, 127, 22, 98, 130, 170, 139, 57, 94,
            212, 58, 211, 236, 167, 136, 139, 71, 107, 112, 141, 19, 160, 147, 68, 14, 7, 180, 173,
            1, 124, 12, 163, 59, 14, 221, 29, 119, 7, 117, 45, 230, 62, 116, 12, 81, 152, 32, 144,
            64, 54, 200, 177, 53, 181, 215, 246, 251, 113, 52, 246, 242, 217, 190, 68, 71, 120,
            215, 69, 145, 129, 252, 180, 236, 188, 248, 141, 139, 186, 206, 185, 201, 218, 63, 147,
            153, 55, 2, 78, 51, 216, 47, 223, 148, 254, 127, 63, 255, 180, 66, 189, 189, 131, 239,
            16, 17, 247, 221, 177, 107, 213, 102, 73, 118, 21, 191, 254, 249, 159, 38, 247, 107,
            41, 175, 234, 35, 117, 47, 134, 219, 109, 199, 24, 89, 46, 167, 185, 183, 238, 185,
            240, 102, 41, 215, 223, 247, 180, 44, 17, 84, 207, 240, 89, 229, 194, 105, 196, 202,
            231, 34, 159, 80, 240, 113, 210, 174, 41, 217, 111, 69, 21, 245, 15, 71, 199, 181, 182,
            224, 32, 40, 168, 254, 39, 128, 114, 117, 121, 234, 49, 167, 73, 240, 240, 207, 225,
            84, 249, 124, 54, 4, 22, 242, 74, 163, 186, 50, 160, 136, 233, 103, 243, 34, 198, 222,
            5, 232, 164, 73, 176, 97, 7, 17, 112, 111, 174, 101, 97, 63, 252, 240, 250, 233, 248,
            62, 177, 69, 236, 53, 115, 249, 57, 176, 100, 245, 59, 102, 119, 153, 154, 142, 102,
            210, 251, 46, 133, 244, 188, 63, 202, 156, 226, 197, 12, 218, 235, 80, 177, 141, 193,
            214, 111, 212, 183, 10, 56, 223, 85, 2, 161, 61, 46, 221, 87, 8, 15, 222, 211, 77, 75,
            6, 19, 113, 177, 34, 105, 31, 115, 12, 5, 12, 59, 83, 87, 138, 227, 81, 98, 77, 56,
            152, 30, 136, 25, 54, 27, 127, 235, 149, 61, 224, 165, 36, 235, 176, 218, 161, 68, 220,
            93, 240, 153, 192, 193, 211, 29, 210, 204, 143, 121, 154, 165, 205, 21, 50, 63, 161,
            37, 233, 38, 229, 151, 101, 77, 225, 43, 57, 145, 211, 255, 50, 42, 248, 185, 202, 247,
            41, 190, 215, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 193, 155, 213, 148, 253, 240, 179, 94, 105, 219, 35, 107, 237,
            208, 126, 202, 79, 153, 213, 27, 81, 149, 154, 93, 238, 15, 66, 3, 164, 53, 102, 78,
            216, 251, 76, 190, 85, 72, 6, 221, 21, 87, 252, 205, 73, 238, 90, 55, 42, 64, 188, 216,
            254, 23, 201, 64, 230, 22, 72, 149, 203, 220, 219, 24, 204, 134, 156, 102, 130, 117,
            79, 78, 179, 121, 1, 36, 28, 220, 139, 205, 215, 213, 139, 239, 78, 8, 128, 100, 34,
            249, 164, 174, 118, 47, 75, 115, 85, 208, 210, 146, 185, 107, 68, 226, 121, 100, 195,
            66, 19, 248, 232, 40, 226, 84, 70, 219, 121, 118, 239, 83, 136, 223, 128, 37, 91, 65,
            218, 111, 27, 118, 141, 121, 134, 49, 81, 46, 189, 119, 74, 93, 40, 200, 139, 132, 109,
            89, 55, 202, 58, 169, 55, 147, 126, 96, 215, 153, 33, 185, 220, 85, 80, 34, 164, 122,
            132, 4, 8, 2, 47, 94, 88, 225, 0, 206, 212, 214, 142, 171, 198, 71, 30, 10, 88, 145,
            140, 165, 102, 130, 84, 98, 28, 35, 36, 68, 164, 34, 148, 219, 56, 73, 61, 194, 13,
            151, 124, 172, 210, 189, 190, 73, 32, 138, 204, 245, 72, 203, 195, 174, 217, 186, 238,
            97, 79, 103, 119, 92, 170, 43, 229, 43, 165, 223, 52, 119, 44, 182, 249, 76, 153, 33,
            82, 224, 175, 118, 151, 14, 70, 198, 8, 105, 14, 140, 52, 76, 56, 107, 110, 164, 13,
            112, 68, 47, 246, 49, 44, 117, 162, 184, 180, 202, 155, 218, 182, 116, 139, 109, 67,
            151, 108, 123, 124, 180, 30, 203, 163, 102, 203, 101, 59, 186, 11, 197, 67, 92, 214,
            98, 201, 21, 171, 208, 181, 212, 245, 93, 75, 245, 243, 244, 43, 160, 37, 85, 226, 68,
            27, 87, 136, 252, 87, 99, 234, 26, 238, 42, 194, 122, 18, 221, 50, 189, 242, 219, 6,
            237, 186, 1, 188, 217, 168, 129, 46, 22, 11, 61, 153, 25, 86, 241, 86, 169, 1, 15, 189,
            24, 122, 181, 26, 247, 226, 1, 207, 235, 165, 109, 150, 249, 205, 109, 162, 141, 63,
            152, 160, 212, 23, 42, 240, 139, 83, 5, 166, 114, 140, 39, 29, 4, 157, 161, 183, 195,
            118, 80, 26, 109, 105, 233, 224, 112, 226, 103, 196, 193, 115, 237, 157, 239, 31, 244,
            196, 199, 43, 152, 86, 95, 129, 9, 178, 245, 229, 9, 65, 221, 187, 81, 64, 64, 184, 82,
            163, 87, 190, 167, 63, 39, 174, 216, 56, 206, 173, 158, 77, 25, 245, 186, 23, 168, 22,
            108, 48, 238, 160, 164, 224, 218, 95, 118, 211, 150, 163, 148, 126, 240, 254, 46, 216,
            38, 115, 137, 44, 91, 195, 229, 228, 15, 133, 13, 52, 70, 62, 31, 133, 218, 226, 249,
            243, 222, 84, 61, 63, 112, 199, 171, 162, 94, 5, 212, 128, 190, 154, 125, 49, 219, 57,
            162, 234, 141, 120, 139, 145, 241, 158, 34, 7, 110, 90, 153, 97, 159, 164, 99, 41, 187,
            111, 73, 16, 31, 252, 241, 26, 114, 79, 176, 35, 3, 97, 133, 250, 15, 117, 180, 194,
            17, 10, 93, 183, 137, 72, 203, 188, 4, 41, 212, 89, 58, 206, 140, 195, 48, 186, 30,
            121, 111, 247, 42, 170, 178, 53, 70, 166, 8, 129, 4, 174, 162, 3, 19, 125, 223, 93,
            124, 123, 29, 219, 55, 197, 120, 156, 118, 185, 185, 101, 62, 163, 121, 135, 228, 61,
            201, 176, 74, 43, 102, 247, 167, 206, 76, 235, 35, 254, 162, 194, 170, 6, 214, 233, 52,
            209, 137, 98, 230, 144, 129, 213, 86, 130, 200, 39, 15, 121, 65, 144, 211, 0, 101, 212,
            1, 2, 253, 132, 31, 146, 245, 34, 133, 79, 194, 139, 194, 78, 13, 57, 202, 135, 94, 83,
            172, 124, 78, 112, 42, 49, 225, 161, 124, 208, 99, 251, 200, 163, 76, 173, 75, 18, 232,
            128, 6, 249, 13, 27, 232, 247, 174, 59, 249, 20, 201, 123, 217, 51, 198, 68, 124, 6,
            175, 236, 134, 21, 104, 251, 47, 188, 255, 183, 44, 146, 13, 27, 89, 190, 149, 192, 58,
            33, 108, 85, 187, 242, 225, 241, 104, 53, 28, 95, 125, 18, 176, 127, 189, 181, 233,
            152, 182, 247, 255, 213, 80, 204, 212, 197, 44, 196, 195, 29, 177, 0, 181, 173, 60,
            223, 6, 195, 131, 31, 154, 147, 246, 27, 69, 238, 110, 221, 156, 169, 240, 243, 157,
            147, 67, 173, 195, 208, 95, 104, 14, 185, 40, 168, 145, 127, 108, 55, 184, 252, 193,
            47, 7, 119, 6, 213, 185, 232, 252, 26, 209, 211, 168, 98, 71, 174, 1, 125, 91, 10, 67,
            226, 115, 42, 8, 125, 58, 96, 31, 99, 165, 208, 126, 204, 166, 134, 71, 160, 142, 182,
            197, 142, 205, 61, 201, 183, 2, 147, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 197, 186, 121, 65, 217, 105, 78,
            200, 236, 79, 119, 233, 43, 239, 188, 176, 37, 44, 59, 68, 77, 45, 141, 106, 105, 208,
            202, 113, 153, 106, 169, 1, 31, 48, 79, 113, 156, 119, 23, 135, 209, 162, 37, 12, 38,
            83, 103, 26, 206, 65, 23, 152, 249, 165, 44, 49, 219, 127, 109, 20, 92, 72, 240, 80,
            183, 80, 252, 112, 247, 246, 150, 230, 103, 148, 223, 190, 215, 211, 53, 15, 235, 242,
            119, 93, 125, 33, 255, 123, 160, 170, 176, 100, 2, 209, 76, 69, 26, 234, 96, 92, 96,
            205, 255, 75, 136, 194, 81, 93, 50, 166, 157, 124, 79, 37, 35, 54, 58, 100, 252, 149,
            213, 156, 55, 36, 216, 199, 86, 83, 19, 192, 3, 187, 66, 169, 2, 239, 117, 172, 156,
            214, 149, 61, 200, 188, 122, 229, 185, 105, 187, 3, 211, 122, 15, 211, 82, 159, 28,
            227, 66, 48, 132, 67, 109, 44, 140, 34, 30, 207, 106, 248, 157, 7, 85, 168, 93, 97,
            103, 145, 1, 103, 96, 106, 124, 32, 214, 239, 129, 94, 216, 108, 117, 78, 96, 75, 4,
            29, 32, 166, 20, 98, 119, 137, 255, 245, 74, 2, 24, 231, 147, 227, 129, 89, 202, 203,
            253, 219, 41, 10, 130, 153, 178, 76, 205, 25, 34, 177, 242, 18, 0, 41, 241, 131, 19,
            231, 21, 99, 233, 107, 90, 215, 151, 136, 57, 88, 105, 97, 230, 202, 123, 10, 219, 25,
            108, 89, 100, 49, 13, 160, 59, 49, 142, 245, 215, 121, 131, 4, 102, 72, 198, 89, 253,
            23, 5, 248, 125, 170, 159, 174, 75, 188, 139, 20, 17, 33, 81, 105, 192, 35, 61, 10, 48,
            81, 21, 148, 96, 155, 206, 1, 204, 241, 106, 248, 77, 18, 53, 82, 176, 131, 236, 171,
            201, 0, 178, 22, 145, 178, 13, 156, 15, 57, 16, 176, 200, 85, 55, 112, 10, 72, 82, 114,
            145, 137, 253, 249, 4, 197, 152, 139, 74, 231, 29, 78, 61, 177, 99, 41, 153, 235, 210,
            197, 148, 107, 37, 132, 231, 43, 72, 174, 92, 102, 97, 119, 240, 178, 204, 84, 182, 16,
            169, 139, 162, 19, 6, 213, 59, 199, 191, 32, 22, 40, 7, 163, 119, 83, 108, 71, 77, 152,
            56, 28, 97, 235, 18, 164, 194, 196, 185, 45, 40, 2, 138, 184, 10, 6, 197, 154, 120, 14,
            34, 177, 218, 51, 62, 91, 235, 46, 249, 50, 31, 39, 19, 114, 190, 154, 7, 138, 109,
            253, 203, 34, 127, 184, 79, 155, 176, 74, 31, 24, 225, 14, 174, 2, 99, 101, 192, 235,
            65, 108, 123, 53, 102, 99, 185, 212, 171, 215, 182, 208, 28, 113, 169, 69, 55, 122,
            151, 76, 70, 123, 173, 3, 89, 32, 137, 125, 76, 190, 20, 95, 136, 107, 167, 220, 18,
            140, 128, 34, 34, 166, 13, 236, 52, 54, 95, 225, 90, 172, 81, 95, 22, 73, 160, 96, 183,
            254, 130, 156, 250, 186, 44, 76, 154, 41, 240, 149, 89, 204, 23, 192, 167, 161, 54, 88,
            162, 27, 182, 140, 163, 142, 123, 178, 191, 179, 13, 99, 7, 77, 9, 150, 26, 205, 162,
            197, 106, 29, 78, 241, 39, 26, 171, 50, 205, 6, 69, 169, 148, 166, 81, 25, 94, 208, 13,
            188, 2, 176, 120, 64, 230, 59, 47, 50, 37, 46, 98, 161, 138, 34, 74, 12, 218, 145, 127,
            46, 88, 63, 40, 225, 115, 113, 129, 131, 88, 197, 84, 104, 199, 87, 211, 195, 40, 241,
            100, 73, 60, 221, 3, 220, 82, 40, 5, 211, 193, 68, 74, 213, 138, 130, 187, 23, 88, 69,
            98, 64, 233, 217, 177, 105, 18, 190, 187, 109, 7, 44, 202, 95, 100, 212, 9, 221, 66,
            75, 209, 148, 199, 76, 75, 109, 255, 7, 206, 33, 61, 229, 10, 198, 194, 192, 135, 14,
            251, 7, 90, 18, 250, 119, 159, 220, 201, 113, 25, 122, 74, 38, 134, 223, 239, 174, 105,
            55, 131, 90, 199, 65, 38, 50, 135, 162, 132, 112, 61, 236, 104, 114, 246, 201, 128, 98,
            145, 144, 253, 182, 135, 26, 44, 61, 59, 215, 104, 230, 49, 185, 250, 102, 21, 139,
            116, 216, 197, 22, 138, 172, 235, 193, 171, 246, 51, 65, 22, 47, 198, 243, 166, 198,
            108, 151, 48, 4, 207, 177, 180, 181, 33, 165, 103, 134, 21, 40, 68, 209, 51, 172, 201,
            72, 99, 38, 231, 83, 48, 78, 182, 126, 228, 36, 92, 218, 198, 240, 219, 30, 208, 84,
            83, 215, 41, 249, 233, 205, 0, 90, 203, 49, 251, 1, 244, 33, 75, 216, 0, 250, 71, 27,
            17, 153, 107, 110, 218, 141, 190, 192, 178, 98, 171, 60, 162, 39, 13, 76, 98, 56, 195,
            157, 180, 13, 205, 109, 226, 35, 206, 208, 76, 148, 50, 70, 249, 104, 71, 104, 139,
            145, 6, 98, 21, 39, 44, 166, 207, 229, 245, 126, 237, 243, 236, 5, 42, 235, 144, 233,
            120, 194, 108, 53, 185, 80, 184, 255, 144, 166, 158, 194, 141, 78, 142, 241, 10, 63,
            179, 47, 251, 116, 230, 53, 224, 231, 75, 135, 48, 82, 113, 189, 230, 38, 136, 95, 164,
            74, 14, 105, 168, 220, 149, 124, 95, 32, 5, 194, 244, 81, 254, 66, 84, 101, 60, 208,
            203, 137, 157, 132, 72, 246, 67, 210, 214, 198, 152, 225, 224, 177, 239, 115, 158, 170,
            20, 44, 87, 243, 23, 84, 27, 106, 99, 182, 57, 60, 43, 111, 124, 145, 136, 64, 237,
            137, 107, 187, 67, 85, 88, 1, 120, 79, 193, 248, 74, 180, 246, 215, 216, 15, 23, 251,
            229, 103, 18, 154, 119, 85, 225, 188, 145, 222, 99, 232, 59, 70, 119, 7, 235, 218, 164,
            222, 24, 242, 142, 227, 233, 48, 25, 208, 240, 115, 215, 76, 166, 91, 25, 155, 174,
            155, 224, 78, 166, 179, 123, 102, 160, 22, 186, 128, 14, 6, 172, 251, 98, 161, 105, 69,
            248, 69, 85, 240, 58, 150, 75, 196, 111, 74, 155, 25, 150, 221, 205, 35, 26, 142, 181,
            133, 34, 250, 200, 17, 233, 53, 51, 161, 247, 122, 243, 234, 50, 127, 88, 64, 107, 192,
            187, 53, 174, 5, 32, 199, 78, 53, 81, 126, 39, 208, 74, 74, 137, 130, 184, 6, 137, 144,
            168, 48, 78, 33, 149, 140, 243, 230, 140, 134, 227, 60, 0, 61, 47, 83, 89, 16, 219, 51,
            90, 39, 240, 25, 111, 82, 65, 167, 238, 22, 127, 108, 124, 152, 228, 171, 54, 84, 15,
            165, 142, 87, 154, 180, 33, 171, 23, 31, 169, 182, 41, 233, 65, 138, 245, 182, 62, 197,
            98, 170, 245, 124, 80, 228, 98, 52, 216, 154, 97, 97, 169, 91, 162, 148, 82, 177, 125,
            103, 31, 84, 84, 250, 232, 92, 69, 62, 45, 35, 139, 146, 139, 81, 27, 219, 206, 42,
            128, 50, 126, 178, 230, 194, 115, 244, 96, 70, 244, 64, 92, 183, 140, 102, 226, 97, 30,
            169, 210, 25, 32, 94, 243, 3, 187, 57, 220, 214, 119, 59, 128, 107, 101, 159, 65, 101,
            44, 1, 92, 163, 218, 42, 29, 39, 51, 14, 124, 216, 91, 55, 60, 62, 162, 12, 161, 234,
            153, 69, 204, 199, 176, 97, 235, 234, 210, 167, 178, 204, 138, 57, 60, 176, 110, 200,
            245, 80, 10, 22, 80, 94, 64, 240, 16, 7, 194, 93, 18, 2, 250, 254, 101, 185, 123, 131,
            13, 10, 156, 70, 40, 143, 87, 216, 65, 232, 66, 17, 139, 45, 109, 111, 170, 217, 78,
            229, 12, 161, 253, 232, 185, 185, 119, 254, 132, 149, 184, 177, 102, 209, 207, 21, 241,
            244, 143, 54, 175, 40, 85, 209, 230, 55, 2, 177, 204, 74, 219, 10, 97, 240, 50, 55,
            194, 101, 102, 238, 1, 254, 195, 170, 82, 254, 192, 115, 54, 187, 84, 224, 47, 218,
            189, 101, 96, 136, 150, 129, 57, 20, 14, 85, 199, 238, 250, 247, 7, 137, 30, 241, 242,
            249, 233, 60, 31, 146, 74, 0, 20, 89, 231, 151, 67, 66, 236, 182, 17, 46, 232, 2, 113,
            31, 208, 203, 108, 39, 12, 215, 227, 133, 216, 5, 229, 136, 165, 93, 221, 67, 182, 188,
            254, 72, 86, 105, 195, 76, 45, 23, 195, 43, 6, 26, 64, 164, 41, 196, 211, 97, 76, 83,
            244, 197, 143, 208, 223, 252, 191, 19, 249, 223, 188, 117, 242, 64, 5, 88, 153, 213,
            189, 252, 122, 226, 58, 186, 172, 197, 175, 133, 107, 39, 220, 7, 35, 149, 225, 137,
            229, 28, 87, 86, 180, 233, 176, 109, 66, 47, 128, 70, 231, 70, 166, 149, 217, 217, 125,
            80, 159, 50, 138, 175, 125, 9, 150, 148, 121, 28, 84, 204, 49, 110, 129, 128, 146, 90,
            239, 68, 74, 117, 79, 254, 155, 196, 63, 144, 110, 116, 128, 0, 102, 112, 97, 114, 97,
            109, 115, 163, 97, 109, 24, 200, 97, 107, 5, 101, 112, 104, 105, 95, 102, 251, 63, 233,
            153, 153, 153, 153, 153, 154, 113, 109, 101, 114, 107, 108, 101, 95, 116, 114, 101,
            101, 95, 100, 101, 112, 116, 104, 4,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = AggregateSignature::<D>::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            let re_encoded = decoded.to_bytes().expect("re-encode should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), re_encoded.as_slice());
        }
    }
}
