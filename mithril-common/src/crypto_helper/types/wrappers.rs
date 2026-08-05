use kes_summed_ed25519::kes::Sum6KesSig;
use mithril_stm::{
    AggregateSignature, AggregateSignatureType, AggregateVerificationKey,
    AggregateVerificationKeyForConcatenation, AncillaryProverData, AncillaryVerifierData,
    SingleSignature, VerificationKeyProofOfPossessionForConcatenation,
};
#[cfg(feature = "future_snark")]
use mithril_stm::{AggregateVerificationKeyForSnark, VerificationKeyForSnark};

use crate::StdResult;
use crate::crypto_helper::{
    MKMapProof, MKProof, OpCert, ProtocolKey, ProtocolKeyCodec, ProtocolMembershipDigest,
};
use crate::entities::BlockRange;

/// Wrapper of [MithrilStm:VerificationKeyProofOfPossessionForConcatenation](type@VerificationKeyProofOfPossessionForConcatenation) to add serialization
/// utilities.
pub type ProtocolSignerVerificationKeyForConcatenation =
    ProtocolKey<VerificationKeyProofOfPossessionForConcatenation>;

/// Wrapper of [KES:Sum6KesSig](https://github.com/input-output-hk/kes/blob/master/src/kes.rs) to add
/// serialization utilities.
pub type ProtocolSignerVerificationKeySignatureForConcatenation = ProtocolKey<Sum6KesSig>;

/// Wrapper of [MithrilStm:VerificationKeyForSnark](type@VerificationKeyForSnark) to add serialization
/// utilities.
#[cfg(feature = "future_snark")]
pub type ProtocolSignerVerificationKeyForSnark = ProtocolKey<VerificationKeyForSnark>;

/// Wrapper of [KES:Sum6KesSig](https://github.com/input-output-hk/kes/blob/master/src/kes.rs) to add
/// serialization utilities.
#[cfg(feature = "future_snark")]
pub type ProtocolSignerVerificationKeySignatureForSnark = ProtocolKey<Sum6KesSig>;

/// Wrapper of [MithrilStm:SingleSignature](type@SingleSignature) to add serialization utilities.
pub type ProtocolSingleSignature = ProtocolKey<SingleSignature>;

/// Wrapper of [MithrilStm:AggregateSignature](enum@AggregateSignature) to add serialization utilities.
pub type ProtocolMultiSignature = ProtocolKey<AggregateSignature<ProtocolMembershipDigest>>;

/// Wrapper of [OpCert] to add serialization utilities.
pub type ProtocolOpCert = ProtocolKey<OpCert>;

/// Wrapper of [MithrilStm:AggregateVerificationKey](struct@AggregateVerificationKey).
pub type ProtocolAggregateVerificationKey = AggregateVerificationKey<ProtocolMembershipDigest>;

/// Wrapper of [MithrilStm:AggregateVerificationKeyForConcatenation](struct@AggregateVerificationKeyForConcatenation).
pub type ProtocolAggregateVerificationKeyForConcatenation =
    ProtocolKey<AggregateVerificationKeyForConcatenation<ProtocolMembershipDigest>>;

/// Wrapper of [MithrilStm:AggregateVerificationKeyForSnark](struct@AggregateVerificationKeyForSnark).
#[cfg(feature = "future_snark")]
pub type ProtocolAggregateVerificationKeyForSnark =
    ProtocolKey<AggregateVerificationKeyForSnark<ProtocolMembershipDigest>>;

/// Wrapper of [MKProof] to add serialization utilities.
pub type ProtocolMkProof = ProtocolKey<MKMapProof<BlockRange>>;

/// Wrapper of [MithrilStm:AncillaryProverData](enum@AncillaryProverData) to add serialization utilities.
pub type ProtocolAncillaryProverData = ProtocolKey<AncillaryProverData>;

/// Wrapper of [MithrilStm:AncillaryVerifierData](enum@AncillaryVerifierData) to add serialization utilities.
pub type ProtocolAncillaryVerifierData = ProtocolKey<AncillaryVerifierData>;

impl_codec_and_type_conversions_for_protocol_key!(
    json_hex_codec => ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey, AggregateVerificationKeyForConcatenation<ProtocolMembershipDigest>,
        MKProof, VerificationKeyProofOfPossessionForConcatenation, Sum6KesSig, OpCert, SingleSignature
);

impl_codec_and_type_conversions_for_protocol_key!(
    bytes_hex_codec => ed25519_dalek::Signature, AncillaryProverData, AncillaryVerifierData
);

impl_codec_and_type_conversions_for_protocol_key!(
    no_default_codec => AggregateSignature<ProtocolMembershipDigest>
);

impl ProtocolKeyCodec<AggregateSignature<ProtocolMembershipDigest>>
    for AggregateSignature<ProtocolMembershipDigest>
{
    fn decode_key(
        encoded: &str,
    ) -> StdResult<ProtocolKey<AggregateSignature<ProtocolMembershipDigest>>> {
        match ProtocolKey::from_json_hex(encoded) {
            Ok(res) => Ok(res),
            Err(_) => ProtocolKey::from_bytes_hex(encoded),
        }
    }

    fn encode_key(key: &AggregateSignature<ProtocolMembershipDigest>) -> StdResult<String> {
        // Temporary workaround: encode by aggregate signature type rather than a single codec. The
        // bytes encoding of an aggregate signature is only decodable by clients from distribution
        // 2617.0 onwards, so concatenation multi-signatures must stay JSON-hex until the older
        // distributions (up to 2603.1) are retired. Once they are, register `AggregateSignature`
        // under `bytes_hex_codec` and drop this custom codec.
        match AggregateSignatureType::from(key) {
            AggregateSignatureType::Concatenation => ProtocolKey::key_to_json_hex(key),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark | AggregateSignatureType::IvcSnark => {
                ProtocolKey::key_to_bytes_hex(key)
            }
        }
    }
}

#[cfg(feature = "future_snark")]
impl_codec_and_type_conversions_for_protocol_key!(
    json_hex_codec => VerificationKeyForSnark
);

#[cfg(feature = "future_snark")]
impl_codec_and_type_conversions_for_protocol_key!(
    bytes_hex_codec => AggregateVerificationKeyForSnark<ProtocolMembershipDigest>
);
