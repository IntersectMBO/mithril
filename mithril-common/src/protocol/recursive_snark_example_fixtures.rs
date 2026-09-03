//! Canonical fixtures for the recursive SNARK example shipped by `mithril-stm`.
//!
//! The example cannot build its own protocol messages: assembling a rigid preimage needs the
//! labels, the dynamic-parts digest and the protocol-parameters hash, all of which live here rather
//! than in `mithril-stm`, which cannot depend on this crate. The generator below produces them
//! once; the comparison test keeps the committed copies honest.

use std::fs;
use std::path::PathBuf;

use mithril_stm::{
    AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, BaseFieldElement, Clerk,
    GenesisVerificationKeyBundle, Initializer, KeyRegistration, Parameters, SchnorrSigningKey,
    SchnorrVerificationKey, Signer, SingleSignature, Stake,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::crypto_helper::{ProtocolAggregateVerificationKeyForSnark, ProtocolMembershipDigest};
use crate::entities::{ProtocolMessage, ProtocolMessagePartKey, ProtocolParameters};

/// Seed of the example's signer key material. Public and therefore compromised: it exists so the
/// aggregate verification key is reproducible and the committed preimages stay valid.
const SIGNER_SEED: [u8; 32] = [0u8; 32];

/// Seed of the example's genesis Schnorr key. Compromised for the same reason.
const GENESIS_SEED: [u8; 32] = [1u8; 32];

/// Stakes of the example's four signers, fixed so the aggregate verification key is reproducible.
const SIGNER_STAKES: [Stake; 4] = [1_000, 2_000, 3_000, 4_000];

const QUORUM_PARAMETER: u64 = 2;
const SECURITY_PARAMETER: u64 = 100;
const LOTTERY_PARAMETER: f64 = 0.2;

const GENESIS_EPOCH: u64 = 0;
const FIRST_CERTIFICATE_EPOCH: u64 = 1;
const SECOND_CERTIFICATE_EPOCH: u64 = 2;

const GENESIS_PREIMAGE_FILE: &str = "genesis_protocol_message_preimage.bin";
const FIRST_CERTIFICATE_PREIMAGE_FILE: &str = "first_certificate_protocol_message_preimage.bin";
const SECOND_CERTIFICATE_PREIMAGE_FILE: &str = "second_certificate_protocol_message_preimage.bin";

fn fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../mithril-stm/examples/assets")
}

fn protocol_parameters() -> ProtocolParameters {
    ProtocolParameters {
        k: QUORUM_PARAMETER,
        m: SECURITY_PARAMETER,
        phi_f: LOTTERY_PARAMETER,
    }
}

fn stm_parameters() -> Parameters {
    Parameters {
        k: QUORUM_PARAMETER,
        m: SECURITY_PARAMETER,
        phi_f: LOTTERY_PARAMETER,
    }
}

/// Builds the example's signer set from the fixed seed. Cheap: key registration and the membership
/// commitment only, no trusted setup and no proving.
fn example_signers() -> Vec<Signer<ProtocolMembershipDigest>> {
    let parameters = stm_parameters();
    let mut rng = ChaCha20Rng::from_seed(SIGNER_SEED);

    let mut key_registration = KeyRegistration::initialize();
    let mut initializers = Vec::with_capacity(SIGNER_STAKES.len());
    for stake in SIGNER_STAKES {
        let initializer = Initializer::new(parameters, stake, &mut rng);
        key_registration
            .register(
                initializer.stake,
                &initializer.get_verification_key_proof_of_possession_for_concatenation(),
                initializer.schnorr_verification_key,
            )
            .expect("example signer registration must succeed");
        initializers.push(initializer);
    }
    let closed_registration = key_registration
        .close_registration(&parameters)
        .expect("example key registration must close");

    initializers
        .into_iter()
        .map(|initializer| {
            initializer
                .try_create_signer(&closed_registration)
                .expect("example signer creation must succeed")
        })
        .collect()
}

/// Hex encoding of the example's SNARK aggregate verification key, as the rigid
/// `next_aggregate_verification_key` message part carries it.
fn aggregate_verification_key_hex(clerk: &Clerk<ProtocolMembershipDigest>) -> String {
    let aggregate_verification_key = clerk.compute_aggregate_verification_key();
    let snark_aggregate_verification_key = aggregate_verification_key
        .to_snark_aggregate_verification_key()
        .expect("the example registration carries Schnorr verification keys")
        .clone();

    ProtocolAggregateVerificationKeyForSnark::from(snark_aggregate_verification_key)
        .to_bytes_hex()
        .expect("the SNARK aggregate verification key must encode to hex")
}

/// The three rigid protocol messages the example's chain consumes, in chain order: the genesis
/// message, then one certificate per epoch. All three announce the same aggregate verification key
/// because the signer set never changes, which is what makes each next-epoch transition validate.
fn example_protocol_messages(clerk: &Clerk<ProtocolMembershipDigest>) -> [ProtocolMessage; 3] {
    let aggregate_verification_key = aggregate_verification_key_hex(clerk);
    let parameters_hash = protocol_parameters().compute_hash();

    [GENESIS_EPOCH, FIRST_CERTIFICATE_EPOCH, SECOND_CERTIFICATE_EPOCH].map(|epoch| {
        let mut protocol_message = ProtocolMessage::new_rigid();
        protocol_message.set_message_part(
            ProtocolMessagePartKey::NextSnarkAggregateVerificationKey,
            aggregate_verification_key.clone(),
        );
        protocol_message.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            parameters_hash.clone(),
        );
        protocol_message.set_message_part(ProtocolMessagePartKey::CurrentEpoch, epoch.to_string());
        protocol_message
            .check_rigid_integrity()
            .expect("the example protocol message must be a well-formed rigid message");
        protocol_message
    })
}

#[test]
fn committed_preimages_match_the_canonical_protocol_messages() {
    let signers = example_signers();
    let clerk = Clerk::new_clerk_from_signer(&signers[0]);
    let protocol_messages = example_protocol_messages(&clerk);

    let directory = fixture_directory();
    let files = [
        GENESIS_PREIMAGE_FILE,
        FIRST_CERTIFICATE_PREIMAGE_FILE,
        SECOND_CERTIFICATE_PREIMAGE_FILE,
    ];

    for (protocol_message, file) in protocol_messages.iter().zip(files) {
        let committed = fs::read(directory.join(file))
            .unwrap_or_else(|error| panic!("committed fixture {file} must be readable: {error}"));
        assert_eq!(
            protocol_message.rigid_preimage(),
            committed,
            "committed fixture {file} no longer matches the protocol message the example documents"
        );
    }
}

/// Regenerates the committed preimages. Expensive: every certificate is proved and then verified
/// before anything is written, so a fixture is never committed unless the chain it describes
/// actually works. Proving alone would not establish that: the prover emits proof bytes for any
/// witness, and only verification rejects an inconsistent one.
#[test]
#[ignore]
fn generate_recursive_snark_example_fixtures() {
    let signers = example_signers();
    let clerk = Clerk::new_clerk_from_signer(&signers[0]);
    let protocol_messages = example_protocol_messages(&clerk);
    let parameters = stm_parameters();
    let aggregate_verification_key = clerk.compute_aggregate_verification_key();

    let mut genesis_rng = ChaCha20Rng::from_seed(GENESIS_SEED);
    let genesis_signing_key = SchnorrSigningKey::generate(&mut genesis_rng);
    let genesis_verification_key =
        SchnorrVerificationKey::new_from_signing_key(genesis_signing_key.clone());
    let genesis_message =
        BaseFieldElement::from_raw(&protocol_messages[0].compute_rigid_hash_bytes())
            .expect("the genesis message hash must reduce into the base field");
    let genesis_signature = genesis_signing_key
        .sign_standard(&[genesis_message], &mut genesis_rng)
        .expect("the genesis attestation must sign");
    let genesis_verification_key_bundle =
        GenesisVerificationKeyBundle::new(genesis_verification_key);
    let genesis_data = AncillaryGenesisData::new(
        protocol_messages[0].rigid_preimage(),
        Some(genesis_signature),
        Some(genesis_verification_key),
    );

    let mut rolling_state = None;
    for protocol_message in &protocol_messages[1..] {
        let message = protocol_message.compute_rigid_hash_bytes();
        let signatures = signers
            .iter()
            .filter_map(|signer| signer.create_single_signature(&message).ok())
            .collect::<Vec<SingleSignature>>();

        let (certificate, output) = clerk
            .aggregate_signatures_with_type(
                &signatures,
                &message,
                AggregateSignatureType::IvcSnark,
                AncillaryProofInput::new(
                    rolling_state,
                    genesis_data.clone(),
                    protocol_message.rigid_preimage(),
                ),
            )
            .expect("the example chain step must aggregate");

        certificate
            .verify(
                &message,
                &aggregate_verification_key,
                &parameters,
                output.verifier_data().cloned(),
                Some(genesis_verification_key_bundle.clone()),
            )
            .expect("the example chain step must verify");

        rolling_state = Some(
            output
                .prover_data()
                .cloned()
                .expect("a next-epoch step must produce the rolling state the next step consumes"),
        );
    }

    let directory = fixture_directory();
    fs::create_dir_all(&directory).expect("the fixture directory must be creatable");
    for (protocol_message, file) in protocol_messages.iter().zip([
        GENESIS_PREIMAGE_FILE,
        FIRST_CERTIFICATE_PREIMAGE_FILE,
        SECOND_CERTIFICATE_PREIMAGE_FILE,
    ]) {
        fs::write(directory.join(file), protocol_message.rigid_preimage())
            .unwrap_or_else(|error| panic!("fixture {file} must be writable: {error}"));
    }
}
