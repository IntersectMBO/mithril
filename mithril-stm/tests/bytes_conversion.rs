mod test_extensions;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use mithril_stm::{
    AggregateSignature, Initializer, MithrilMembershipDigest, Parameters, SingleSignature,
    VerificationKeyForConcatenation,
};

use test_extensions::protocol_phase::{
    InitializationPhaseResult, OperationPhaseResult, initialization_phase, operation_phase,
};

type D = MithrilMembershipDigest;

#[test]
fn test_stm_parameters_serialization() {
    let params = Parameters {
        m: 100,
        k: 2,
        phi_f: 0.2,
    };
    let bytes = params.to_bytes().expect("Parameters serialization should not fail");
    let deserialized_params = Parameters::from_bytes(&bytes).unwrap();

    assert_eq!(params, deserialized_params);
}

#[test]
fn test_binary_conversions() {
    let nparties: usize = 32;
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let params = Parameters {
        k: 20,
        m: 200,
        phi_f: 0.9,
    };
    let InitializationPhaseResult {
        signers,
        reg_parties,
        initializers,
    } = initialization_phase(nparties, rng.clone(), params);

    let encoded = params.to_bytes().expect("Parameters serialization should not fail");
    Parameters::from_bytes(&encoded[..23])
        .expect_err("Decoding should fail with bytes shorter than the legacy 24-byte layout");
    let decoded = Parameters::from_bytes(&encoded).unwrap();
    assert_eq!(params, decoded);

    let verification_key = reg_parties[0].0;
    let encoded = verification_key.to_raw_bytes();
    VerificationKeyForConcatenation::from_raw_bytes(&encoded[1..])
        .expect_err("VerificationKey decoding should fail with invalid bytes");
    let decoded = VerificationKeyForConcatenation::from_raw_bytes(&encoded).unwrap();
    assert_eq!(verification_key, decoded);

    let initializer = &initializers[0];
    let encoded = initializer
        .to_bytes()
        .expect("Initializer serialization should not fail");
    Initializer::from_bytes(&encoded[1..])
        .expect_err("Initializer decoding should fail with invalid bytes");
    let decoded = Initializer::from_bytes(&encoded).unwrap();
    assert_eq!(
        initializer
            .to_bytes()
            .expect("Initializer serialization should not fail"),
        decoded.to_bytes().expect("Initializer serialization should not fail")
    );

    let OperationPhaseResult { msig, avk: _, sigs } =
        operation_phase(params, signers, reg_parties, msg);

    let sig = &sigs[0];
    let encoded = sig.to_bytes().expect("SingleSignature serialization should not fail");
    SingleSignature::from_bytes::<D>(&encoded[1..])
        .expect_err("SingleSignature decoding should fail with invalid bytes");
    let decoded = SingleSignature::from_bytes::<D>(&encoded).unwrap();
    assert_eq!(sig, &decoded);

    let (msig, _ancillary_proof_output) = msig.unwrap();
    let encoded = msig
        .to_bytes()
        .expect("AggregateSignature serialization should not fail");
    AggregateSignature::<D>::from_bytes(&encoded[1..])
        .expect_err("AggregateSignature decoding should fail with invalid bytes");
    let decoded = AggregateSignature::<D>::from_bytes(&encoded).unwrap();
    assert_eq!(
        msig.to_bytes()
            .expect("AggregateSignature serialization should not fail"),
        decoded
            .to_bytes()
            .expect("AggregateSignature serialization should not fail")
    );
}
