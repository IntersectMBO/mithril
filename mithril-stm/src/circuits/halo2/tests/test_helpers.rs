//! Shared test harness and fixtures for focused Halo2 gadget checks.
//!
//! These helpers support inline `#[cfg(test)]` modules colocated with gadget implementations,
//! while `tests/golden` remains responsible for broader end-to-end scenarios.

use anyhow::Result;
use midnight_circuits::hash::poseidon::PoseidonState;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib as zk;
use midnight_zk_stdlib::{MidnightCircuit, Relation};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::LotteryTargetValue;
use crate::circuits::halo2::types::CircuitBase;
use crate::circuits::halo2::witness::LotteryTargetValue as CircuitLotteryTargetValue;
use crate::circuits::halo2::witness::{
    CircuitMerkleTreeLeaf, CircuitWitnessEntry, MerklePath, MerkleTreeCommitment,
    SignedMessageWithoutPrefix,
};
use crate::hash::poseidon::MidnightPoseidonDigest;
use crate::membership_commitment::{
    MerkleTree as StmMerkleTree, MerkleTreeSnarkLeaf as StmMerkleTreeSnarkLeaf,
};
use crate::signature_scheme::{BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey};

/// Small Merkle depth shared by focused gadget tests to keep proving cheap in CI.
pub(crate) const TEST_MERKLE_TREE_DEPTH: usize = 3;
/// Small Merkle depth to test the proper implementation of the merkle path padding.
pub(crate) const TEST_MERKLE_TREE_DEPTH_FOR_PATH_PADDING: usize = 5;

/// Proves and verifies a tiny test-only relation.
pub(crate) fn prove_and_verify_relation<R>(
    relation: &R,
    instance: &R::Instance,
    witness: R::Witness,
) -> Result<()>
where
    R: Relation,
    <R as Relation>::Error: std::error::Error + Send + Sync + 'static,
{
    let circuit = MidnightCircuit::from_relation(relation, None);
    let srs = ParamsKZG::<Bls12>::unsafe_setup(circuit.k(), ChaCha20Rng::seed_from_u64(42));
    let vk = zk::setup_vk(&srs, relation);
    let pk = zk::setup_pk(relation, &vk);
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let proof = zk::prove::<R, PoseidonState<CircuitBase>>(
        &srs, &pk, relation, instance, witness, &mut rng,
    )
    .map_err(anyhow::Error::new)?;

    zk::verify::<R, PoseidonState<CircuitBase>>(&srs.verifier_params(), &vk, instance, None, &proof)
        .map_err(anyhow::Error::new)
}

/// Asserts that a focused gadget relation rejects the supplied witness.
pub(crate) fn assert_relation_rejected(result: Result<()>) {
    assert!(result.is_err(), "expected relation to reject witness");
}

/// Minimal chip preset for comparison/range-only helpers.
pub(crate) fn comparison_used_chips() -> midnight_zk_stdlib::ZkStdLibArch {
    midnight_zk_stdlib::ZkStdLibArch {
        nr_pow2range_cols: 2,
        ..midnight_zk_stdlib::ZkStdLibArch::default()
    }
}

/// Minimal chip preset for gadgets that rely on both Jubjub and Poseidon.
pub(crate) fn jubjub_poseidon_used_chips() -> midnight_zk_stdlib::ZkStdLibArch {
    midnight_zk_stdlib::ZkStdLibArch {
        jubjub: true,
        poseidon: true,
        nr_pow2range_cols: 2,
        ..midnight_zk_stdlib::ZkStdLibArch::default()
    }
}

/// Builds one valid circuit witness entry for focused gadget tests.
pub(crate) fn sample_valid_circuit_witness_entry(
    merkle_path_length: u32,
) -> Result<(
    CircuitWitnessEntry,
    MerkleTreeCommitment,
    SignedMessageWithoutPrefix,
)> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let signing_key = SchnorrSigningKey::generate(&mut rng);
    let verification_key = SchnorrVerificationKey::new_from_signing_key(signing_key.clone());
    let circuit_lottery_target_value = -CircuitLotteryTargetValue::ONE;
    let stm_lottery_target_value: LotteryTargetValue = circuit_lottery_target_value.into();
    let leaf = StmMerkleTreeSnarkLeaf(verification_key, stm_lottery_target_value);
    let stm_tree = StmMerkleTree::<MidnightPoseidonDigest, StmMerkleTreeSnarkLeaf>::new(
        &vec![leaf; 1 << TEST_MERKLE_TREE_DEPTH],
    );
    let merkle_tree_commitment: MerkleTreeCommitment =
        BaseFieldElement::from_bytes(stm_tree.to_merkle_tree_commitment().root.as_slice())?.into();
    let message = SignedMessageWithoutPrefix::from(42u64);
    let transcript = [merkle_tree_commitment.into(), message.into()];
    let unique_schnorr_signature = signing_key.sign_unique(&transcript, &mut rng)?;
    let merkle_path: MerklePath =
        (&stm_tree.compute_merkle_tree_path_fixed_length(0, merkle_path_length)).try_into()?;
    let entry = CircuitWitnessEntry {
        leaf: CircuitMerkleTreeLeaf(verification_key, circuit_lottery_target_value),
        merkle_path,
        unique_schnorr_signature,
        lottery_index: 0,
    };

    Ok((entry, merkle_tree_commitment, message))
}

/// Declares a tiny test-only relation with no public inputs and a single witness payload.
macro_rules! impl_focused_test_relation {
    ($name:ident, $witness:ty, error = $error:ty, $chips:expr, |$std_lib:ident, $layouter:ident, $witness_value:ident| $body:block) => {
        #[derive(Clone, Default, Debug)]
        struct $name;

        impl midnight_zk_stdlib::Relation for $name {
            type Error = $error;
            type Instance = ();
            type Witness = $witness;

            fn format_instance(
                _instance: &Self::Instance,
            ) -> Result<Vec<crate::circuits::halo2::types::CircuitBase>, Self::Error> {
                Ok(vec![])
            }

            fn circuit(
                &self,
                $std_lib: &midnight_zk_stdlib::ZkStdLib,
                $layouter: &mut impl midnight_proofs::circuit::Layouter<crate::circuits::halo2::types::CircuitBase>,
                _instance: midnight_proofs::circuit::Value<()>,
                $witness_value: midnight_proofs::circuit::Value<$witness>,
            ) -> Result<(), Self::Error> $body

            fn used_chips(&self) -> midnight_zk_stdlib::ZkStdLibArch {
                $chips
            }

            fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
                Ok(())
            }

            fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
                Ok(Self)
            }
        }
    };
}

pub(crate) use impl_focused_test_relation;
