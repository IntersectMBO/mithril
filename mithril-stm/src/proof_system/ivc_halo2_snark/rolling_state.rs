//! `IvcRollingState`: caller-owned bridge between consecutive IVC proving steps.

use midnight_circuits::{
    types::Instantiable,
    verifier::{Accumulator, BlstrsEmulation},
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::circuits::halo2_ivc::types::EpochNumber;
use crate::{
    StmResult,
    circuits::{
        halo2::types::CircuitBase,
        halo2_ivc::{
            AssignedAccumulator, ProtocolMessagePreimage,
            accumulator::trivial_accumulator,
            errors::{EpochTransitionErrorKind, IvcCircuitError},
            state::{Global, State},
            types::{IvcProofBytes, StepCounter},
        },
    },
    proof_system::ivc_halo2_snark::{
        errors::IvcProofError,
        prover_input_helpers::{IvcTransitionType, create_snark_message_for_next_state},
    },
    signature_scheme::{BaseFieldElement, StandardSchnorrSignature},
};

/// Caller-owned bridge between consecutive IVC proving steps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IvcRollingState {
    /// Last committed chain state.
    state: State,
    /// Bytes of the last IVC proof under the Poseidon transcript
    ivc_proof: IvcProofBytes,
    /// Folded accumulator the new step will build on top of
    #[serde(with = "midnight_accumulator_serde")]
    accumulator: Accumulator<BlstrsEmulation>,
    /// Chain-specific Schnorr signature over the genesis message
    genesis_signature: StandardSchnorrSignature,
}

impl IvcRollingState {
    /// Builds a rolling state from the four fields produced by an IVC proving step.
    pub(crate) fn new(
        state: State,
        ivc_proof: IvcProofBytes,
        accumulator: Accumulator<BlstrsEmulation>,
        genesis_signature: StandardSchnorrSignature,
    ) -> Self {
        Self {
            state,
            ivc_proof,
            accumulator,
            genesis_signature,
        }
    }

    /// Builds the genesis rolling state: zeroed chain state, empty IVC proof,
    /// trivial accumulator over the supplied fixed-base names, and the
    /// caller-supplied genesis signature.
    ///
    /// `fixed_base_names` must be the keys of `IvcSnarkProverSetup::combined_fixed_bases`.
    /// Passing any other list produces a genesis accumulator that does not match
    /// what the in-circuit verifier expects, and the first proving step will fail.
    pub(crate) fn genesis(
        genesis_signature: StandardSchnorrSignature,
        fixed_base_names: &[String],
    ) -> Self {
        Self {
            state: State::genesis(),
            ivc_proof: IvcProofBytes::empty(),
            accumulator: trivial_accumulator(fixed_base_names),
            genesis_signature,
        }
    }

    /// Returns the last committed chain state.
    pub(crate) fn state(&self) -> &State {
        &self.state
    }

    /// Returns the last IVC proof bytes wrapper.
    pub(crate) fn ivc_proof(&self) -> &IvcProofBytes {
        &self.ivc_proof
    }

    /// Returns the folded accumulator the new step will build on top of.
    pub(crate) fn accumulator(&self) -> &Accumulator<BlstrsEmulation> {
        &self.accumulator
    }

    /// Returns the chain-specific Schnorr signature over the genesis state.
    pub(crate) fn genesis_signature(&self) -> StandardSchnorrSignature {
        self.genesis_signature
    }

    /// Verifies the chain's genesis Schnorr signature against the genesis message and
    /// verification key carried in `global`. Called at the first proving step only.
    pub(crate) fn verify_genesis_signature(&self, global: &Global) -> StmResult<()> {
        self.genesis_signature.verify(
            &[BaseFieldElement::from(global.genesis_message.as_field())],
            &global.genesis_verification_key,
        )
    }

    /// Returns the public inputs expected by the IVC verifier gadget for the previous
    /// step's IVC proof: `[global | previous state | previous folded accumulator]`.
    pub(crate) fn previous_ivc_proof_public_inputs(&self, global: &Global) -> Vec<CircuitBase> {
        [
            global.as_public_input(),
            self.state.as_public_input(),
            AssignedAccumulator::as_public_input(&self.accumulator),
        ]
        .concat()
    }

    /// Returns the step counter for the next step (current + 1). Errors if the counter
    /// would overflow `u64`.
    pub(crate) fn new_step_counter(&self) -> StmResult<StepCounter> {
        let current = self.state.step_counter.as_u64();
        let next = current
            .checked_add(1)
            .ok_or(IvcCircuitError::StepCounterOverflow { current })?;
        Ok(StepCounter::new(next))
    }

    /// Returns `true` if this rolling state is at the genesis step (`step_counter == 0`).
    pub(crate) fn is_genesis(&self) -> bool {
        self.state.step_counter == StepCounter::ZERO
    }

    /// Returns `true` if the certificate belongs to the epoch immediately following
    /// the chain's current epoch (`certificate_epoch == current_epoch + 1`).
    #[cfg(test)]
    pub(crate) fn is_next_epoch(&self, certificate_epoch: EpochNumber) -> bool {
        certificate_epoch.as_field()
            == self.state.current_epoch.as_field() + EpochNumber::new(1).as_field()
    }

    /// Asserts that the parameters in the rolling state matches the ones in
    /// the protocol message depending on the epoch transition type.
    /// This is done mainly to avoid computing a proof that will not verify.
    pub(crate) fn assert_correct_parameters(
        &self,
        protocol_message_preimage: &ProtocolMessagePreimage,
        aggregate_verification_key_commitment: &[u8],
        message: &[u8],
        transition_type: IvcTransitionType,
    ) -> StmResult<()> {
        let (_, merkle_tree_commitment) =
            create_snark_message_for_next_state(aggregate_verification_key_commitment, message)?;

        let result = match transition_type {
            IvcTransitionType::SameEpoch => {
                let merkle_tree_commitment_matches =
                    self.state().merkle_tree_commitment == merkle_tree_commitment;
                let next_merkle_tree_commitment_matches = self.state().next_merkle_tree_commitment
                    == protocol_message_preimage.next_merkle_tree_commitment();
                let next_protocol_parameters_matches = self.state().next_protocol_parameters
                    == protocol_message_preimage.next_protocol_parameters();

                merkle_tree_commitment_matches
                    && next_merkle_tree_commitment_matches
                    && next_protocol_parameters_matches
                    && self.state().step_counter.is_not_first_step()
            }
            IvcTransitionType::NextEpoch => {
                self.state().next_merkle_tree_commitment == merkle_tree_commitment
            }
            IvcTransitionType::Genesis => true,
        };

        if !result {
            return Err(IvcCircuitError::InvalidEpochTransition {
                kind: EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                last_committed_epoch: self.state().current_epoch.as_u64(),
            }
            .into());
        }

        Ok(())
    }

    /// Rejects a `rolling_state` that carries a genesis state (`step_counter == 0`).
    ///
    /// The genesis step is only ever produced internally by the bootstrap path; callers reach it by
    /// passing `rolling_state = None`. A genesis state supplied as a previous step would instead run
    /// a normal step that silently ignores the certificate. Since `genesis_bootstrap` is always
    /// supplied, this is the only remaining invalid context: the previously-possible both-`Some` and
    /// both-`None` misuses are now unrepresentable.
    pub(crate) fn ensure_advanceable_rolling_state(
        rolling_state: Option<&IvcRollingState>,
    ) -> StmResult<()> {
        if rolling_state.is_some_and(|rs| rs.is_genesis()) {
            return Err(IvcProofError::InvalidProvingContext.into());
        }
        Ok(())
    }
}

pub(crate) mod midnight_accumulator_serde {
    use midnight_circuits::verifier::{Accumulator, BlstrsEmulation};
    use midnight_proofs::utils::SerdeFormat;
    use serde::{Deserializer, Serializer};

    use crate::circuits::halo2_ivc::io::{Read, Write};

    /// Serialization function based on the write function of Midnight's Accumulator
    pub fn serialize<S: Serializer>(
        accumulator: &Accumulator<BlstrsEmulation>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::new();
        accumulator
            .write(&mut buf, SerdeFormat::RawBytesUnchecked)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&buf)
    }

    /// Deserialization function based on the read function of Midnight's Accumulator
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Accumulator<BlstrsEmulation>, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Accumulator::<BlstrsEmulation>::read(&mut bytes.as_slice(), SerdeFormat::RawBytesUnchecked)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        circuits::halo2_ivc::{
            embedded_assets::load_embedded_recursive_chain_state_asset, types::EpochNumber,
        },
        signature_scheme::{BaseFieldElement, SchnorrSigningKey},
    };

    use super::*;

    fn build_genesis_signature() -> StandardSchnorrSignature {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let message = vec![BaseFieldElement::from(1u64)];
        signing_key.sign_standard(&message, &mut rng).unwrap()
    }

    #[test]
    fn genesis_initializes_zero_state_empty_proof_and_supplied_signature() {
        let genesis_signature = build_genesis_signature();
        let fixed_base_names = vec!["base_one".to_string(), "base_two".to_string()];

        let rolling_state = IvcRollingState::genesis(genesis_signature, &fixed_base_names);

        assert_eq!(
            rolling_state.state().as_public_input(),
            State::genesis().as_public_input(),
            "genesis rolling state must carry the genesis chain state"
        );
        assert!(
            rolling_state.ivc_proof().is_empty(),
            "genesis rolling state must have an empty IVC proof"
        );
        assert_eq!(rolling_state.genesis_signature(), genesis_signature);
    }

    #[test]
    fn genesis_accumulator_carries_supplied_fixed_base_names() {
        let genesis_signature = build_genesis_signature();
        let fixed_base_names = vec!["base_one".to_string(), "base_two".to_string()];

        let rolling_state = IvcRollingState::genesis(genesis_signature, &fixed_base_names);

        let mut accumulator_fixed_base_keys: Vec<String> = rolling_state
            .accumulator()
            .rhs()
            .fixed_base_scalars()
            .keys()
            .cloned()
            .collect();
        accumulator_fixed_base_keys.sort();
        let mut expected = fixed_base_names.clone();
        expected.sort();
        assert_eq!(accumulator_fixed_base_keys, expected);
    }

    #[test]
    fn is_genesis_returns_true_for_genesis_state() {
        let genesis_signature = build_genesis_signature();
        let rolling_state = IvcRollingState::genesis(genesis_signature, &[]);
        assert!(rolling_state.is_genesis());
    }

    #[test]
    fn is_next_epoch_identifies_direct_successor_of_chain_epoch() {
        let genesis_signature = build_genesis_signature();
        let rolling_state = IvcRollingState::genesis(genesis_signature, &[]);
        // Genesis state has current_epoch == 0. The immediate next epoch is 1.
        assert!(rolling_state.is_next_epoch(EpochNumber::new(1)));
        assert!(!rolling_state.is_next_epoch(EpochNumber::new(0)));
        assert!(!rolling_state.is_next_epoch(EpochNumber::new(2)));
    }

    // The context guard is the first thing `IvcProver::prove` runs. It is tested directly here
    // rather than through `prove` so the test stays fast: reaching `prove` would require building
    // an `IvcSnarkProverSetup` (full keygen). With `genesis_bootstrap` now always supplied, a genesis
    // `rolling_state` is the only remaining invalid context; both-`Some`/both-`None` are
    // unrepresentable.
    #[test]
    fn ensure_advanceable_rolling_state_rejects_only_genesis_state() {
        // A genesis signature is needed to build any rolling state; its value is irrelevant
        // because the guard only inspects the step counter.
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let signing_key = SchnorrSigningKey::generate(&mut rng);
        let genesis_signature = signing_key
            .sign_standard(&[BaseFieldElement::from(1u64)], &mut rng)
            .expect("genesis signature should be produced");

        // `None` bootstraps from genesis internally: accepted.
        IvcRollingState::ensure_advanceable_rolling_state(None)
            .expect("None must be accepted (genesis bootstrap)");

        // A genesis rolling state (`step_counter == 0`) must be rejected.
        let genesis_state = IvcRollingState::genesis(genesis_signature, &[]);
        assert!(genesis_state.is_genesis());
        let err = IvcRollingState::ensure_advanceable_rolling_state(Some(&genesis_state))
            .expect_err("genesis rolling state must be rejected");
        assert_eq!(
            err.downcast_ref::<IvcProofError>(),
            Some(&IvcProofError::InvalidProvingContext),
            "genesis rolling state must fail with InvalidProvingContext, got: {err}"
        );

        // A non-genesis rolling state (a previous step's output) is accepted.
        let chain_state = load_embedded_recursive_chain_state_asset()
            .expect("recursive chain state asset should load");
        let advanced_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );
        assert!(!advanced_state.is_genesis());
        IvcRollingState::ensure_advanceable_rolling_state(Some(&advanced_state))
            .expect("a non-genesis rolling state must be accepted");
    }

    mod assert_correct_parameters {
        use crate::{
            circuits::halo2_ivc::types::ProtocolParametersHash,
            proof_system::ivc_halo2_snark::prover_input_helpers::tests::{
                build_preimage, build_rolling_state, build_standard_preimage,
                build_standard_rolling_state, merkle_tree_commitment_from_bytes,
            },
        };

        use super::*;

        // Creates a zero root of an avk
        fn avk_zero_root() -> Vec<u8> {
            [0u8; 40].to_vec()
        }

        // Creates a non-zero root of an avk
        fn avk_nonzero_root() -> Vec<u8> {
            let mut bytes = [0u8; 40];
            bytes[0] = 0x02;
            bytes.to_vec()
        }

        #[test]
        fn same_epoch_passes_with_valid_parameters() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(5), EpochNumber::new(3));
            let preimage = build_standard_preimage(EpochNumber::new(3));

            let result = rolling_state.assert_correct_parameters(
                &preimage,
                &avk_zero_root(),
                &[0u8; 32],
                IvcTransitionType::SameEpoch,
            );

            assert!(result.is_ok());
        }

        #[test]
        fn rejects_same_epoch_after_genesis_step() {
            let rolling_state_with_step_counter_one =
                build_standard_rolling_state(StepCounter::new(1), EpochNumber::ZERO);
            let preimage = build_standard_preimage(EpochNumber::ZERO);

            let err = rolling_state_with_step_counter_one
                .assert_correct_parameters(
                    &preimage,
                    &avk_zero_root(),
                    &[0u8; 32],
                    IvcTransitionType::SameEpoch,
                )
                .unwrap_err();

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind:
                        EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                    ..
                }
            ));
        }

        #[test]
        fn rejects_same_epoch_with_mismatched_lookahead_commitment() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(5), EpochNumber::new(3));
            let preimage_with_non_zero_next_merkle_tree_commitment =
                build_preimage(EpochNumber::new(3), [0x11; 32], [0u8; 32]);

            let err = rolling_state
                .assert_correct_parameters(
                    &preimage_with_non_zero_next_merkle_tree_commitment,
                    &avk_zero_root(),
                    &[0u8; 32],
                    IvcTransitionType::SameEpoch,
                )
                .unwrap_err();

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind:
                        EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                    ..
                }
            ));
        }

        #[test]
        fn rejects_same_epoch_with_mismatched_lookahead_parameters() {
            let rolling_state_with_zero_hash_parameters =
                build_standard_rolling_state(StepCounter::new(5), EpochNumber::new(3));
            let preimage_with_non_zero_hash_parameters =
                build_preimage(EpochNumber::new(3), [0u8; 32], [0x22; 32]);

            let err = rolling_state_with_zero_hash_parameters
                .assert_correct_parameters(
                    &preimage_with_non_zero_hash_parameters,
                    &avk_zero_root(),
                    &[0u8; 32],
                    IvcTransitionType::SameEpoch,
                )
                .unwrap_err();

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind:
                        EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                    ..
                }
            ));
        }

        #[test]
        fn next_epoch_passes_when_next_merkle_commitment_matches_current() {
            let mut non_zero_root_bytes = [0u8; 32];
            non_zero_root_bytes[0] = 0x02;
            let non_zero_next_merkle_tree_commitment =
                merkle_tree_commitment_from_bytes(non_zero_root_bytes);

            let rolling_state = build_rolling_state(
                StepCounter::new(5),
                EpochNumber::new(3),
                non_zero_next_merkle_tree_commitment,
                ProtocolParametersHash::ZERO,
                ProtocolParametersHash::ZERO,
            );
            let preimage = build_preimage(EpochNumber::new(4), [0u8; 32], [0u8; 32]);

            let result = rolling_state.assert_correct_parameters(
                &preimage,
                &avk_nonzero_root(),
                &[0u8; 32],
                IvcTransitionType::NextEpoch,
            );

            assert!(result.is_ok());
        }

        #[test]
        fn rejects_next_epoch_when_next_merkle_commitment_does_not_match() {
            let zero_next_merkle_tree_commitment = merkle_tree_commitment_from_bytes([0u8; 32]);

            let rolling_state = build_rolling_state(
                StepCounter::new(5),
                EpochNumber::new(3),
                zero_next_merkle_tree_commitment,
                ProtocolParametersHash::ZERO,
                ProtocolParametersHash::ZERO,
            );
            let preimage = build_preimage(EpochNumber::new(4), [0u8; 32], [0u8; 32]);

            let err = rolling_state
                .assert_correct_parameters(
                    &preimage,
                    &avk_nonzero_root(),
                    &[0u8; 32],
                    IvcTransitionType::NextEpoch,
                )
                .unwrap_err();

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind:
                        EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                    ..
                }
            ));
        }

        #[test]
        fn genesis_always_passes() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(1), EpochNumber::ZERO);
            let preimage = build_standard_preimage(EpochNumber::ZERO);

            let result = rolling_state.assert_correct_parameters(
                &preimage,
                &avk_zero_root(),
                &[0u8; 32],
                IvcTransitionType::Genesis,
            );

            assert!(result.is_ok());
        }
    }
}
