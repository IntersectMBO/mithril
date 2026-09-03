//! `IvcRollingState`: caller-owned bridge between consecutive IVC proving steps.

use midnight_circuits::{
    types::Instantiable,
    verifier::{Accumulator, BlstrsEmulation},
};
use serde::{Deserialize, Serialize};

use crate::{
    AggregateVerificationKeyForSnark, MembershipDigest, StmResult,
    circuits::{
        halo2::types::CircuitBase,
        halo2_ivc::{
            AssignedAccumulator, ProtocolMessagePreimage,
            accumulator::trivial_accumulator,
            errors::{EpochTransitionErrorKind, IvcCircuitError},
            state::{Global, State},
            types::{IvcProofBytes, MerkleTreeCommitment, MessageHash, StepCounter},
        },
    },
    proof_system::halo2_ivc_snark::prover_input_helpers::create_snark_message_for_next_state,
    signature_scheme::{BaseFieldElement, StandardSchnorrSignature},
};

/// Classifies how the incoming certificate advances the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IvcTransitionType {
    /// First step of the chain; no certificate is processed.
    Genesis,
    /// Certificate extends the current epoch.
    SameEpoch,
    /// Certificate starts a new epoch.
    NextEpoch,
}

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
    /// `fixed_base_names` must be the keys of `IvcProverSetup::combined_fixed_bases`.
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

    /// Classifies how the incoming certificate advances the chain and checks that the rolling
    /// state agrees with the protocol message for that transition. Rejecting a mismatch here
    /// avoids computing a proof that could not verify.
    ///
    /// Returns the transition type together with the derived certificate message hash and Merkle
    /// tree commitment, which the commitment check builds here and the caller needs to assemble
    /// the next state.
    ///
    /// Returns `IvcCircuitError::InvalidEpochTransition` with the specific
    /// `EpochTransitionErrorKind` when the incoming certificate's epoch is out of range or the
    /// state does not match the protocol message.
    pub(crate) fn validate_transition<D: MembershipDigest>(
        &self,
        protocol_message_preimage: &ProtocolMessagePreimage,
        aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
        message: &[u8],
    ) -> StmResult<(IvcTransitionType, MessageHash, MerkleTreeCommitment)> {
        let last_committed_epoch = self.state.current_epoch;
        let next_last_committed_epoch =
            last_committed_epoch
                .next_epoch()
                .ok_or(IvcCircuitError::InvalidEpochTransition {
                    kind: EpochTransitionErrorKind::EpochOverflow,
                    last_committed_epoch: last_committed_epoch.as_u64(),
                })?;
        let incoming_certificate_epoch = protocol_message_preimage.current_epoch();

        let transition_type = if incoming_certificate_epoch.is_equal(&last_committed_epoch) {
            IvcTransitionType::SameEpoch
        } else if incoming_certificate_epoch.is_equal(&next_last_committed_epoch) {
            IvcTransitionType::NextEpoch
        } else {
            return Err(IvcCircuitError::InvalidEpochTransition {
                kind: EpochTransitionErrorKind::EpochGap {
                    incoming_certificate_epoch: incoming_certificate_epoch.as_u64(),
                    last_committed_epoch: last_committed_epoch.as_u64(),
                },
                last_committed_epoch: last_committed_epoch.as_u64(),
            }
            .into());
        };

        let (certificate_message_hash, certificate_merkle_tree_commitment) =
            create_snark_message_for_next_state(aggregate_verification_key, message)?;

        let parameters_match = match transition_type {
            IvcTransitionType::SameEpoch => {
                self.state.merkle_tree_commitment == certificate_merkle_tree_commitment
                    && self.state.next_merkle_tree_commitment
                        == protocol_message_preimage.next_merkle_tree_commitment()
                    && self.state.next_protocol_parameters
                        == protocol_message_preimage.next_protocol_parameters()
                    && self.state.step_counter.is_not_first_step()
            }
            IvcTransitionType::NextEpoch => {
                self.state.next_merkle_tree_commitment == certificate_merkle_tree_commitment
            }
            // The classification above never yields `Genesis`: the genesis step is built by
            // `IvcProverInput::prepare_genesis`, which never validates a transition.
            IvcTransitionType::Genesis => unreachable!("genesis bypasses transition validation"),
        };

        if !parameters_match {
            return Err(IvcCircuitError::InvalidEpochTransition {
                kind: EpochTransitionErrorKind::RollingStateParametersDoesNotMatchProtocolMessage,
                last_committed_epoch: last_committed_epoch.as_u64(),
            }
            .into());
        }

        Ok((
            transition_type,
            certificate_message_hash,
            certificate_merkle_tree_commitment,
        ))
    }
}

pub(crate) mod midnight_accumulator_serde {
    use midnight_circuits::verifier::{Accumulator, BlstrsEmulation};
    use midnight_proofs::utils::SerdeFormat;
    use serde::{Deserializer, Serializer};

    use crate::circuits::halo2_ivc::io::{ReadWithFormat, WriteWithFormat};

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
        circuits::halo2_ivc::types::EpochNumber,
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

    mod validate_transition {
        use crate::{
            MithrilMembershipDigest,
            circuits::halo2_ivc::types::ProtocolParametersHash,
            proof_system::{
                AggregateVerificationKeyForSnark,
                halo2_ivc_snark::prover_input_helpers::tests::{
                    build_preimage, build_rolling_state, build_standard_preimage,
                    build_standard_rolling_state, merkle_tree_commitment_from_bytes,
                },
            },
        };

        use super::*;

        // Creates an avk with a zero root
        fn avk_with_zero_root() -> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
            AggregateVerificationKeyForSnark::from_bytes(&[0u8; 40]).unwrap()
        }

        // Creates an avk with non zero root
        fn avk_with_nonzero_root() -> AggregateVerificationKeyForSnark<MithrilMembershipDigest> {
            let mut bytes = [0u8; 40];
            bytes[0] = 0x02;
            AggregateVerificationKeyForSnark::from_bytes(&bytes).unwrap()
        }

        #[test]
        fn classifies_same_epoch_with_valid_parameters() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(5), EpochNumber::new(3));
            let preimage = build_standard_preimage(EpochNumber::new(3));

            let (transition_type, _, _) = rolling_state
                .validate_transition(&preimage, &avk_with_zero_root(), &[0u8; 32])
                .unwrap();

            assert_eq!(transition_type, IvcTransitionType::SameEpoch);
        }

        #[test]
        fn rejects_same_epoch_after_genesis_step() {
            let rolling_state_with_step_counter_one =
                build_standard_rolling_state(StepCounter::new(1), EpochNumber::ZERO);
            let preimage = build_standard_preimage(EpochNumber::ZERO);

            let err = rolling_state_with_step_counter_one
                .validate_transition(&preimage, &avk_with_zero_root(), &[0u8; 32])
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
                .validate_transition(
                    &preimage_with_non_zero_next_merkle_tree_commitment,
                    &avk_with_zero_root(),
                    &[0u8; 32],
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
                .validate_transition(
                    &preimage_with_non_zero_hash_parameters,
                    &avk_with_zero_root(),
                    &[0u8; 32],
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
        fn classifies_next_epoch_when_next_merkle_commitment_matches_current() {
            let mut non_zero_root_bytes = [0u8; 32];
            non_zero_root_bytes[0] = 0x02;
            let non_zero_next_merkle_tree_commitment =
                merkle_tree_commitment_from_bytes(non_zero_root_bytes);
            let non_zero_merkle_tree_commitment_avk = avk_with_nonzero_root();

            let rolling_state = build_rolling_state(
                StepCounter::new(5),
                EpochNumber::new(3),
                non_zero_next_merkle_tree_commitment,
                ProtocolParametersHash::ZERO,
                ProtocolParametersHash::ZERO,
            );
            let preimage = build_preimage(EpochNumber::new(4), [0u8; 32], [0u8; 32]);

            let (transition_type, _, _) = rolling_state
                .validate_transition(&preimage, &non_zero_merkle_tree_commitment_avk, &[0u8; 32])
                .unwrap();

            assert_eq!(transition_type, IvcTransitionType::NextEpoch);
        }

        #[test]
        fn rejects_next_epoch_when_next_merkle_commitment_does_not_match() {
            let zero_next_merkle_tree_commitment = merkle_tree_commitment_from_bytes([0u8; 32]);
            let non_zero_merkle_tree_commitment_avk = avk_with_nonzero_root();

            let rolling_state = build_rolling_state(
                StepCounter::new(5),
                EpochNumber::new(3),
                zero_next_merkle_tree_commitment,
                ProtocolParametersHash::ZERO,
                ProtocolParametersHash::ZERO,
            );
            let preimage = build_preimage(EpochNumber::new(4), [0u8; 32], [0u8; 32]);

            let err = rolling_state
                .validate_transition(&preimage, &non_zero_merkle_tree_commitment_avk, &[0u8; 32])
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
        fn rejects_transition_when_last_committed_epoch_cannot_advance() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(5), EpochNumber::new(u64::MAX));
            let preimage = build_standard_preimage(EpochNumber::new(4));

            let err = rolling_state
                .validate_transition(&preimage, &avk_with_zero_root(), &[0u8; 32])
                .unwrap_err();

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind: EpochTransitionErrorKind::EpochOverflow,
                    ..
                }
            ));
        }

        #[test]
        fn rejects_out_of_range_cert_epoch() {
            let rolling_state =
                build_standard_rolling_state(StepCounter::new(5), EpochNumber::new(3));
            let preimage = build_standard_preimage(EpochNumber::new(10));

            let err = rolling_state
                .validate_transition(&preimage, &avk_with_zero_root(), &[0u8; 32])
                .unwrap_err();

            let circuit_error = err
                .downcast_ref::<IvcCircuitError>()
                .expect("error chain should carry IvcCircuitError");
            assert!(matches!(
                circuit_error,
                IvcCircuitError::InvalidEpochTransition {
                    kind: EpochTransitionErrorKind::EpochGap {
                        incoming_certificate_epoch: 10,
                        ..
                    },
                    ..
                }
            ));
        }
    }
}
