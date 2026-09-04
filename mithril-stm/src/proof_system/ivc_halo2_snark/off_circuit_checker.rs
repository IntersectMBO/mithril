use anyhow::anyhow;

use crate::{
    AggregationError, AncillaryProofInput, BaseFieldElement, StmResult,
    circuits::halo2_ivc::{PREIMAGE_SIZE, ProtocolMessagePreimage, types::MessageHash},
    proof_system::{
        IvcRollingState,
        ivc_halo2_snark::{
            errors::IvcProofError,
            interface::IvcOffCircuitChecker,
            proof::IvcGenesisBootstrapInput,
            prover_input_helpers::{IvcTransitionType, create_snark_message_for_next_state},
        },
    },
};

#[derive(Debug)]
pub(crate) struct RealIvcOffCircuitChecker;

impl IvcOffCircuitChecker for RealIvcOffCircuitChecker {
    fn check(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        self.check_genesis(ancillary_input)?;
        self.check_rolling_state(msg, aggregate_verification_key_merkle_root, ancillary_input)?;
        self.check_protocol_message(msg, aggregate_verification_key_merkle_root, ancillary_input)?;
        Ok(())
    }

    fn check_genesis(&self, ancillary_input: &AncillaryProofInput) -> StmResult<()> {
        let genesis_data = ancillary_input.genesis_data();

        let genesis_verifying_key = genesis_data
            .genesis_schnorr_verification_key()
            .cloned()
            .ok_or_else(|| anyhow!(AggregationError::MissingGenesisVerificationKey))?;
        genesis_verifying_key.is_valid()?;

        let genesis_message: MessageHash = genesis_data.genesis_message_preimage().try_into()?;

        let genesis_bootstrap: IvcGenesisBootstrapInput = genesis_data.try_into()?;
        genesis_bootstrap.genesis_signature.verify(
            &[BaseFieldElement::from(genesis_message.as_field())],
            &genesis_verifying_key,
        )?;
        Ok(())
    }

    fn check_rolling_state(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        let rolling_state = ancillary_input
            .prover_data()
            .and_then(|prover_data| prover_data.as_ivc_rolling_state());

        IvcRollingState::ensure_advanceable_rolling_state(rolling_state)?;

        let Some(rolling_state) = rolling_state else {
            return Ok(());
        };

        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        let transition_type =
            IvcTransitionType::try_compute_transition_type(rolling_state, &preimage)?;
        rolling_state.assert_correct_parameters(
            &preimage,
            aggregate_verification_key_merkle_root,
            msg,
            transition_type,
        )?;
        assert_protocol_parameters_unchanged(rolling_state)?;

        Ok(())
    }

    fn check_protocol_message(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        let preimage_bytes: [u8; PREIMAGE_SIZE] = ancillary_input.message_preimage().try_into()?;
        let preimage = ProtocolMessagePreimage(preimage_bytes);

        let (certificate_message_hash, _) =
            create_snark_message_for_next_state(aggregate_verification_key_merkle_root, msg)?;

        let recomputed_hash: MessageHash = (&preimage).try_into()?;
        if recomputed_hash != certificate_message_hash {
            return Err(IvcProofError::MessagePreimageMismatch.into());
        }

        Ok(())
    }
}

/// Asserts that the rolling state's protocol parameters have not diverged from their
/// lookahead value. At genesis `protocol_parameters` is zeroed while `next_protocol_parameters`
/// carries the bootstrap value, so genesis is exempt; every step after that must have the two
/// equal, since changing protocol parameters between epochs isn't currently supported.
pub(crate) fn assert_protocol_parameters_unchanged(
    rolling_state: &IvcRollingState,
) -> StmResult<()> {
    if !rolling_state.is_genesis()
        && rolling_state.state().protocol_parameters
            != rolling_state.state().next_protocol_parameters
    {
        return Err(IvcProofError::ProtocolParametersChanged.into());
    }
    Ok(())
}
