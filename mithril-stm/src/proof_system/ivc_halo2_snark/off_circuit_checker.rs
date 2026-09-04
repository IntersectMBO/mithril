use anyhow::anyhow;

use crate::{
    AggregationError, AncillaryProofInput, BaseFieldElement, StmResult,
    circuits::halo2_ivc::{PREIMAGE_SIZE, ProtocolMessagePreimage, types::MessageHash},
    proof_system::{
        IvcRollingState,
        ivc_halo2_snark::{
            errors::IvcProofError, interface::IvcOffCircuitChecker,
            proof::IvcGenesisBootstrapInput, prover_input_helpers::IvcTransitionType,
        },
    },
};

#[derive(Debug)]
struct RealIvcOffCircuitChecker;

impl IvcOffCircuitChecker for RealIvcOffCircuitChecker {
    fn check(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        todo!()
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

        ensure_advanceable_rolling_state(rolling_state)?;

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
        rolling_state.assert_protocol_parameters_unchanged()?;

        Ok(())
    }

    fn check_protocol_message(
        &self,
        msg: &[u8],
        aggregate_verification_key_merkle_root: &[u8],
        ancillary_input: &AncillaryProofInput,
    ) -> StmResult<()> {
        todo!()
    }
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
