use std::fmt::Debug;

use crate::{
    MERKLE_TREE_DEPTH_FOR_SNARK, MembershipDigest, Parameters, StmResult,
    proof_system::{
        SnarkAggregateSignatureProver, SnarkProver, SnarkProverSetupReuse,
        halo2_ivc_snark::{IvcChainProver, IvcProver},
    },
};

/// Builds the provers needed to generate a non-recursive SNARK aggregate signature
/// and a recursive SNARK proof that the chain is valid.
#[cfg_attr(test, mockall::automock)]
pub(crate) trait SnarkProverFactory<D: MembershipDigest>: Debug {
    /// Builds a non-recursive SNARK prover given the parameters. This prover can generate
    /// a succinct proof that a set of enough signatures are valid to reach the quorum
    /// `k` of the parameters.
    fn snark_aggregate_signature_prover(
        &self,
        parameters: &Parameters,
    ) -> StmResult<Box<dyn SnarkAggregateSignatureProver<D>>>;

    /// Builds the recursive SNARK prover that can advance one step of the chain and generate a
    /// succinct proof that the chain is valid up to and including this step.
    fn ivc_chain_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcChainProver<D>>>;
}

/// Production factory: `SnarkProver<OsRng>` and `IvcProver<OsRng>` over the trusted setup.
#[derive(Debug)]
pub(crate) struct NonDeterministicSnarkProverFactory {
    /// Whether the setups handed to the provers are reused across aggregations.
    setup_reuse: SnarkProverSetupReuse,
}

impl NonDeterministicSnarkProverFactory {
    /// Factory resolving the setups it hands to the provers through `setup_reuse`.
    pub(crate) fn new(setup_reuse: SnarkProverSetupReuse) -> Self {
        Self { setup_reuse }
    }
}

impl<D: MembershipDigest> SnarkProverFactory<D> for NonDeterministicSnarkProverFactory {
    fn snark_aggregate_signature_prover(
        &self,
        parameters: &Parameters,
    ) -> StmResult<Box<dyn SnarkAggregateSignatureProver<D>>> {
        let setup = self
            .setup_reuse
            .certificate_setup(parameters, MERKLE_TREE_DEPTH_FOR_SNARK)?;

        Ok(Box::new(SnarkProver::new_non_deterministic(setup)))
    }

    fn ivc_chain_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcChainProver<D>>> {
        let setup = self.setup_reuse.ivc_setup(parameters)?;

        Ok(Box::new(IvcProver::new_non_deterministic(setup)))
    }
}
