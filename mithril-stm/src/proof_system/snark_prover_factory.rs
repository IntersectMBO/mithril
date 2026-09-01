use std::fmt::Debug;

use crate::{
    MERKLE_TREE_DEPTH_FOR_SNARK, MembershipDigest, Parameters, StmResult,
    proof_system::{
        SnarkAggregateSignatureProver, SnarkProver,
        ivc_halo2_snark::{IvcChainProver, proof::IvcProver},
    },
};

/// Builds the provers needed to generate a non-recursive SNARK aggregate signature
/// and a recursive SNARK proof that the chain is valid.
#[cfg_attr(test, mockall::automock)]
pub(crate) trait SnarkProverFactory<D: MembershipDigest + Send + Sync>:
    Debug + Send + Sync
{
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
#[derive(Debug, Default)]
pub(crate) struct NonDeterministicSnarkProverFactory;

impl<D: MembershipDigest + Send + Sync> SnarkProverFactory<D>
    for NonDeterministicSnarkProverFactory
{
    fn snark_aggregate_signature_prover(
        &self,
        parameters: &Parameters,
    ) -> StmResult<Box<dyn SnarkAggregateSignatureProver<D>>> {
        Ok(Box::new(SnarkProver::try_new_non_deterministic(
            parameters,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )?))
    }

    fn ivc_chain_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcChainProver<D>>> {
        Ok(Box::new(IvcProver::try_new_non_deterministic(parameters)?))
    }
}
