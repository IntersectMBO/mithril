use std::fmt::Debug;

use crate::{
    MERKLE_TREE_DEPTH_FOR_SNARK, MembershipDigest, Parameters, StmResult,
    proof_system::{
        SnarkProver, SnarkSignatureProver,
        ivc_halo2_snark::proof::{IvcChainProver, IvcProver},
    },
};

/// Builds the provers an aggregation needs, once the aggregate signature type is known.
#[cfg_attr(test, mockall::automock)]
pub(crate) trait SnarkProverFactory<D: MembershipDigest>: Debug + Send + Sync {
    /// Builds the non-recursive prover for the certificate proof.
    fn snark_signature_prover(
        &self,
        parameters: &Parameters,
    ) -> StmResult<Box<dyn SnarkSignatureProver<D>>>;

    /// Builds the recursive prover for one IVC step.
    fn ivc_chain_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcChainProver<D>>>;
}

/// Production factory: `SnarkProver<OsRng>` and `IvcProver<OsRng>` over the trusted setup.
#[derive(Debug, Default)]
pub(crate) struct NonDeterministicSnarkProverFactory;

impl<D: MembershipDigest> SnarkProverFactory<D> for NonDeterministicSnarkProverFactory {
    fn snark_signature_prover(
        &self,
        parameters: &Parameters,
    ) -> StmResult<Box<dyn SnarkSignatureProver<D>>> {
        Ok(Box::new(SnarkProver::try_new_non_deterministic(
            parameters,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )?))
    }

    fn ivc_chain_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcChainProver<D>>> {
        Ok(Box::new(IvcProver::try_new_non_deterministic(parameters)?))
    }
}
