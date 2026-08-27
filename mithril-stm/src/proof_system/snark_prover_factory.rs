use std::fmt::Debug;

use crate::{
    MERKLE_TREE_DEPTH_FOR_SNARK, Parameters, StmResult,
    proof_system::{
        CertificateProver, SnarkProver,
        ivc_halo2_snark::proof::{IvcProver, IvcStepProver},
    },
};

/// Builds the provers an aggregation needs, once the aggregate signature type is known.
#[cfg_attr(test, mockall::automock)]
pub(crate) trait SnarkProverFactory: Debug + Send + Sync {
    /// Builds the non-recursive prover for the certificate proof.
    fn certificate_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn CertificateProver>>;

    /// Builds the recursive prover for one IVC step.
    fn ivc_step_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcStepProver>>;
}

/// Production factory: `SnarkProver<OsRng>` and `IvcProver<OsRng>` over the trusted setup.
#[derive(Debug, Default)]
pub(crate) struct NonDeterministicSnarkProverFactory;

impl SnarkProverFactory for NonDeterministicSnarkProverFactory {
    fn certificate_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn CertificateProver>> {
        Ok(Box::new(SnarkProver::try_new_non_deterministic(
            parameters,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )?))
    }

    fn ivc_step_prover(&self, parameters: &Parameters) -> StmResult<Box<dyn IvcStepProver>> {
        Ok(Box::new(IvcProver::try_new_non_deterministic(parameters)?))
    }
}
