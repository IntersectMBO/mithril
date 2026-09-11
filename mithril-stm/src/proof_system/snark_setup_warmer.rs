//! Ahead-of-time materialization of the SNARK prover setups.
//!
//! A node materializes its prover setup on the first aggregation it runs, which is the longest part
//! of a cold start and lands inside a signing round. [`SnarkProverSetupWarmer`] does it beforehand,
//! into the same process-wide cache the provers read, so the first aggregation finds it ready.

use crate::{
    AggregateSignatureType, MERKLE_TREE_DEPTH_FOR_SNARK, Parameters, StmResult,
    proof_system::snark_setup_cache::SnarkProverSetupReuse,
};

/// Materializes the SNARK prover setups a node needs, ahead of its first aggregation.
pub struct SnarkProverSetupWarmer;

impl SnarkProverSetupWarmer {
    /// Materializes the setups `aggregate_signature_type` needs for `parameters` into the cache the
    /// provers read, deriving and storing their keys on a miss. Nothing to materialize for a
    /// concatenation aggregate signature.
    ///
    /// The setups are kept resident, since the process calling this is the one that will aggregate.
    pub fn warm(
        parameters: &Parameters,
        aggregate_signature_type: AggregateSignatureType,
    ) -> StmResult<()> {
        match aggregate_signature_type {
            AggregateSignatureType::Concatenation => (),
            AggregateSignatureType::Snark => {
                SnarkProverSetupReuse::Enabled
                    .certificate_setup(parameters, MERKLE_TREE_DEPTH_FOR_SNARK)?;
            }
            AggregateSignatureType::IvcSnark => {
                SnarkProverSetupReuse::Enabled.ivc_setup(parameters)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concatenation_has_no_setup_to_derive() {
        let parameters = Parameters {
            m: 9,
            k: 5,
            phi_f: 0.95,
        };

        SnarkProverSetupWarmer::warm(&parameters, AggregateSignatureType::Concatenation).unwrap();
    }
}
