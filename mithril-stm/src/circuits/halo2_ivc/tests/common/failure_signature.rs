//! Classifies `MockProver` failures by the public-statement rows they implicate.
//!
//! A negative test that asserts only `verify().is_err()` can pass for the wrong reason. The
//! recursive circuit binds every element of its public statement with a copy constraint, so a
//! tampered element surfaces as a [`VerifyFailure::Permutation`] on the public-statement instance
//! column at that element's row. Asserting the exact set of those rows turns "something failed"
//! into "these public inputs, and only these, stopped being satisfiable".
//!
//! The contract is deliberately two-sided: an **exact** public-statement row signature, plus a
//! **permitted failure class** for everything else. Advice-side members of a broken permutation
//! class are constrained by class and never enumerated, because the columns and regions they name
//! belong to the gadget layer and carry no stability guarantee.
//!
//! An internal copy constraint can still implicate a named public row, when its equality class also
//! contains an instance-bound cell. The state message and its preimage hash are joined that way, so
//! corrupting only the witness preimage legitimately yields an exact public-row signature.

use std::collections::{BTreeMap, BTreeSet};

use ff::Field;
use midnight_proofs::{
    dev::{FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Circuit},
};

use crate::circuits::halo2_ivc::{NativeField, circuit::IvcCircuitData};

/// Index of the instance column carrying the circuit's public statement.
///
/// The recursive circuit declares the committed-instance column first and leaves it empty, so the
/// public statement lands in the second column. Filtering on this index is what keeps a failure in
/// the committed column from being mistaken for a public-statement failure.
pub(crate) const PUBLIC_STATEMENT_INSTANCE_COLUMN: usize = 1;

/// Mutates the public input at `row` by a guaranteed nonzero delta.
///
/// Adding one rather than assigning a fixed value keeps the mutation effective whatever the
/// original held: assigning `ONE` is a no-op wherever the honest value already is one, as the
/// genesis step counter is.
pub(crate) fn mutate_public_input(public_inputs: &mut [NativeField], row: usize) {
    public_inputs[row] += NativeField::ONE;
}

/// True when `failure` is a permutation failure on the public-statement column.
fn is_public_statement_failure(failure: &VerifyFailure) -> bool {
    matches!(
        failure,
        VerifyFailure::Permutation { column, .. }
            if column.column_type() == Any::Instance
                && column.index() == PUBLIC_STATEMENT_INSTANCE_COLUMN
    )
}

/// Returns the public-statement row implicated by `failure`, if it implicates one.
///
/// Public-statement cells are assigned outside any region, so their failures carry an absolute row.
fn public_statement_row(failure: &VerifyFailure) -> Option<usize> {
    match failure {
        VerifyFailure::Permutation {
            location: FailureLocation::OutsideRegion { row },
            ..
        } if is_public_statement_failure(failure) => Some(*row),
        _ => None,
    }
}

/// Runs `MockProver` on any circuit, requires rejection, and asserts that the public-statement rows
/// implicated are exactly the keys of `expected_rows`.
///
/// `expected_rows` maps each expected row to the field name reported in diagnostics; rows that fail
/// unexpectedly are reported by index, since a generic circuit has no field names to resolve them
/// against. Every returned failure must be a permutation failure, and every permutation failure on
/// the public-statement column must carry an absolute row — anything else means the circuit rejected
/// in a way this helper cannot account for, and is surfaced rather than dropped.
pub(crate) fn assert_circuit_rejects_public_input_rows<C: Circuit<NativeField>>(
    circuit: &C,
    instances: Vec<Vec<NativeField>>,
    expected_rows: &BTreeMap<usize, &str>,
) {
    let prover = MockProver::run(circuit, instances).expect("MockProver setup should succeed");
    let failures = prover
        .verify()
        .expect_err("the circuit should reject the provided circuit and instances");

    let unexpected_classes: Vec<String> = failures
        .iter()
        .filter(|failure| !matches!(failure, VerifyFailure::Permutation { .. }))
        .map(|failure| format!("{failure:?}"))
        .collect();
    assert!(
        unexpected_classes.is_empty(),
        "every failure should be a permutation failure, since the public statement is bound by \
         copy constraints; got {} of another class:\n{}",
        unexpected_classes.len(),
        unexpected_classes.join("\n")
    );

    // Without this, a public-statement failure reported against a region would be dropped by
    // `public_statement_row` and an empty expected signature would pass on a circuit that had in
    // fact broken a public-input binding.
    let unlocatable: Vec<String> = failures
        .iter()
        .filter(|failure| {
            is_public_statement_failure(failure) && public_statement_row(failure).is_none()
        })
        .map(|failure| format!("{failure:?}"))
        .collect();
    assert!(
        unlocatable.is_empty(),
        "every public-statement failure should carry an absolute row; got {} that did not:\n{}",
        unlocatable.len(),
        unlocatable.join("\n")
    );

    let observed: BTreeSet<usize> = failures.iter().filter_map(public_statement_row).collect();
    let expected: BTreeSet<usize> = expected_rows.keys().copied().collect();
    let describe = |rows: &BTreeSet<usize>| {
        rows.iter()
            .map(|row| match expected_rows.get(row) {
                Some(name) => format!("{row} ({name})"),
                None => format!("{row} (not expected to fail)"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    assert_eq!(
        observed,
        expected,
        "public-input failure signature mismatch\n  failed:   [{}]\n  expected: [{}]",
        describe(&observed),
        describe(&expected)
    );
}

/// Recursive-circuit wrapper over [`assert_circuit_rejects_public_input_rows`].
///
/// The empty first column is the committed-instance column the circuit declares and never uses.
pub(crate) fn assert_recursive_mock_prover_rejects_public_input_rows(
    ivc_circuit_data: IvcCircuitData,
    public_inputs: Vec<NativeField>,
    expected_rows: &BTreeMap<usize, &str>,
) {
    assert_circuit_rejects_public_input_rows(
        &ivc_circuit_data,
        vec![vec![], public_inputs],
        expected_rows,
    );
}

#[cfg(test)]
mod tests {
    use midnight_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Column, ConstraintSystem, Error, Instance},
    };

    use super::*;

    /// Advice values assigned by the minimal circuit. The third is bound to the committed column.
    const MINIMAL_CIRCUIT_VALUES: [u64; 3] = [10, 20, 30];

    /// Public-statement row left deliberately unbound by the minimal circuit.
    const UNBOUND_PUBLIC_STATEMENT_ROW: usize = 2;

    #[derive(Clone)]
    struct MinimalConfig {
        advice: Column<Advice>,
        committed_instance: Column<Instance>,
        public_statement_instance: Column<Instance>,
    }

    /// Smallest circuit that reproduces the two-instance-column shape of the recursive circuit.
    ///
    /// Two of its public-statement inputs are bound by copy constraints, one is left unbound, and a
    /// third cell is bound to the committed column. That is exactly the discrimination the helper
    /// claims: it must report the bound public-statement rows, and neither the unbound row nor the
    /// committed-column failure.
    struct MinimalCircuit;

    impl Circuit<NativeField> for MinimalCircuit {
        type Config = MinimalConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self
        }

        fn configure(meta: &mut ConstraintSystem<NativeField>) -> Self::Config {
            let advice = meta.advice_column();
            // Declaration order mirrors the recursive circuit: committed column first.
            let committed_instance = meta.instance_column();
            let public_statement_instance = meta.instance_column();
            meta.enable_equality(advice);
            meta.enable_equality(committed_instance);
            meta.enable_equality(public_statement_instance);
            MinimalConfig {
                advice,
                committed_instance,
                public_statement_instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<NativeField>,
        ) -> Result<(), Error> {
            let cells = layouter.assign_region(
                || "values",
                |mut region| {
                    let mut assigned = Vec::with_capacity(MINIMAL_CIRCUIT_VALUES.len());
                    for (offset, value) in MINIMAL_CIRCUIT_VALUES.iter().enumerate() {
                        assigned.push(region.assign_advice(
                            || "value",
                            config.advice,
                            offset,
                            || Value::known(NativeField::from(*value)),
                        )?);
                    }
                    Ok(assigned)
                },
            )?;
            layouter.constrain_instance(cells[0].cell(), config.public_statement_instance, 0)?;
            layouter.constrain_instance(cells[1].cell(), config.public_statement_instance, 1)?;
            layouter.constrain_instance(cells[2].cell(), config.committed_instance, 0)
        }
    }

    /// `[committed, public statement]` instances satisfying the minimal circuit.
    fn honest_minimal_instances() -> Vec<Vec<NativeField>> {
        vec![
            vec![NativeField::from(MINIMAL_CIRCUIT_VALUES[2])],
            vec![
                NativeField::from(MINIMAL_CIRCUIT_VALUES[0]),
                NativeField::from(MINIMAL_CIRCUIT_VALUES[1]),
                // Unbound row: any value satisfies the circuit.
                NativeField::from(777u64),
            ],
        ]
    }

    #[test]
    fn minimal_circuit_accepts_honest_instances() {
        // Canary: without it, a helper that always found failures would look correct.
        let prover = MockProver::run(&MinimalCircuit, honest_minimal_instances())
            .expect("MockProver setup should succeed");
        prover
            .verify()
            .expect("the minimal circuit should accept its honest instances");
    }

    #[test]
    fn helper_reports_bound_public_statement_rows_only() {
        let mut instances = honest_minimal_instances();
        // Tamper every kind of row at once: both bound public-statement rows, the unbound one, and
        // the committed column. Only the bound public-statement rows may be reported.
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 0);
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 1);
        mutate_public_input(
            &mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN],
            UNBOUND_PUBLIC_STATEMENT_ROW,
        );
        mutate_public_input(&mut instances[0], 0);

        assert_circuit_rejects_public_input_rows(
            &MinimalCircuit,
            instances,
            &BTreeMap::from([(0, "first bound input"), (1, "second bound input")]),
        );
    }

    #[test]
    fn helper_accepts_rejection_with_an_empty_expected_signature() {
        // A break confined to the committed column implicates no public-statement row, so the
        // helper must report an empty signature rather than treating rejection alone as a match.
        let mut instances = honest_minimal_instances();
        mutate_public_input(&mut instances[0], 0);

        assert_circuit_rejects_public_input_rows(&MinimalCircuit, instances, &BTreeMap::new());
    }

    #[test]
    #[should_panic(expected = "public-input failure signature mismatch")]
    fn helper_rejects_an_incomplete_expected_signature() {
        // Proves the assertion has teeth: two rows fail, so expecting one must not pass.
        let mut instances = honest_minimal_instances();
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 0);
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 1);

        assert_circuit_rejects_public_input_rows(
            &MinimalCircuit,
            instances,
            &BTreeMap::from([(0, "first bound input")]),
        );
    }

    #[test]
    #[should_panic(expected = "public-input failure signature mismatch")]
    fn helper_rejects_an_empty_signature_when_a_row_did_fail() {
        // The counterpart to the empty-signature case above: an empty expectation must not absorb a
        // real public-statement failure.
        let mut instances = honest_minimal_instances();
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 0);

        assert_circuit_rejects_public_input_rows(&MinimalCircuit, instances, &BTreeMap::new());
    }
}
