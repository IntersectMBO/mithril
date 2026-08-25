//! Classifies `MockProver` failures by the public-statement rows they implicate.
//!
//! The circuit binds every element of its public statement with a copy constraint, so a tampered
//! element fails as a permutation on the public-statement instance column at that element's row.
//! Advice-side members of a broken class are not enumerated: their columns and regions are named by
//! the gadget layer and carry no stability guarantee.

use std::collections::{BTreeMap, BTreeSet};

use midnight_proofs::{
    dev::{FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Circuit},
};

use crate::circuits::halo2_ivc::{NativeField, circuit::IvcCircuitData};

/// Index of the instance column carrying the circuit's public statement.
///
/// Column zero is the committed-instance column, which this circuit leaves empty.
pub(crate) const PUBLIC_STATEMENT_INSTANCE_COLUMN: usize = 1;

/// Mutates the public input at `row` by a nonzero, row-dependent delta.
///
/// Adding rather than assigning keeps the mutation effective whatever the original value. The delta
/// varies by row so two tampered cells in one permutation class cannot stay equal to each other,
/// which would let the cycle check report neither.
pub(crate) fn mutate_public_input(public_inputs: &mut [NativeField], row: usize) {
    public_inputs[row] += NativeField::from(row as u64 + 1);
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
/// Public-statement cells sit outside any region, so their failures carry an absolute row.
fn public_statement_row(failure: &VerifyFailure) -> Option<usize> {
    match failure {
        VerifyFailure::Permutation {
            location: FailureLocation::OutsideRegion { row },
            ..
        } if is_public_statement_failure(failure) => Some(*row),
        _ => None,
    }
}

/// Runs `MockProver` on any circuit and compares the resulting failure signature against
/// `expected_rows`, returning the diagnostic when they disagree.
///
/// `expected_rows` maps each row to the field name used in diagnostics. The circuit must reject,
/// every returned failure must be a permutation failure, and every public-statement failure must
/// carry an absolute row.
///
/// An exact row set does not prove each row carries the field named for it: dropping one
/// public-input assignment shifts every later binding while all expected rows still fail, and two
/// fields with equal honest values can swap invisibly.
fn check_public_input_row_signature<C: Circuit<NativeField>>(
    circuit: &C,
    instances: Vec<Vec<NativeField>>,
    expected_rows: &BTreeMap<usize, &str>,
) -> Result<(), String> {
    let prover = MockProver::run(circuit, instances).expect("MockProver setup should succeed");
    let Err(failures) = prover.verify() else {
        return Err("the circuit should reject the provided circuit and instances".to_string());
    };

    let unexpected_classes: Vec<String> = failures
        .iter()
        .filter(|failure| !matches!(failure, VerifyFailure::Permutation { .. }))
        .map(|failure| format!("{failure:?}"))
        .collect();
    if !unexpected_classes.is_empty() {
        return Err(format!(
            "every failure should be a permutation failure, since the public statement is bound by \
             copy constraints; got {} of another class:\n{}",
            unexpected_classes.len(),
            unexpected_classes.join("\n")
        ));
    }

    // A row-less public-statement failure would otherwise be dropped, letting an empty expected
    // signature pass on a circuit that had broken a binding.
    let unlocatable: Vec<String> = failures
        .iter()
        .filter(|failure| {
            is_public_statement_failure(failure) && public_statement_row(failure).is_none()
        })
        .map(|failure| format!("{failure:?}"))
        .collect();
    if !unlocatable.is_empty() {
        return Err(format!(
            "every public-statement failure should carry an absolute row; got {} that did not:\n{}",
            unlocatable.len(),
            unlocatable.join("\n")
        ));
    }

    let observed: BTreeSet<usize> = failures.iter().filter_map(public_statement_row).collect();
    let expected: BTreeSet<usize> = expected_rows.keys().copied().collect();
    if observed == expected {
        return Ok(());
    }
    let describe = |rows: &BTreeSet<usize>| {
        rows.iter()
            .map(|row| match expected_rows.get(row) {
                Some(name) => format!("{row} ({name})"),
                None => format!("{row} (not expected to fail)"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(format!(
        "public-input failure signature mismatch\n  failed:   [{}]\n  expected: [{}]",
        describe(&observed),
        describe(&expected)
    ))
}

/// Asserts the failure signature matches, panicking with the diagnostic when it does not.
pub(crate) fn assert_circuit_rejects_public_input_rows<C: Circuit<NativeField>>(
    circuit: &C,
    instances: Vec<Vec<NativeField>>,
    expected_rows: &BTreeMap<usize, &str>,
) {
    if let Err(diagnostic) = check_public_input_row_signature(circuit, instances, expected_rows) {
        panic!("{diagnostic}");
    }
}

/// Recursive-circuit wrapper over [`assert_circuit_rejects_public_input_rows`].
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
        plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Instance, Selector},
        poly::Rotation,
    };

    use super::*;

    /// Advice values assigned by the minimal circuit. The third is bound to the committed column.
    const MINIMAL_CIRCUIT_VALUES: [u64; 3] = [10, 20, 30];

    /// Public-statement row left deliberately unbound by the minimal circuit.
    const UNBOUND_PUBLIC_STATEMENT_ROW: usize = 2;

    /// Value assigned by the gate-failure circuit, which its gate requires to be zero.
    const GATE_FAILURE_VALUE: u64 = 5;

    #[derive(Clone)]
    struct MinimalConfig {
        advice: Column<Advice>,
        committed_instance: Column<Instance>,
        public_statement_instance: Column<Instance>,
    }

    /// Smallest circuit reproducing the two-instance-column shape of the recursive circuit.
    ///
    /// Two public-statement inputs are bound, one is left unbound, and a third cell is bound to the
    /// committed column, so both the row and column filters are exercised.
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

    #[derive(Clone)]
    struct GateFailureConfig {
        advice: Column<Advice>,
        selector: Selector,
        public_statement_instance: Column<Instance>,
    }

    /// Circuit whose only fault is an unsatisfied gate, with its public statement left consistent.
    ///
    /// The helper permits permutation failures alone, so this is what proves that rule is enforced.
    struct GateFailureCircuit;

    impl Circuit<NativeField> for GateFailureCircuit {
        type Config = GateFailureConfig;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self
        }

        fn configure(meta: &mut ConstraintSystem<NativeField>) -> Self::Config {
            let advice = meta.advice_column();
            let selector = meta.selector();
            // Declared first so the public statement lands in column one, as the recursive circuit does.
            let _committed_instance = meta.instance_column();
            let public_statement_instance = meta.instance_column();
            meta.enable_equality(advice);
            meta.enable_equality(public_statement_instance);
            meta.create_gate("the assigned value must be zero", |meta| {
                let value = meta.query_advice(advice, Rotation::cur());
                Constraints::with_selector(selector, vec![value])
            });
            GateFailureConfig {
                advice,
                selector,
                public_statement_instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<NativeField>,
        ) -> Result<(), Error> {
            let cell = layouter.assign_region(
                || "value",
                |mut region| {
                    config.selector.enable(&mut region, 0)?;
                    region.assign_advice(
                        || "value",
                        config.advice,
                        0,
                        || Value::known(NativeField::from(GATE_FAILURE_VALUE)),
                    )
                },
            )?;
            layouter.constrain_instance(cell.cell(), config.public_statement_instance, 0)
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
    fn mutation_gives_equal_valued_rows_distinct_nonzero_deltas() {
        // Equal-valued rows in one permutation class would mask each other under a shared delta.
        const SHARED: u64 = 7;
        let mut public_inputs = vec![NativeField::from(SHARED); 4];
        for row in 0..public_inputs.len() {
            mutate_public_input(&mut public_inputs, row);
        }

        assert!(
            public_inputs.iter().all(|value| *value != NativeField::from(SHARED)),
            "every mutation must change its row"
        );
        assert_eq!(
            public_inputs.iter().copied().collect::<BTreeSet<_>>().len(),
            public_inputs.len(),
            "rows that started equal must end distinct"
        );
    }

    #[test]
    fn minimal_circuit_accepts_honest_instances() {
        // Guards the cases below: a helper that always found failures would look correct.
        let prover = MockProver::run(&MinimalCircuit, honest_minimal_instances())
            .expect("MockProver setup should succeed");
        prover
            .verify()
            .expect("the minimal circuit should accept its honest instances");
    }

    #[test]
    fn helper_reports_bound_public_statement_rows_only() {
        let mut instances = honest_minimal_instances();
        // Only the bound public-statement rows may be reported.
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
        // A break confined to the committed column implicates no public-statement row.
        let mut instances = honest_minimal_instances();
        mutate_public_input(&mut instances[0], 0);

        assert_circuit_rejects_public_input_rows(&MinimalCircuit, instances, &BTreeMap::new());
    }

    #[test]
    fn helper_rejects_a_non_permutation_failure() {
        // The public statement matches, so the unsatisfied gate is the only fault and the helper
        // must surface it rather than report an empty row set.
        let diagnostic = check_public_input_row_signature(
            &GateFailureCircuit,
            vec![vec![], vec![NativeField::from(GATE_FAILURE_VALUE)]],
            &BTreeMap::new(),
        )
        .expect_err("a gate failure is not a permitted failure class");

        assert!(
            diagnostic.contains("every failure should be a permutation failure"),
            "{diagnostic}"
        );
    }

    #[test]
    fn helper_rejects_an_incomplete_expected_signature() {
        // Two rows fail, so expecting one must not pass.
        let mut instances = honest_minimal_instances();
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 0);
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 1);

        let diagnostic = check_public_input_row_signature(
            &MinimalCircuit,
            instances,
            &BTreeMap::from([(0, "first bound input")]),
        )
        .expect_err("a row that failed unexpectedly should be reported");

        assert!(
            diagnostic.contains("public-input failure signature mismatch"),
            "{diagnostic}"
        );
    }

    #[test]
    fn helper_rejects_an_empty_signature_when_a_row_did_fail() {
        // An empty expectation must not absorb a real public-statement failure.
        let mut instances = honest_minimal_instances();
        mutate_public_input(&mut instances[PUBLIC_STATEMENT_INSTANCE_COLUMN], 0);

        let diagnostic =
            check_public_input_row_signature(&MinimalCircuit, instances, &BTreeMap::new())
                .expect_err("a bound row that failed should be reported");

        assert!(
            diagnostic.contains("public-input failure signature mismatch"),
            "{diagnostic}"
        );
    }
}
