use kimchi::{
    circuits::{
        gate::CircuitGate,
        lookup::{
            runtime_tables::{RuntimeTable, RuntimeTableCfg},
            tables::LookupTable,
        },
        wires::{COLUMNS, PERMUTS},
        witness::{self, Variables},
        polynomials::{and, xor::{num_xors, layout}},
    },
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    proof::{ProverProof, RecursionChallenge},
    prover_index::{testing::new_index_for_test_with_lookups, ProverIndex},
    verifier::verify,
    verifier_index::VerifierIndex,
    variable_map,
};
use ark_ff::{PrimeField, SquareRootField, Zero};
use ark_poly::{EvaluationDomain};
use kimchi::groupmap::GroupMap;
use mina_poseidon::sponge::FqSponge;
use poly_commitment::commitment::CommitmentCurve;
use std::{fmt::Write, mem, time::Instant};
use num_bigint::BigUint;
use o1_utils::{BigUintFieldHelpers, BigUintHelpers, BitwiseOps, FieldHelpers, Two};
use std::array;

#[derive(Default, Clone)]
pub(crate) struct FuzzFramework<G: KimchiCurve> {
    gates: Option<Vec<CircuitGate<G::ScalarField>>>,
    witness: Option<[Vec<G::ScalarField>; COLUMNS]>,
    public_inputs: Vec<G::ScalarField>,
    lookup_tables: Vec<LookupTable<G::ScalarField>>,
    runtime_tables_setup: Option<Vec<RuntimeTableCfg<G::ScalarField>>>,
    runtime_tables: Vec<RuntimeTable<G::ScalarField>>,
    recursion: Vec<RecursionChallenge<G>>,
    num_prev_challenges: usize,
    disable_gates_checks: bool,

    prover_index: Option<ProverIndex<G>>,
    verifier_index: Option<VerifierIndex<G>>,
}

#[derive(Clone)]
pub(crate) struct FuzzRunner<G: KimchiCurve>(FuzzFramework<G>);

impl<G: KimchiCurve> FuzzFramework<G>
where
    G::BaseField: PrimeField,
    G::ScalarField: PrimeField,
{
    #[must_use]
    pub(crate) fn gates(mut self, gates: Vec<CircuitGate<G::ScalarField>>) -> Self {
        self.gates = Some(gates);
        self
    }

    #[must_use]
    pub(crate) fn witness(mut self, witness: [Vec<G::ScalarField>; COLUMNS]) -> Self {
        self.witness = Some(witness);
        self
    }

    #[must_use]
    pub(crate) fn public_inputs(mut self, public_inputs: Vec<G::ScalarField>) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    #[must_use]
    pub(crate) fn num_prev_challenges(mut self, num_prev_challenges: usize) -> Self {
        self.num_prev_challenges = num_prev_challenges;
        self
    }

    #[must_use]
    pub(crate) fn lookup_tables(mut self, lookup_tables: Vec<LookupTable<G::ScalarField>>) -> Self {
        self.lookup_tables = lookup_tables;
        self
    }

    #[must_use]
    pub(crate) fn runtime_tables_setup(
        mut self,
        runtime_tables_setup: Vec<RuntimeTableCfg<G::ScalarField>>,
    ) -> Self {
        self.runtime_tables_setup = Some(runtime_tables_setup);
        self
    }

    #[must_use]
    pub(crate) fn disable_gates_checks(mut self, disable_gates_checks: bool) -> Self {
        self.disable_gates_checks = disable_gates_checks;
        self
    }

    /// creates the indexes
    #[must_use]
    pub(crate) fn setup(mut self) -> FuzzRunner<G> {
        let start = Instant::now();

        let lookup_tables = std::mem::take(&mut self.lookup_tables);
        let runtime_tables_setup = mem::replace(&mut self.runtime_tables_setup, None);

        let index = new_index_for_test_with_lookups::<G>(
            self.gates.take().unwrap(),
            self.public_inputs.len(),
            self.num_prev_challenges,
            lookup_tables,
            runtime_tables_setup,
            self.disable_gates_checks,
        );
        println!(
            "- time to create prover index: {:?}s",
            start.elapsed().as_secs()
        );

        self.verifier_index = Some(index.verifier_index());
        self.prover_index = Some(index);

        FuzzRunner(self)
    }
}

impl<G: KimchiCurve> FuzzRunner<G>
where
    G::ScalarField: PrimeField + Clone,
    G::BaseField: PrimeField + Clone,
{
    #[must_use]
    pub(crate) fn runtime_tables(
        mut self,
        runtime_tables: Vec<RuntimeTable<G::ScalarField>>,
    ) -> Self {
        self.0.runtime_tables = runtime_tables;
        self
    }

    #[must_use]
    pub(crate) fn recursion(mut self, recursion: Vec<RecursionChallenge<G>>) -> Self {
        self.0.recursion = recursion;
        self
    }

    #[must_use]
    pub(crate) fn witness(mut self, witness: [Vec<G::ScalarField>; COLUMNS]) -> Self {
        self.0.witness = Some(witness);
        self
    }

    pub(crate) fn prover_index(&self) -> &ProverIndex<G> {
        self.0.prover_index.as_ref().unwrap()
    }

    /// Create and verify a proof
    pub(crate) fn prove_and_verify<EFqSponge, EFrSponge>(self) -> Result<(), String>
    where
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    {
        let prover = self.0.prover_index.unwrap();
        let mut witness= self.0.witness.unwrap();

        let pad = vec![G::ScalarField::zero(); prover.cs.domain.d1.size() - witness[0].len()];
        let mut witness = array::from_fn(|i| {
            let mut w = witness[i].to_vec();
            w.extend_from_slice(&pad);
            w
        });

        for (row, gate) in prover.cs.gates.iter().enumerate() {
            // check if wires are connected
            for col in 0..PERMUTS {
                let wire = gate.wires[col];

                if wire.col >= PERMUTS {
                    println!("aaaasdfghjjdfhsgcgvbjecvof");
                }
                if witness[col][row] != witness[wire.col][wire.row] {
                    witness[col][row] = witness[wire.col][wire.row]
                    
                }
            }
        }

        // add the proof to the batch
        let start = Instant::now();

        let group_map = <G as CommitmentCurve>::Map::setup();

        let proof = ProverProof::create_recursive::<EFqSponge, EFrSponge>(
            &group_map,
            witness,
            &self.0.runtime_tables,
            &prover,
            self.0.recursion,
            None,
        )
        .map_err(|e| e.to_string())?;
        println!("- time to create proof: {:?}s", start.elapsed().as_secs());

        // verify the proof (propagate any errors)
        let start = Instant::now();
        verify::<G, EFqSponge, EFrSponge>(
            &group_map,
            &self.0.verifier_index.unwrap(),
            &proof,
            &self.0.public_inputs,
        )
        .map_err(|e| e.to_string())?;
        println!("- time to verify: {}ms", start.elapsed().as_millis());

        Ok(())
    }
}

pub fn print_witness<F>(cols: &[Vec<F>; COLUMNS], start_row: usize, end_row: usize)
where
    F: PrimeField,
{
    let rows = cols[0].len();
    if start_row > rows || end_row > rows {
        panic!("start_row and end_row are supposed to be in [0, {rows}]");
    }

    for row in start_row..end_row {
        let mut line = "| ".to_string();
        for col in cols {
            let bigint: BigUint = col[row].into();
            write!(line, "{bigint} | ").unwrap();
        }
    }
}


/// Create a random witness for inputs as field elements starting at row 0
/// Input: first input, second input, and desired byte length
/// Panics if the input is too large for the chosen number of bytes
pub fn create_and_witness<F: PrimeField>(input1: F, input2: F, bytes: usize) -> [Vec<F>; COLUMNS] {
    let input1_big = input1.to_biguint();
    let input2_big = input2.to_biguint();
    if bytes * 8 < input1_big.bitlen() || bytes * 8 < input2_big.bitlen() {
        panic!("Bytes must be greater or equal than the inputs length");
    }

    // Compute BigUint output of AND, XOR
    let big_and = BigUint::bitwise_and(&input1_big, &input2_big, bytes);
    let big_xor = BigUint::bitwise_xor(&input1_big, &input2_big);
    // Transform BigUint values to field elements
    let xor = big_xor.to_field().unwrap();
    let and = big_and.to_field().unwrap();
    let sum = input1 + input2;

    let and_row = num_xors(bytes * 8) + 1;
    let mut and_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); and_row + 1]);

    init_xor(&mut and_witness, 0, bytes * 8, (input1, input2, xor));
    // Fill in double generic witness
    and_witness[0][and_row] = input1;
    and_witness[1][and_row] = input2;
    and_witness[2][and_row] = sum;
    and_witness[3][and_row] = sum;
    and_witness[4][and_row] = xor;
    and_witness[5][and_row] = and;

    and_witness
}
// pub fn create_xor_witness<F: PrimeField>(input1: F, input2: F, bits: usize) -> [Vec<F>; COLUMNS] {
   
//     let output = BigUint::bitwise_xor(&input1_big, &input2_big);

//     let mut xor_witness: [Vec<F>; COLUMNS] =
//         array::from_fn(|_| vec![F::zero(); 1 + num_xors(bits)]);

//     init_xor(
//         &mut xor_witness,
//         0,
//         bits,
//         (input1, input2, output.to_field().unwrap()),
//     );

//     xor_witness
// }

pub fn init_xor<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    curr_row: usize,
    bits: usize,
    words: (F, F, F),
) {
    let xor_rows = layout(curr_row, bits);

    witness::init(
        witness,
        curr_row,
        &xor_rows,
        &variable_map!["in1" => words.0, "in2" => words.1, "out" => words.2],
    )
}
