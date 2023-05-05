#[macro_use]
extern crate honggfuzz;

use kimchi::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        lookup::{runtime_tables::{RuntimeTableCfg,  RuntimeTable, RuntimeTableSpec}, tables::LookupTable},
        polynomial::COLUMNS,
        polynomials::{
            and, 
            xor, 
            not,
            rot::{self, RotMode}, 
            generic::{GenericGateSpec, testing::{create_circuit, fill_in_witness}}},
        wires::Wire,
    },
    prover_index::{testing::new_index_for_test_with_lookups, ProverIndex},
    proof::{ProverProof, RecursionChallenge},
    verifier::verify,
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    groupmap::GroupMap,
};
mod fuzz_utils;
use fuzz_utils::FuzzFramework;
use ark_ec::AffineCurve;
use ark_ff::{Field, One, PrimeField, Zero, SquareRootField};
use ark_std::cmp::min;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use ark_std::UniformRand;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::BigUint;
use o1_utils::{BitwiseOps, FieldHelpers, RandomField, math};
use rand::{rngs::StdRng, SeedableRng};
use poly_commitment::commitment::{CommitmentCurve, PolyComm};
use poly_commitment::commitment::b_poly_coefficients;
use std::{fmt::Write, mem, time::Instant};
use std::array;

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn main() {
    loop {
        fuzz!(|data: [u8; 32]| {
            // Create inputs
            let rng = &mut StdRng::from_seed(data);
            // Try uncomenting this to test with random bytes number
            // let bytes = fuzz_utils::create_random_bytes_number(data[1])
            let bytes = 8;
            let vinput1: <Vesta as AffineCurve>::ScalarField = rng.gen(None, Some(bytes * 8));
            let vinput2: <Vesta as AffineCurve>::ScalarField = rng.gen(None, Some(bytes * 8));
            let pinput1: <Pallas as AffineCurve>::ScalarField = rng.gen(None, Some(bytes * 8));
            let pinput2: <Pallas as AffineCurve>::ScalarField = rng.gen(None, Some(bytes * 8));
            let vshort_input1: <Vesta as AffineCurve>::ScalarField = rng.gen(None, Some(bytes ));
            let vshort_input2: <Vesta as AffineCurve>::ScalarField = rng.gen(None, Some(bytes ));
            let pshort_input1: <Pallas as AffineCurve>::ScalarField = rng.gen(None, Some(bytes ));
            let pshort_input2: <Pallas as AffineCurve>::ScalarField = rng.gen(None, Some(bytes ));
            prove_and_verify_and::<Vesta, VestaBaseSponge, VestaScalarSponge>(bytes, vinput1.clone(), vinput2.clone());
            prove_and_verify_and::<Pallas, PallasBaseSponge, PallasScalarSponge>(bytes, pinput1.clone(), pinput2.clone());
            test_prove_and_verify_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(bytes, vshort_input1.clone(), vshort_input2.clone());
            test_prove_and_verify_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(bytes, pshort_input1.clone(), pshort_input2.clone());
            // This couple test fail with an unwrap in an DisconnectedWires error,
            // it follows the same structure as test_prove_and_verify_not_xor in kimchi/src/test/not uncomment and investigate
            // test_prove_and_verify_not_xor::<Vesta, VestaBaseSponge, VestaScalarSponge>(bytes, rng.gen_field_with_bits(bytes));
            // test_prove_and_verify_not_xor::<Pallas, PallasBaseSponge, PallasScalarSponge>(bytes, rng.gen_field_with_bits(bytes));
            prove_and_verify_rot::<Vesta, VestaBaseSponge, VestaScalarSponge>(8, data[1] as u64);
            prove_and_verify_rot::<Pallas, PallasBaseSponge, PallasScalarSponge>(8, data[1] as u64);
        });
    }
}

// Function to create a prover and verifier to test the AND circuit
fn prove_and_verify_and<G: KimchiCurve, EFqSponge, EFrSponge>(bytes: usize, input1: G::ScalarField , input2: G::ScalarField )
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{

    // Create
    let mut gates = vec![];
    let _next_row = CircuitGate::<G::ScalarField>::extend_and(&mut gates, bytes);

    // Create witness
    let witness = and::create_and_witness(input1, input1, bytes);

    FuzzFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .unwrap()

}

fn test_prove_and_verify_xor<G: KimchiCurve, EFqSponge, EFrSponge>(bits: usize, input1: G::ScalarField , input2: G::ScalarField ) 
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    // Create
    let mut gates = vec![];
    let _next_row = CircuitGate::<G::ScalarField>::extend_xor_gadget(&mut gates, bits);

    // Create witness and random inputs
    let witness = xor::create_xor_witness(input1, input2, bits);

    FuzzFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .unwrap();
}

// fn test_prove_and_verify_not_xor<G: KimchiCurve, EFqSponge, EFrSponge>(bits: usize, input: G::ScalarField )
// where
//     G::BaseField: PrimeField,
//     EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
//     EFrSponge: FrSponge<G::ScalarField>,
// {

//     // Create circuit
//     let gates = {
//         let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
//             Wire::for_row(0),
//             GenericGateSpec::Pub,
//             None,
//         )];
//         let _next_row = CircuitGate::<G::ScalarField>::extend_not_gadget_checked_length(&mut gates, 0, bits);
//         gates
//     };

//     // Create witness and random inputs

//     let witness =
//         fuzz_utils::create_not_witness_unchecked_length::<G::ScalarField>(&[input], bits);

//     FuzzFramework::<G>::default()
//         .gates(gates)
//         .witness(witness)
//         .public_inputs(vec![
//             <G::ScalarField>::from(2u32).pow([bits as u64]) - <G::ScalarField>::one(),
//         ])
//         .setup()
//         .prove_and_verify::<EFqSponge, EFrSponge>()
//         .unwrap();
// }

// // Creates as many negations as the number of inputs. The inputs must fit in the native field.
// // We start at the row 0 using generic gates to perform the negations.
// // Input: a vector of words to be negated, and the number of bits (all the same)
// // Panics if the bits length is too small for the inputs
// fn create_not_witness_unchecked_length<F: PrimeField>(
//     inputs: &[F],
//     bits: usize,
// ) -> [Vec<F>; COLUMNS] {
//     let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 1]);
//     witness[0][0] = F::from(2u8).pow([bits as u64]) - F::one();
//     let result = not::extend_not_witness_unchecked_length(&mut witness, inputs, bits);
//     if let Err(e) = result {
//         panic!("{}", e);
//     }
//     witness
// }

fn prove_and_verify_rot<G: KimchiCurve, EFqSponge, EFrSponge>(rot: u32 , word: u64  )
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    //let rot = rng.gen_range(1..64);
    // Create
    let gates = create_rot_gadget::<G>(rot, RotMode::Left);

    // Create input
    //let word = rng.gen_range(0..2u128.pow(64)) as u64;

    // Create witness
    let witness = create_rot_witness::<G>(word, rot, RotMode::Left);

    FuzzFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .unwrap();
}

fn create_rot_witness<G: KimchiCurve>(
    word: u64,
    rot: u32,
    side: RotMode,
) -> [Vec<G::ScalarField>; COLUMNS]
where
    G::BaseField: PrimeField,
{
    // Include the zero row
    let mut witness: [Vec<G::ScalarField>; COLUMNS] =
        array::from_fn(|_| vec![G::ScalarField::zero()]);
    rot::extend_rot(&mut witness, word, rot, side);
    witness
}

fn create_rot_gadget<G: KimchiCurve>(rot: u32, side: RotMode) -> Vec<CircuitGate<G::ScalarField>>
where
    G::BaseField: PrimeField,
{
    // gate for the zero value
    let mut gates = vec![CircuitGate::<G::ScalarField>::create_generic_gadget(
        Wire::for_row(0),
        GenericGateSpec::Pub,
        None,
    )];
    CircuitGate::<G::ScalarField>::extend_rot(&mut gates, rot, side, 0);
    gates
}
