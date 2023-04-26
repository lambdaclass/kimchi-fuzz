#[macro_use]
extern crate honggfuzz;

use kimchi::{
    circuits::{
        constraints::ConstraintSystem,
        gate::{CircuitGate, CircuitGateError, GateType},
        lookup::{runtime_tables::{RuntimeTableCfg,  RuntimeTable, RuntimeTableSpec}, tables::LookupTable},
        polynomial::COLUMNS,
        polynomials::{and, xor},
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
use ark_ff::PrimeField;
use ark_std::cmp::min;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::BigUint;
use o1_utils::{BitwiseOps, FieldHelpers, RandomField};
use rand::{rngs::StdRng, SeedableRng};
use poly_commitment::commitment::{CommitmentCurve, PolyComm};
use std::{fmt::Write, mem, time::Instant};

type PallasField = <Pallas as AffineCurve>::BaseField;
type VestaField = <Vesta as AffineCurve>::BaseField;
type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
type PallasBaseSponge = DefaultFqSponge<PallasParameters, SpongeParams>;
type PallasScalarSponge = DefaultFrSponge<Fq, SpongeParams>;

fn main() {
    loop {
        fuzz!(|data: [u8; 32]| {
            prove_and_verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(8, data);
            prove_and_verify::<Pallas, PallasBaseSponge, PallasScalarSponge>(8, data);
        });
    }
}

// Function to create a prover and verifier to test the AND circuit
fn prove_and_verify<G: KimchiCurve, EFqSponge, EFrSponge>(bytes: usize, seed: [u8; 32] )
where
    G::BaseField: PrimeField,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{

    // Create
    let mut gates = vec![];
    let _next_row = CircuitGate::<G::ScalarField>::extend_and(&mut gates, bytes);

    // // Create inputs
    let rng = &mut StdRng::from_seed(seed);
    let input1 = rng.gen(None, Some(bytes * 8));
    let input2 = rng.gen(None, Some(bytes * 8));
    println!("{:?}", input1);
    println!("{:?}", input2);

    println!("{:?}", input1);

    let inputs = [input1, input2].to_vec();

    // Create witness
    let witness = and::create_and_witness(input1, input2, bytes);

    FuzzFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .unwrap();

}

