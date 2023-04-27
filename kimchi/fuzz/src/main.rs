#[macro_use]
extern crate honggfuzz;

use kimchi::{
    circuits::{
        gate::CircuitGate,
        lookup::{runtime_tables, tables::LookupTable},
        polynomials::{and, xor},
    },
    prover_index,
    proof,
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    groupmap::GroupMap,
};
use std::array;

mod fuzz_utils;
use fuzz_utils::FuzzFramework;
use ark_ec::AffineCurve;
use mina_curves::pasta::{Fp, Fq, Pallas, PallasParameters, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
    FqSponge,
};
use num_bigint::BigUint;
use rand::{rngs::StdRng, SeedableRng};
use poly_commitment::commitment;
use std::{fmt::Write, mem, time::Instant};
use ark_ff::{PrimeField, SquareRootField};
use o1_utils::{RandomField};

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

fn prove_and_verify<G: KimchiCurve, EFqSponge, EFrSponge>(bytes: usize, seed: [u8; 32])
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
    let input1 = rng.gen(None, Some(bytes));
    let input2 = rng.gen(None, Some(bytes));
    
    // Create witness
    let witness = and::create_and_witness(input1, input2, bytes);

    let verify = FuzzFramework::<G>::default()
        .gates(gates)
        .witness(witness)
        .setup()
        .prove_and_verify::<EFqSponge, EFrSponge>()
        .unwrap();

    println!("{:?}", verify);
}
