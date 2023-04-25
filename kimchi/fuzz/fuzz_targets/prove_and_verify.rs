#![no_main]
use libfuzzer_sys::fuzz_target;

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



fuzz_target!(|data: [u8; 32]| {
    // fuzzed code goes here
    
    prove_and_verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(8, data);
    prove_and_verify::<Pallas, PallasBaseSponge, PallasScalarSponge>(8, data);
});


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

    let inputs = [input1, input2].to_vec();

    

    // Create witness
    let witness = and::create_and_witness(input1, input2, bytes);

    // without setup 

    let default_table = LookupTable {
        id: 0,              // set the default value for the id field
        data: Vec::new(),   // create an empty vector for the data field
    };
    let runtime_table_spec = RuntimeTableSpec{
        id: 0,              // set the default value for the id field
        len: 0,
    };
    let runtime_table_cfg = [RuntimeTableCfg::Indexed(runtime_table_spec)].to_vec();

    let runtime_table = RuntimeTable{
        id: 0,              // set the default value for the id field
        data: Vec::new(),
    };

    // prove and verify 
    let index = new_index_for_test_with_lookups::<G>(
        gates,
        inputs.to_vec().len(),
        0,
        std::mem::take(&mut [default_table].to_vec()),
        mem::replace(&mut Some(runtime_table_cfg), None),
        false,
    );

    let prover = index.clone();

    // add the proof to the batch
    let start = Instant::now();

    let group_map = <G as CommitmentCurve>::Map::setup();

    let comm = PolyComm {
        unshifted: Vec::new(),
        shifted: None,
    };

    let default_chal = [RecursionChallenge {
        chals: Vec::new(),
        comm: comm,
    }].to_vec();

    let proof = ProverProof::create_recursive::<EFqSponge, EFrSponge>(
        &group_map,
        witness,
        runtime_table.data.as_slice(),
        &prover,
        default_chal,
        None,
    )
    .map_err(|e| e.to_string()).unwrap();

    // verify the proof (propagate any errors)
    let start = Instant::now();
    verify::<G, EFqSponge, EFrSponge>(
        &group_map,
        &index.verifier_index.unwrap(),
        &proof,
        &inputs,
    )
    .map_err(|e| e.to_string());
}

// /// Reads bytes in big-endian, and converts them to a field element.
// /// If the bytes are larger than the modulus, it will reduce them.
// fn from_be_bytes_mod_order(bytes: &[u8]) -> PrimeField{
//     let num_modulus_bytes = ((PrimeField::Params::MODULUS_BITS + 7) / 8) as usize;
//     let num_bytes_to_directly_convert = min(num_modulus_bytes - 1, bytes.len());
//     // Copy the leading big-endian bytes directly into a field element.
//     // The number of bytes directly converted must be less than the
//     // number of bytes needed to represent the modulus, as we must begin
//     // modular reduction once the data is of the same number of bytes as the modulus.
//     let mut bytes_to_directly_convert = Vec::new();
//     bytes_to_directly_convert.extend(bytes[..num_bytes_to_directly_convert].iter().rev());
//     // Guaranteed to not be None, as the input is less than the modulus size.
//     let mut res = PrimeField::from_random_bytes(&bytes_to_directly_convert).unwrap();

//     // Update the result, byte by byte.
//     // We go through existing field arithmetic, which handles the reduction.
//     // TODO: If we need higher speeds, parse more bytes at once, or implement
//     // modular multiplication by a u64
//     let window_size = PrimeField::from(256u64);
//     for byte in bytes[num_bytes_to_directly_convert..].iter() {
//         res *= window_size;
//         res += PrimeField::from(*byte);
//     }
//     res
// }
// /// Create and verify a proof
// pub(crate) fn prove_and_verify<EFqSponge, EFrSponge>(self) -> Result<(), String>
// where
//     EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
//     EFrSponge: FrSponge<G::ScalarField>,
// {
//     let prover = self.0.prover_index.unwrap();
//     let witness = self.0.witness.unwrap();

//     if !self.0.disable_gates_checks {
//         // Note: this is already done by ProverProof::create_recursive::()
//         //       not sure why we do it here
//         prover
//             .verify(&witness, &self.0.public_inputs)
//             .map_err(|e| format!("{e:?}"))?;
//     }

//     // add the proof to the batch
//     let start = Instant::now();

//     let group_map = <G as CommitmentCurve>::Map::setup();

//     let proof = ProverProof::create_recursive::<EFqSponge, EFrSponge>(
//         &group_map,
//         witness,
//         &self.0.runtime_tables,
//         &prover,
//         self.0.recursion,
//         None,
//     )
//     .map_err(|e| e.to_string())?;
//     println!("- time to create proof: {:?}s", start.elapsed().as_secs());

//     // verify the proof (propagate any errors)
//     let start = Instant::now();
//     verify::<G, EFqSponge, EFrSponge>(
//         &group_map,
//         &self.0.verifier_index.unwrap(),
//         &proof,
//         &self.0.public_inputs,
//     )
//     .map_err(|e| e.to_string())?;
//     println!("- time to verify: {}ms", start.elapsed().as_millis());

//     Ok(())
// }