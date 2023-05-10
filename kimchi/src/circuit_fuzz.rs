use honggfuzz::fuzz;
use kimchi::{
    circuits::{
        polynomials::generic::GenericGateSpec, 
        gate::CircuitGate, 
        wires::Wire,
        constraints::ConstraintSystem
    },
    prover_index::ProverIndex,
    mina_curves::pasta::{Vesta, VestaParameters, Fp, Pallas},
    poly_commitment::{commitment::CommitmentCurve, srs::{SRS, endos}},
    proof::ProverProof,
    mina_poseidon::{sponge::{DefaultFqSponge, DefaultFrSponge}, constants::PlonkSpongeConstantsKimchi},
    verifier::verify,
    precomputed_srs::get_srs
};
use groupmap::GroupMap;
use ark_ff::Zero;
use std::sync::Arc;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;


fn gen_circuit_witness((starting_value, gates): (u32, Vec<u32>)) ->  (Vec<CircuitGate<Fp>>, [Vec::<Fp>; 15]) {
    let mut witness = std::array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    let mut circuit = Vec::new();
    
    for (i, r_val) in gates.iter().enumerate() {
        let gate = GenericGateSpec::<Fp>::Add {
            left_coeff: None,
            right_coeff: None,
            output_coeff: None
        };
        let mut wire = Wire::for_row(i);
        if i == 0 {
            // Connect the output to the input below
            wire[2] = Wire::new(i + 1, 0);
            witness[0][i] = starting_value.into();
        } else if i == gates.len() - 1 {
            // Connect the left input to the output above
            wire[0] = Wire::new(i - 1, 2);
            witness[0][i] = witness[2][i - 1];
        } else {
            wire[0] = Wire::new(i - 1, 2);
            wire[2] = Wire::new(i + 1, 0);
            witness[0][i] = witness[2][i - 1];
        }
        witness[1][i] = (*r_val).into();
        witness[2][i] = witness[0][i] + witness[1][i];
        circuit.push(CircuitGate::<Fp>::create_generic_gadget(wire, gate, None));
    }
    (circuit, witness)
}

fn main() {
    let vestas_srs: SRS::<Vesta> = get_srs();
    let mut srs = Arc::new(vestas_srs);

    loop {
        fuzz!(|data: (u32, Vec<u32>)| {
            if data.1.len() > 1 {
                let (circuit, witness) = gen_circuit_witness(data);
                // Create constraint system
                let cs = ConstraintSystem::<Fp>::create(circuit).build().unwrap();

                Arc::make_mut(&mut srs).add_lagrange_basis(cs.domain.d1);

                let (endo_q, _) = endos::<Pallas>();
                let prover_index = ProverIndex::<Vesta>::create(cs, endo_q, Arc:: clone(&srs));
                let verifier_index = prover_index.verifier_index();
                let group_map = <Vesta as CommitmentCurve>::Map::setup();
                // Get proof
                let proof = ProverProof::create::<VestaBaseSponge, VestaScalarSponge>(&group_map, witness, &[], &prover_index);
                // Verify
                match verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(&group_map, &verifier_index, &proof.unwrap(), &[]).map_err(|e|e.to_string()) {
                    Ok(_) => {},
                    Err(e) => println!("{}", e)
                }
            }
        });
    }
}
