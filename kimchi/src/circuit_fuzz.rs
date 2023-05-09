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
};
use groupmap::GroupMap;
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use std::sync::Arc;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn gen_circuit_witness((starting_value, gates): (u32, Vec<u32>)) ->  (Vec<CircuitGate<Fp>>, [Vec::<Fp>; 15]) {
    let mut witness = std::array::from_fn(|_| vec![Fp::zero(); gates.len()]);
    let mut circuit = Vec::new();
    
    let mut output = 0;
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
            output = starting_value;
        } else if i == gates.len() - 1 {
            // Connect the left input to the output above
            wire[0] = Wire::new(i - 1, 2);
            witness[0][i] = output.into();
        } else {
            wire[0] = Wire::new(i - 1, 2);
            wire[2] = Wire::new(i + 1, 0);
            witness[0][i] = output.into();
        }
        witness[1][i] = (*r_val).into();
        output = output.checked_add(*r_val).unwrap_or((output as u64 + *r_val as u64 - u32::max_value() as u64) as u32);
        output += r_val;
        witness[2][i] = output.into();
        circuit.push(CircuitGate::<Fp>::create_generic_gadget(wire, gate, None));
    }
    (circuit, witness)
}

fn main() {
    fuzz!(|data: (u32, Vec<u32>)| {
        if data.1.len() > 1 {
            let (circuit, witness) = gen_circuit_witness(data);
            // Create constraint system
            let cs = ConstraintSystem::<Fp>::create(circuit).build().unwrap();

            let mut srs = SRS::<Vesta>::create(cs.domain.d1.size());
            srs.add_lagrange_basis(cs.domain.d1);
            let srs = Arc::new(srs);

            let (endo_q, _) = endos::<Pallas>();
            let prover_index = ProverIndex::<Vesta>::create(cs, endo_q, srs);
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
