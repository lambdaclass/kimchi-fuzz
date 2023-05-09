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
    precomputed_srs
};
use groupmap::GroupMap;
use ark_ff::Zero;
use std::sync::Arc;

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn main() {
    let mut srs: SRS::<Vesta> = precomputed_srs::get_srs();
    fuzz!(|data: u32| {
        // Create gates
        let g1 = GenericGateSpec::<Fp>::Add {
            left_coeff: None,
            right_coeff: None,
            output_coeff: None
        };
        let g2 = GenericGateSpec::<Fp>::Add {
            left_coeff: None,
            right_coeff: None,
            output_coeff: None
        };

        // Create circuits
        let circuit_gate_1 = CircuitGate::<Fp>::create_generic_gadget(Wire::for_row(0), g1, None);
        let circuit_gate_2 = CircuitGate::<Fp>::create_generic_gadget(Wire::for_row(1), g2, None);

        // Create witness
        let mut witness: [Vec::<Fp>; 15] = std::array::from_fn(|_| vec![Fp::zero(); 2]);
        witness[0][0] = data.into();        // l | r | o | ...
        witness[1][0] = 5_u32.into();       // 1 | 5 | 6 | ...
        witness[2][0] = (data + 5).into();  // 2 | 5 | 7 | ...
        witness[0][1] = 2_u32.into();       // Gates:
        witness[1][1] = 5_u32.into();       // add add no coefficients
        witness[2][1] = 7_u32.into();

        // Create constraint system
        let cs = ConstraintSystem::<Fp>::create(vec![circuit_gate_1.clone(), circuit_gate_2.clone()]).build().unwrap();

        srs.add_lagrange_basis(cs.domain.d1);
        let srs_arc = Arc::new(srs);

        let (endo_q, _) = endos::<Pallas>();
        let prover_index = ProverIndex::<Vesta>::create(cs, endo_q, srs_arc);
        let verifier_index = prover_index.verifier_index();
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        // Get proof
        let proof = ProverProof::create::<VestaBaseSponge, VestaScalarSponge>(&group_map, witness, &[], &prover_index);
        // Verify
        match verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(&group_map, &verifier_index, &proof.unwrap(), &[]).map_err(|e|e.to_string()) {
            Ok(_) => {},
            Err(e) => println!("{}", e)
        }
    });
}
