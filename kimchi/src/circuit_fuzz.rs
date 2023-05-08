//use honggfuzz::fuzz;
use kimchi::{
    circuits::{
        polynomials::generic::GenericGateSpec, 
        gate::CircuitGate,
        wires::Wire,
        constraints::ConstraintSystem
    },
    prover_index::ProverIndex,
    mina_curves::pasta::{Vesta, VestaParameters, Fp, Pallas},
    precomputed_srs,
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

fn main() {
    //fuzz!(|data: u8| {
        let g1 = GenericGateSpec::<Fp>::Add {
            left_coeff: Some(2_32.into()),
            right_coeff: Some(4_u32.into()),
            output_coeff: None
        };

        let circuit_gate_1 = CircuitGate::<Fp>::create_generic_gadget(Wire::for_row(0), GenericGateSpec::Pub, None);
        let circuit_gate_2 = CircuitGate::<Fp>::create_generic_gadget(Wire::for_row(1), g1, None);
        let mut witness: [Vec::<Fp>; 15] = std::array::from_fn(|_| vec![Fp::zero(); 2]);
        witness[0][0] = 3_u32.into();
        witness[0][1] = 3_u32.into();
        witness[1][1] = 5_u32.into();
        witness[2][1] = 8_u32.into();
        let cs = ConstraintSystem::<Fp>::create(vec![circuit_gate_1.clone(), circuit_gate_2.clone()]).build().unwrap();
        let mut srs = if cs.domain.d1.log_size_of_group <= precomputed_srs::SERIALIZED_SRS_SIZE {
            // TODO: we should trim it if it's smaller
            precomputed_srs::get_srs()
        } else {
            // TODO: we should resume the SRS generation starting from the serialized one
            SRS::<Vesta>::create(cs.domain.d1.size())
        };

        srs.add_lagrange_basis(cs.domain.d1);
        let srs = Arc::new(srs);
        let (endo_q, _) = endos::<Pallas>();
        let prover_index = ProverIndex::<Vesta>::create(cs, endo_q, srs);
        dbg!(&prover_index.cs.public);
        let verifier_index = prover_index.verifier_index();
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        let proof = ProverProof::create::<VestaBaseSponge, VestaScalarSponge>(&group_map, witness, &[], &prover_index);
    //    let e = verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(&group_map, &verifier_index, &proof.unwrap(), &[]).map_err(|e|e.to_string());
        match verify::<Vesta, VestaBaseSponge, VestaScalarSponge>(&group_map, &verifier_index, &proof.unwrap(), &[]).map_err(|e|e.to_string()) {
            Ok(val) => dbg!(val),
            Err(e) => println!("{}", e)
        }
    //});
}
