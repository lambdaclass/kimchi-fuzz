use honggfuzz::fuzz;
use kimchi::{
    circuits::{
        gate::{CircuitGate, GateType}, 
        wires::GateWires,
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
use std::sync::Arc;
use ark_poly::EvaluationDomain;

use arbitrary::{Unstructured, Arbitrary};

type SpongeParams = PlonkSpongeConstantsKimchi;
type VestaBaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type VestaScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[derive(Arbitrary)]
struct CircuitGateFp {
    #[arbitrary(with = gen_circ_gate)]
    pub circuit_gate: CircuitGate::<Fp>
}

fn gen_circ_gate(u: &mut Unstructured) -> arbitrary::Result<CircuitGate<Fp>> {
    Ok(CircuitGate {
        typ: GateType::arbitrary(u)?,
        wires: GateWires::arbitrary(u)?,
        coeffs: gen_coeffs(u)?,
    })
}

fn gen_coeffs(u: &mut Unstructured) -> arbitrary::Result<Vec<Fp>> {
    let res_vec = Vec::<i128>::arbitrary(u)?;
    Ok(res_vec.iter().map(|n| Fp::from(*n)).collect())
}

fn main() {
    loop {
        fuzz!(|data: (Vec::<CircuitGateFp>, [Vec<i128>; 15]) | {
            // Skip if the wintess witness rows have different sizes or if they don't match the
            // circuit length.
            let correct_shape = data.1.iter().all(|row| row.len() == data.0.len());
            if data.0.len() > 1 && correct_shape {
                let (circuit_wrapped, witness_i128) = data;
                let mut witness = std::array::from_fn(|_| vec![]);
                for (i, col) in witness_i128.iter().enumerate() {
                    witness[i] = col.iter().map(|n| Fp::from(*n)).collect();
                }
                let circuit = circuit_wrapped.iter().map(|g| (*g).circuit_gate.to_owned()).collect();
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
}
