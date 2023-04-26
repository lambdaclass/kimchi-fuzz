use honggfuzz::fuzz;

use kimchi::{
    mina_poseidon::{
      constants::PlonkSpongeConstantsKimchi,
      sponge::{DefaultFrSponge, DefaultFqSponge}
    },
    mina_curves::pasta::{
       Fp, Vesta, VestaParameters
    },
    proof::ProverProof,
    verifier_index::VerifierIndex,
    verifier::verify,
    groupmap::GroupMap,
    poly_commitment::commitment::CommitmentCurve,
};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            let mut scalar = Vec::<Fp>::new();

            let input_size: usize = if data[0] as usize >= data.len() {
                data.len()
            } else {
                data[0] as usize
            };

            for i in 0..input_size {
                scalar.push(Fp::from(data[i]))
            }

            let proof = serde_json::from_slice::<ProverProof<Vesta>>(data);
            let verifier_index = serde_json::from_slice::<VerifierIndex<Vesta>>(data);
            let group_map = <Vesta as CommitmentCurve>::Map::setup();

            match (proof, verifier_index) {
                (Ok(proof), Ok(verifier_index)) => {
                    let _ = verify::<Vesta, BaseSponge, ScalarSponge>(&group_map, &verifier_index, &proof, &scalar);
                },
                _ => {}
            };
        });
    }
}
