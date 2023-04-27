use honggfuzz::fuzz;

use kimchi::{
    mina_poseidon::{
      constants::PlonkSpongeConstantsKimchi,
      sponge::{DefaultFrSponge, DefaultFqSponge}
    },
    mina_curves::pasta::{
       Fp, Vesta, VestaParameters
    },
    curve::KimchiCurve,
    proof::ProverProof,
    verifier_index::VerifierIndex,
    verifier::verify,
    groupmap::GroupMap,
    poly_commitment::commitment::CommitmentCurve,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ark_ec::AffineCurve;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
struct ProofVerifierIndex<G: AffineCurve, H: KimchiCurve> {
    pub proof: ProverProof<G>,
    pub verifier_index: VerifierIndex<H>,
    pub public: Vec<u8>
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            match serde_json::from_slice::<ProofVerifierIndex<Vesta, Vesta>>(data) {
                Ok(proof_verifier_index) => {
                    let group_map = <Vesta as CommitmentCurve>::Map::setup();
                    let scalar: Vec<Fp> = proof_verifier_index.public.iter().map(|n| Fp::from(*n)).collect();
                    let _ = verify::<Vesta, BaseSponge, ScalarSponge>(&group_map, &proof_verifier_index.verifier_index, &proof_verifier_index.proof, &scalar);
                },
                Err(_) => {}
            };
        });
    }
}

