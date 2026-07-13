// DLEQ proof through g^a
use super::crypto::*;

type Challenge<C> = Scalar<C>;

#[derive(Clone)]
pub struct DLEQ<'a, C: EcOperation> {
    pub g1: &'a Point<C>,
    pub h1: &'a Point<C>,
    pub g2: &'a Point<C>,
    pub h2: &'a Point<C>,
}

#[derive(Clone)]
pub struct Proof<C: EcOperation> {
    c: Challenge<C>,
    z: Scalar<C>,
}

const DOMAIN_SEP: &[u8] = b"pvss-dleq-v1:sha2-256:";

impl<C: EcOperation> Proof<C> {
    pub fn create(w: &Scalar<C>, a: &Scalar<C>, dleq: &DLEQ<'_, C>) -> Proof<C> {
        let a1 = dleq.g1.mul(&w);
        let a2 = dleq.g2.mul(&w);
        let c = PointHasher::new_sep(DOMAIN_SEP)
            .update(&dleq.g1)
            .update(&dleq.g2)
            .update(&dleq.h1)
            .update(&dleq.h2)
            .update(&a1)
            .update(&a2)
            .finalize();
        let r = w + &(a * &c);
        Proof { c, z: r }
    }

    pub fn verify(&self, dleq: &DLEQ<'_, C>) -> bool {
        let r1 = dleq.g1.mul(&self.z);
        let r2 = dleq.g2.mul(&self.z);
        let a1 = r1 - dleq.h1.mul(&self.c);
        let a2 = r2 - dleq.h2.mul(&self.c);
        let c = PointHasher::new_sep(DOMAIN_SEP)
            .update(&dleq.g1)
            .update(&dleq.g2)
            .update(&dleq.h1)
            .update(&dleq.h2)
            .update(&a1)
            .update(&a2)
            .finalize();
        self.c == c
    }
}
