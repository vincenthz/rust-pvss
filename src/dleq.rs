// DLEQ proof through g^a
use super::crypto::*;

type Challenge = Scalar;

#[derive(Clone)]
pub struct DLEQ {
    pub g1: Point,
    pub h1: Point,
    pub g2: Point,
    pub h2: Point,
}
#[derive(Clone)]
pub struct Proof {
    c: Challenge,
    z: Scalar,
}

impl Proof {
    pub fn create(w: &Scalar, a: &Scalar, dleq: DLEQ) -> Proof {
        let a1 = dleq.g1.mul(&w);
        let a2 = dleq.g2.mul(&w);
        let c = PointHasher::new()
            .update(&dleq.h1)
            .update(&dleq.h2)
            .update(&a1)
            .update(&a2)
            .finalize();
        let r = w + &(a * &c);
        Proof { c, z: r }
    }

    pub fn verify(&self, dleq: &DLEQ) -> bool {
        let r1 = dleq.g1.mul(&self.z);
        let r2 = dleq.g2.mul(&self.z);
        let a1 = r1 - dleq.h1.mul(&self.c);
        let a2 = r2 - dleq.h2.mul(&self.c);
        let c = PointHasher::new()
            .update(&dleq.h1)
            .update(&dleq.h2)
            .update(&a1)
            .update(&a2)
            .finalize();
        self.c == c
    }
}
