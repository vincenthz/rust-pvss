// implementation of the simple publicly verifiable secret sharing scheme
// http://www.win.tue.nl/~berry/papers/crypto99.pdf

use super::dleq;
use super::math;
use super::types::*;

use super::crypto::*;

use std::borrow::Borrow;

pub type Secret = Point;

pub struct Escrow {
    pub extra_generator: Point,
    pub polynomial: math::Polynomial,
    pub secret: Secret,
    pub proof: dleq::Proof,
}

pub struct Commitment {
    point: Point,
}

pub struct EncryptedShare {
    pub id: ShareId,
    encrypted_val: Point,
    proof: dleq::Proof,
}

pub struct DecryptedShare {
    pub id: ShareId,
    decrypted_val: Point,
    proof: dleq::Proof,
}

// create a new escrow parameter.
// the only parameter needed is the threshold necessary to be able to reconstruct.
pub fn escrow(drg: &mut Drg, t: Threshold) -> Escrow {
    assert!(t >= 1, "threshold is invalid; < 1");

    let poly = math::Polynomial::generate(drg, t - 1);
    let gen = Point::random_generator(drg);

    let secret = poly.at_zero();
    let g_s = Point::from_scalar(&secret);

    let challenge = Scalar::generate(drg);
    let dleq = dleq::DLEQ {
        g1: Point::generator(),
        h1: g_s.clone(),
        g2: gen.clone(),
        h2: gen.mul(&secret),
    };
    let proof = dleq::Proof::create(&challenge, &secret, dleq);

    Escrow {
        extra_generator: gen,
        polynomial: poly,
        secret: g_s,
        proof,
    }
}

pub fn commitments(escrow: &Escrow) -> Vec<Commitment> {
    let mut commitments = Vec::with_capacity(escrow.polynomial.len());

    for i in 0..(escrow.polynomial.len()) {
        let com = Commitment {
            point: escrow.extra_generator.mul(&escrow.polynomial.elements[i]),
        };
        commitments.push(com);
    }
    commitments
}

pub fn create_share(
    drg: &mut Drg,
    escrow: &Escrow,
    share_id: ShareId,
    public: &PublicKey,
) -> EncryptedShare {
    assert!(share_id != 0, "trying to create a share with id = 0");

    let peval = escrow.polynomial.evaluate(Scalar::from_u32(share_id));
    let challenge = Scalar::generate(drg);
    let xi = escrow.extra_generator.mul(&peval);
    let yi = public.point.mul(&peval);
    let dleq = dleq::DLEQ {
        g1: escrow.extra_generator.clone(),
        h1: xi,
        g2: public.point.clone(),
        h2: yi.clone(),
    };
    let proof = dleq::Proof::create(&challenge, &peval, dleq);
    EncryptedShare {
        id: share_id,
        encrypted_val: yi,
        proof,
    }
}

pub fn create_shares<I, K>(drg: &mut Drg, escrow: &Escrow, pubs: I) -> Vec<EncryptedShare>
where
    I: IntoIterator<Item = K>,
    K: Borrow<PublicKey>,
{
    pubs.into_iter()
        .enumerate()
        .map(|(i, pub_key)| create_share(drg, escrow, (i + 1) as ShareId, pub_key.borrow()))
        .collect()
}

fn create_xi(id: ShareId, commitments: &[Commitment]) -> Point {
    let mut r = Point::infinity();
    for (j, com) in commitments.iter().enumerate() {
        let e = Scalar::from_u32(id).pow(j as u32);
        r = r.clone() + (com.point.mul(&e));
    }
    r
}

impl EncryptedShare {
    pub fn verify(
        &self,
        id: ShareId,
        public: &PublicKey,
        extra_generator: &Point,
        commitments: &[Commitment],
    ) -> bool {
        let xi = create_xi(id, commitments);
        let dleq = dleq::DLEQ {
            g1: extra_generator.clone(),
            h1: xi,
            g2: public.point.clone(),
            h2: self.encrypted_val.clone(),
        };
        self.proof.verify(&dleq)
    }
}

impl DecryptedShare {
    pub fn verify(&self, public: &PublicKey, eshare: &EncryptedShare) -> bool {
        let dleq = dleq::DLEQ {
            g1: Point::generator(),
            h1: public.point.clone(),
            g2: self.decrypted_val.clone(),
            h2: eshare.encrypted_val.clone(),
        };
        self.proof.verify(&dleq)
    }
}

pub fn decrypt_share(
    drg: &mut Drg,
    private: &PrivateKey,
    public: &PublicKey,
    share: &EncryptedShare,
) -> DecryptedShare {
    let challenge = Scalar::generate(drg);
    let xi = &private.scalar;
    let yi = public.point.clone();
    let lifted_yi = share.encrypted_val.clone();
    let xi_inverse = xi.inverse();
    let si = lifted_yi.mul(&xi_inverse);
    let dleq = dleq::DLEQ {
        g1: Point::generator(),
        h1: yi,
        g2: si.clone(),
        h2: lifted_yi,
    };
    let proof = dleq::Proof::create(&challenge, xi, dleq);
    DecryptedShare {
        id: share.id,
        decrypted_val: si,
        proof,
    }
}

fn interpolate_one(t: Threshold, sid: usize, shares: &[DecryptedShare]) -> Scalar {
    let mut v = Scalar::from_u32(1);
    for j in 0..(t as usize) {
        if j != sid {
            let sj = Scalar::from_u32(shares[j].id);
            let si = Scalar::from_u32(shares[sid].id);
            let d = &sj - &si;
            let dinv = d.inverse();
            let e = sj * dinv;
            v = v * e;
        }
    }
    v
}

// Try to recover a secret
pub fn recover(t: Threshold, shares: &[DecryptedShare]) -> Result<Secret, ()> {
    if t as usize > shares.len() {
        return Err(());
    };
    let mut result = Point::infinity();
    for i in 0..(t as usize) {
        let v = interpolate_one(t, i, shares);
        result = result + shares[i].decrypted_val.mul(&v);
    }
    Ok(result)
}

pub fn verify_secret(
    secret: Secret,
    extra_generator: Point,
    commitments: &[Commitment],
    proof: dleq::Proof,
) -> bool {
    let dleq = dleq::DLEQ {
        g1: Point::generator(),
        h1: secret,
        g2: extra_generator,
        h2: commitments[0].point.clone(),
    };
    proof.verify(&dleq)
}
