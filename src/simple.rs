// implementation of the simple publicly verifiable secret sharing scheme
// http://www.win.tue.nl/~berry/papers/crypto99.pdf

use super::dleq;
use super::math;
use super::types::*;

use super::crypto::*;

use std::borrow::Borrow;

pub type Secret<C> = Point<C>;

#[derive(Clone)]
pub struct Escrow<C: EcOperation> {
    pub extra_generator: Point<C>,
    pub polynomial: math::Polynomial<C>,
    pub secret: Secret<C>,
    pub proof: dleq::Proof<C>,
}

#[derive(Clone)]
pub struct Commitment<C: EcOperation> {
    point: Point<C>,
}

#[derive(Clone)]
pub struct EncryptedShare<C: EcOperation> {
    pub id: ShareId,
    encrypted_val: Point<C>,
    proof: dleq::Proof<C>,
}

#[derive(Clone)]
pub struct DecryptedShare<C: EcOperation> {
    pub id: ShareId,
    decrypted_val: Point<C>,
    proof: dleq::Proof<C>,
}

// create a new escrow parameter.
// the only parameter needed is the threshold necessary to be able to reconstruct.
pub fn escrow<C: EcOperation>(drg: &mut Drg, t: Threshold) -> Escrow<C> {
    assert!(t >= 1, "threshold is invalid; < 1");

    let poly = math::Polynomial::generate(drg, t - 1);
    let generator = Point::random_generator(drg);

    let secret = poly.at_zero();
    let g_s = Point::from_scalar(&secret);

    let challenge = Scalar::generate(drg);
    let dleq = dleq::DLEQ {
        g1: &Point::generator(),
        h1: &g_s,
        g2: &generator,
        h2: &generator.mul(&secret),
    };
    let proof = dleq::Proof::create(&challenge, &secret, &dleq);

    Escrow {
        extra_generator: generator,
        polynomial: poly,
        secret: g_s,
        proof,
    }
}

pub fn commitments<C: EcOperation>(escrow: &Escrow<C>) -> Vec<Commitment<C>> {
    let mut commitments = Vec::with_capacity(escrow.polynomial.len());

    for i in 0..(escrow.polynomial.len()) {
        let com = Commitment {
            point: escrow.extra_generator.mul(&escrow.polynomial.elements[i]),
        };
        commitments.push(com);
    }
    commitments
}

pub fn create_share<C: EcOperation>(
    drg: &mut Drg,
    escrow: &Escrow<C>,
    share_id: ShareId,
    public: &PublicKey<C>,
) -> EncryptedShare<C> {
    let peval = escrow.polynomial.evaluate(share_id.to_scalar());
    let challenge = Scalar::generate(drg);
    let xi = escrow.extra_generator.mul(&peval);
    let yi = public.point.mul(&peval);
    let dleq = dleq::DLEQ {
        g1: &escrow.extra_generator,
        h1: &xi,
        g2: &public.point,
        h2: &yi,
    };
    let proof = dleq::Proof::create(&challenge, &peval, &dleq);
    EncryptedShare {
        id: share_id,
        encrypted_val: yi,
        proof,
    }
}

pub fn create_shares<I, K, C>(drg: &mut Drg, escrow: &Escrow<C>, pubs: I) -> Vec<EncryptedShare<C>>
where
    I: IntoIterator<Item = K>,
    K: Borrow<PublicKey<C>>,
    C: EcOperation,
{
    ShareIdsSequence::new()
        .zip(pubs.into_iter())
        .map(|(i, pub_key)| create_share(drg, escrow, i, pub_key.borrow()))
        .collect()
}

fn create_xi<C: EcOperation>(id: ShareId, commitments: &[Commitment<C>]) -> Point<C> {
    let mut r = Point::infinity();
    for (j, com) in commitments.iter().enumerate() {
        let e = id.to_scalar().pow(j as u32);
        r = r + com.point.mul(&e);
    }
    r
}

impl<C: EcOperation> EncryptedShare<C> {
    pub fn verify(
        &self,
        id: ShareId,
        public: &PublicKey<C>,
        extra_generator: &Point<C>,
        commitments: &[Commitment<C>],
    ) -> bool {
        let xi = create_xi(id, commitments);
        let dleq = dleq::DLEQ {
            g1: &extra_generator,
            h1: &xi,
            g2: &public.point,
            h2: &self.encrypted_val,
        };
        self.proof.verify(&dleq)
    }
}

impl<C: EcOperation> DecryptedShare<C> {
    pub fn verify(&self, public: &PublicKey<C>, eshare: &EncryptedShare<C>) -> bool {
        let dleq = dleq::DLEQ {
            g1: &Point::generator(),
            h1: &public.point,
            g2: &self.decrypted_val,
            h2: &eshare.encrypted_val,
        };
        self.proof.verify(&dleq)
    }
}

pub fn decrypt_share<C: EcOperation>(
    drg: &mut Drg,
    private: &PrivateKey<C>,
    public: &PublicKey<C>,
    share: &EncryptedShare<C>,
) -> DecryptedShare<C> {
    let challenge = Scalar::generate(drg);
    let xi = &private.scalar;
    let yi = &public.point;
    let lifted_yi = &share.encrypted_val;
    let xi_inverse = xi.inverse();
    let si = lifted_yi.mul(&xi_inverse);
    let dleq = dleq::DLEQ {
        g1: &Point::generator(),
        h1: &yi,
        g2: &si,
        h2: &lifted_yi,
    };
    let proof = dleq::Proof::create(&challenge, xi, &dleq);
    DecryptedShare {
        id: share.id,
        decrypted_val: si,
        proof,
    }
}

fn interpolate_one<C: EcOperation>(
    t: Threshold,
    sid: usize,
    shares: &[DecryptedShare<C>],
) -> Scalar<C> {
    let mut v = Scalar::from_u32(1);
    for j in 0..(t as usize) {
        if j != sid {
            let sj = shares[j].id.to_scalar();
            let si = shares[sid].id.to_scalar();
            let d = &sj - &si;
            let dinv = d.inverse();
            let e = sj * dinv;
            v = v * e;
        }
    }
    v
}

// Try to recover a secret
pub fn recover<C: EcOperation>(
    t: Threshold,
    shares: &[DecryptedShare<C>],
) -> Result<Secret<C>, ()> {
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

pub fn verify_secret<C: EcOperation>(
    secret: Secret<C>,
    extra_generator: Point<C>,
    commitments: &[Commitment<C>],
    proof: dleq::Proof<C>,
) -> bool {
    let dleq = dleq::DLEQ {
        g1: &Point::generator(),
        h1: &secret,
        g2: &extra_generator,
        h2: &commitments[0].point,
    };
    proof.verify(&dleq)
}
