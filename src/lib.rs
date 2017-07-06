extern crate openssl;
pub mod crypto;

// Math module define polynomial types and operations that is used to setup the scheme.
mod math {
    use crypto;
    pub struct Polynomial {
        pub elements: Vec<crypto::Scalar>,
    }
    impl Polynomial {
        /// generate a new polynomial for a threshold
        pub fn generate(t: super::Threshold) -> Polynomial {
            let mut vec = Vec::with_capacity(t as usize);

            for _ in 0..t {
                let r = crypto::Scalar::generate();
                vec.push(r);
            }
            return Polynomial { elements: vec };
        }

        pub fn len(&self) -> usize {
            return self.elements.len();
        }

        /// get the value of a polynomial a0 + a1 * x^1 + a2 * x^2 + .. + an * x^n for a value x=at
        pub fn evaluate(&self, at: crypto::Scalar) -> crypto::Scalar {
            let mut r = crypto::Scalar::from_u32(0);
            for degree in 0..(self.elements.len() - 1) {
                let v = self.elements[degree].clone();
                r = r + v * at.pow(degree as u32);
            }
            return r;
        }
        pub fn at_zero(&self) -> crypto::Scalar {
            return self.elements[0].clone();
        }
    }

}

// DLEQ proof through g^a
mod dleq {
    use crypto::*;
    type Challenge = Scalar;

    #[derive(Clone)]
    pub struct DLEQ {
        pub g1: Point,
        pub h1: Point,
        pub g2: Point,
        pub h2: Point,
    }
    pub struct Proof {
        c: Challenge,
        z: Scalar,
    }

    impl Proof {
        pub fn create(w: Scalar, a: Scalar, dleq: DLEQ) -> Proof {
            let a1 = dleq.g1.mul(&w);
            let a2 = dleq.g2.mul(&w);
            let c = Scalar::hash_points(vec![dleq.h1, dleq.h2, a1, a2]);
            let r = w + a * c.clone();
            return Proof { c: c, z: r };
        }

        pub fn verify(&self, dleq: DLEQ) -> bool {
            let r1 = dleq.g1.mul(&self.z);
            let r2 = dleq.g2.mul(&self.z);
            let a1 = r1 - dleq.h1.mul(&self.c);
            let a2 = r2 - dleq.h2.mul(&self.c);
            return self.c == Scalar::hash_points(vec![dleq.h1, dleq.h2, a1, a2]);
        }
    }
}

use crypto::*;

// threshold need to >= 2
type Threshold = u32;
type Secret = Point;
type ShareId = u32;

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
pub fn escrow(t: Threshold) -> Escrow {
    let poly = math::Polynomial::generate(t);
    let gen = Point::from_scalar(&Scalar::generate());

    let secret = poly.at_zero();
    let g_s = Point::from_scalar(&secret);

    let challenge = Scalar::generate();
    let dleq = dleq::DLEQ {
        g1: Point::generator(),
        h1: g_s.clone(),
        g2: gen.clone(),
        h2: Point::from_scalar(&secret),
    };
    let proof = dleq::Proof::create(challenge, secret, dleq);

    return Escrow {
        extra_generator: gen,
        polynomial: poly,
        secret: g_s,
        proof: proof,
    };
}

pub fn commitments(escrow: &Escrow) -> Vec<Commitment> {
    let mut commitments = Vec::with_capacity(escrow.polynomial.len());

    for i in 0..(escrow.polynomial.len()) {
        let com = Commitment { point: escrow.extra_generator.mul(&escrow.polynomial.elements[i]) };
        commitments.push(com);
    }
    return commitments;
}

pub fn create_share(escrow: &Escrow, share_id: ShareId, public: &PublicKey) -> EncryptedShare {
    let peval = escrow.polynomial.evaluate(Scalar::from_u32(share_id));
    let challenge = Scalar::generate();
    let xi = escrow.extra_generator.mul(&peval);
    let yi = public.point.mul(&peval);
    let dleq = dleq::DLEQ {
        g1: escrow.extra_generator.clone(),
        h1: xi,
        g2: public.point.clone(),
        h2: yi.clone(),
    };
    let proof = dleq::Proof::create(challenge, peval, dleq);
    return EncryptedShare {
        id: share_id,
        encrypted_val: yi,
        proof: proof,
    };
}

pub fn create_shares(escrow: &Escrow, pubs: &Vec<PublicKey>) -> Vec<EncryptedShare> {
    let mut shares = Vec::with_capacity(pubs.len());
    for i in 0..(pubs.len()) {
        let share = create_share(escrow, i as ShareId, &pubs[i]);
        shares.push(share);
    }
    return shares;
}

fn create_xi(id: ShareId, commitments: &[Commitment]) -> Point {
    let mut r = Point::infinity();
    for j in 0..(commitments.len() - 1) {
        let e = Scalar::from_u32(id).pow(j as u32);
        r = r.clone() + (commitments[j].point.mul(&e));
    }
    return r;
}

impl EncryptedShare {
    pub fn verify(&self,
                  id: ShareId,
                  public: &PublicKey,
                  extra_generator: &Point,
                  commitments: &[Commitment])
                  -> bool {
        let xi = create_xi(id, commitments);
        let dleq = dleq::DLEQ {
            g1: extra_generator.clone(),
            h1: xi,
            g2: public.point.clone(),
            h2: self.encrypted_val.clone(),
        };
        return self.proof.verify(dleq);
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
        return self.proof.verify(dleq);
    }
}

pub fn decrypt_share(private: &PrivateKey,
                     public: &PublicKey,
                     share: &EncryptedShare)
                     -> DecryptedShare {
    let challenge = Scalar::generate();
    let xi = private.scalar.clone();
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
    let proof = dleq::Proof::create(challenge, xi, dleq);
    return DecryptedShare {
        id: share.id,
        decrypted_val: si,
        proof: proof,
    };
}

fn interpolate_one(t: Threshold, sid: usize, shares: &[DecryptedShare]) -> Scalar {
    let mut v = Scalar::from_u32(1);
    for j in 0..(t as usize) {
        if j != sid {
            let sj = Scalar::from_u32(shares[j].id);
            let si = Scalar::from_u32(shares[sid].id);
            let d = sj.clone() - si;
            let dinv = d.inverse();
            let e = sj * dinv;
            v = v * e;
        }
    }
    return v;
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
    return Ok(result);
}

#[cfg(test)]
mod tests {
    use crypto::*;
    use crypto;
    use dleq;

    pub const NB_TESTS: usize = 100;
    #[test]
    fn crypto_point_add_identity() {
        for _ in 0..NB_TESTS {
            let i = Scalar::generate();
            let p = Point::from_scalar(&i);
            assert!(p.clone() + Point::infinity() == p);
        }
    }

    #[test]
    fn crypto_point_generator() {
        let g = Point::generator();
        for _ in 0..NB_TESTS {
            let i = Scalar::generate();
            let p1 = Point::from_scalar(&i);
            let p2 = g.mul(&i);
            assert!(p1 == p2);
        }
    }

    #[test]
    fn dleq_works() {
        for _ in 0..NB_TESTS {
            let a = Scalar::generate();
            let w = Scalar::generate();
            let extra_gen = Point::from_scalar(&Scalar::generate());

            let lifted_a = Point::from_scalar(&a);
            let lifted_extra_a = extra_gen.mul(&a);

            let dleq = dleq::DLEQ {
                g1: Point::generator(),
                h1: lifted_a,
                g2: extra_gen,
                h2: lifted_extra_a,
            };
            let proof = dleq::Proof::create(w, a, dleq.clone());
            assert!(proof.verify(dleq));
        }
    }

    #[test]
    fn pvss_works() {
        let tests = [(2, 8), (10, 50), (48, 50), (2, 20), (10, 100)];
        for test in tests.iter() {
            let &(t, nb_keys) = test;

            let mut keys = Vec::with_capacity(nb_keys);
            let mut pubs = Vec::with_capacity(nb_keys);
            for _ in 0..nb_keys {
                let (public, private) = crypto::create_keypair();
                keys.push(private);
                pubs.push(public);
            }

            let escrow = super::escrow(t);

            let commitments = super::commitments(&escrow);
            let shares = super::create_shares(&escrow, &pubs);

            let mut decrypted = Vec::with_capacity(100);

            assert_eq!(t as usize, commitments.len());
            assert_eq!(pubs.len(), shares.len());

            for share in shares {
                let idx = share.id as usize;
                let verified_encrypted =
                    share.verify(share.id, &pubs[idx], &escrow.extra_generator, &commitments);
                assert!(verified_encrypted);

                let d = super::decrypt_share(&keys[idx], &pubs[idx], &share);
                let verified_decrypted = d.verify(&pubs[idx], &share);
                assert!(verified_decrypted);
                decrypted.push(d);
            }

            let recovered = super::recover(t, decrypted.as_slice()).unwrap();
            assert!(recovered == escrow.secret);
        }
    }
}
