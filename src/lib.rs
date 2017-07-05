extern crate openssl;

// FIXME make crypto private: only needed for create_keypair and some types; reexport properly
// FIXME probably should move to it own crypto module as well..
//
// allmost all unwrap() are sadly needed as propagating C allocation errors is mostly pointless
// and make the API terrible for no useful reason.
pub mod crypto {
    use openssl::ec::*;
    use openssl::bn::*;
    use openssl;
    use std::ops::Add;
    use std::ops::Sub;
    use std::ops::Mul;

    // currently hardcode curve to P256R1, but in the future probably a good idea
    // to generalize the interface, and make it more generics (with generics for all crypto types)
    pub const CURVE: openssl::nid::Nid = openssl::nid::X9_62_PRIME256V1;

    pub struct Scalar {
        bn: BigNum,
    }
    pub struct Point {
        point: EcPoint,
    }
    pub struct PrivateKey {
        pub scalar: Scalar,
    }
    pub struct PublicKey {
        pub point: Point,
    }

    pub fn create_keypair() -> (PublicKey, PrivateKey) {
        let s = Scalar::generate();
        let p = Point::from_scalar(&s);
        return (PublicKey { point: p }, PrivateKey { scalar: s });
    }

    fn get_grp() -> EcGroup {
        return openssl::ec::EcGroup::from_curve_name(CURVE).unwrap();
    }

    fn get_order() -> BigNum {
        let mut ctx = BigNumContext::new().unwrap();
        let grp = openssl::ec::EcGroup::from_curve_name(CURVE).unwrap();
        let mut order = BigNum::new().unwrap();
        grp.order(&mut order, &mut ctx).unwrap();
        return order;
    }

    fn get_point_at_infinity() -> EcPoint {
        let mut ctx = BigNumContext::new().unwrap();
        let grp = openssl::ec::EcGroup::from_curve_name(CURVE).unwrap();
        let mut order = BigNum::new().unwrap();
        grp.order(&mut order, &mut ctx).unwrap();
        let mut p = EcPoint::new(&grp).unwrap();
        p.mul_generator(&grp, &order, &mut ctx).unwrap();
        return p;
    }

    fn curve_generator() -> EcPoint {
        let mut ctx = BigNumContext::new().unwrap();
        let grp = openssl::ec::EcGroup::from_curve_name(CURVE).unwrap();
        let pow = BigNum::from_u32(1).unwrap();
        let mut p = EcPoint::new(&grp).unwrap();
        p.mul_generator(&grp, &pow, &mut ctx).unwrap();
        return p;
    }

    impl Scalar {
        pub fn from_u32(v: u32) -> Scalar {
            let r = Scalar { bn: BigNum::from_u32(v).unwrap() };
            return r;
        }
        pub fn generate() -> Scalar {
            let order = get_order();
            let mut r = BigNum::new().unwrap();
            order.rand_range(&mut r).unwrap();
            return Scalar { bn: r };
        }

        pub fn hash_points(points: Vec<Point>) -> Scalar {
            let mut data = Vec::new();
            for p in points {
                data.extend_from_slice(p.to_bytes().as_slice());
            }
            let dig = openssl::sha::sha256(data.as_slice());
            let mut ctx = BigNumContext::new().unwrap();
            let order = get_order();
            let b = BigNum::from_slice(&dig).unwrap();
            let mut r = BigNum::new().unwrap();
            r.nnmod(&b, &order, &mut ctx).unwrap();
            return Scalar { bn: r };
        }


        pub fn pow(&self, pow: u32) -> Scalar {
            let mut ctx = BigNumContext::new().unwrap();
            let order = get_order();

            let mut r = BigNum::new().unwrap();
            let bn_pow = BigNum::from_u32(pow).unwrap();
            r.mod_exp(&self.bn, &bn_pow, &order, &mut ctx).unwrap();
            return Scalar { bn: r };
        }

        pub fn inverse(&self) -> Scalar {
            let mut ctx = BigNumContext::new().unwrap();
            let mut r = BigNum::new().unwrap();
            let order = get_order();
            r.mod_inverse(&self.bn, &order, &mut ctx).unwrap();
            return Scalar { bn: r };
        }
    }

    impl Clone for Scalar {
        fn clone(&self) -> Scalar {
            return Scalar { bn: BigNum::from_slice(&self.bn.to_vec()).unwrap() };
        }
    }

    impl Add for Scalar {
        type Output = Self;
        fn add(self, s: Self) -> Self {
            let mut ctx = BigNumContext::new().unwrap();
            let order = get_order();

            let mut r = BigNum::new().unwrap();
            r.mod_add(&self.bn, &s.bn, &order, &mut ctx).unwrap();
            return Scalar { bn: r };
        }
    }

    impl Sub for Scalar {
        type Output = Self;
        fn sub(self, s: Self) -> Self {
            let mut ctx = BigNumContext::new().unwrap();
            let order = get_order();

            let mut r = BigNum::new().unwrap();
            r.mod_sub(&self.bn, &s.bn, &order, &mut ctx).unwrap();
            return Scalar { bn: r };
        }
    }

    impl Mul for Scalar {
        type Output = Self;
        fn mul(self, s: Self) -> Self {
            let mut ctx = BigNumContext::new().unwrap();
            let order = get_order();

            let mut r = BigNum::new().unwrap();
            r.mod_mul(&self.bn, &s.bn, &order, &mut ctx).unwrap();
            return Scalar { bn: r };
        }
    }

    impl PartialEq for Scalar {
        fn eq(&self, other: &Self) -> bool {
            return self.bn.to_vec() == other.bn.to_vec();
        }
    }

    impl Point {
        pub fn infinity() -> Point {
            return Point { point: get_point_at_infinity() };
        }

        pub fn generator() -> Point {
            return Point { point: curve_generator() };
        }

        pub fn from_scalar(s: &Scalar) -> Point {
            let mut ctx = BigNumContext::new().unwrap();
            let grp = get_grp();
            let mut p = EcPoint::new(&grp).unwrap();
            p.mul_generator(&grp, &s.bn, &mut ctx).unwrap();
            return Point { point: p };
        }

        pub fn mul(&self, s: &Scalar) -> Point {
            let grp = get_grp();
            let mut ctx = BigNumContext::new().unwrap();
            let mut r = EcPoint::new(&grp).unwrap();
            r.mul(&grp, &self.point, &s.bn, &mut ctx).unwrap();
            return Point { point: r };
        }

        pub fn inverse(&self) -> Point {
            let grp = get_grp();
            let mut ctx = BigNumContext::new().unwrap();
            let bytes = self.point.to_bytes(&grp, POINT_CONVERSION_UNCOMPRESSED, &mut ctx).unwrap();
            let mut p = EcPoint::from_bytes(&grp, &bytes, &mut ctx).unwrap();
            p.invert(&grp, &mut ctx).unwrap();
            return Point { point: p };
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let grp = get_grp();
            let mut ctx = BigNumContext::new().unwrap();
            return self.point.to_bytes(&grp, POINT_CONVERSION_COMPRESSED, &mut ctx).unwrap();
        }
    }

    impl Clone for Point {
        fn clone(&self) -> Point {
            let mut ctx = BigNumContext::new().unwrap();
            let grp = get_grp();
            let bytes = self.point.to_bytes(&grp, POINT_CONVERSION_UNCOMPRESSED, &mut ctx).unwrap();
            return Point { point: EcPoint::from_bytes(&grp, &bytes, &mut ctx).unwrap() };
        }
    }

    impl Add for Point {
        type Output = Self;
        fn add(self, p: Self) -> Self {
            let grp = get_grp();
            let mut ctx = BigNumContext::new().unwrap();
            let mut r = EcPoint::new(&grp).unwrap();
            r.add(&grp, &self.point, &p.point, &mut ctx).unwrap();
            return Point { point: r };
        }
    }
    impl Sub for Point {
        type Output = Point;
        fn sub(self, p: Self) -> Self {
            let grp = get_grp();
            let mut ctx = BigNumContext::new().unwrap();
            let p_inv = p.inverse();
            let mut r = EcPoint::new(&grp).unwrap();
            r.add(&grp, &self.point, &p_inv.point, &mut ctx).unwrap();
            return Point { point: r };
        }
    }

    impl PartialEq for Point {
        fn eq(&self, other: &Self) -> bool {
            let mut ctx = BigNumContext::new().unwrap();
            let grp = get_grp();
            let b1 = self.point.to_bytes(&grp, POINT_CONVERSION_UNCOMPRESSED, &mut ctx).unwrap();
            let b2 = other.point.to_bytes(&grp, POINT_CONVERSION_UNCOMPRESSED, &mut ctx).unwrap();
            return b1 == b2;
        }
    }
}

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
