use openssl;
use openssl::ec::*;
use openssl::bn::*;
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

#[derive(PartialEq)]
pub struct PrivateKey {
    pub scalar: Scalar,
}

#[derive(PartialEq)]
pub struct PublicKey {
    pub point: Point,
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        let mut ctx = BigNumContext::new().unwrap();
        PublicKey {
            point: Point {
                point: EcPoint::from_bytes(&get_grp(), bytes, &mut ctx)
                    .expect("Could not create PublicKey from bytes")
            }
        }
    }
}

impl PrivateKey {
    // to_hex_str?? https://docs.rs/openssl/0.9.14/openssl/bn/struct.BigNum.html#method.to_hex_str
    pub fn to_bytes(&self) -> Vec<u8> {
        self.scalar.bn.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> PrivateKey {
        PrivateKey {
            scalar: Scalar {
                bn: BigNum::from_slice(bytes).expect("Could not create PrivateKey from bytes")
            }
        }
    }
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

    pub fn multiplicative_identity() -> Scalar {
        return Self::from_u32(1);
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
