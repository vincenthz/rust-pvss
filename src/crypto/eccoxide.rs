use eccoxide::curve::sec2::p256r1 as curve;
use std::convert::TryFrom;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;

// currently hardcode curve to P256R1, but in the future probably a good idea
// to generalize the interface, and make it more generics (with generics for all crypto types)
//pub const CURVE: openssl::nid::Nid = openssl::nid::Nid::X9_62_PRIME256V1;

#[derive(Clone)]
pub struct Scalar {
    bn: curve::Scalar,
}

#[derive(Clone)]
pub struct Point {
    point: curve::Point,
}

#[derive(PartialEq)]
pub struct PrivateKey {
    pub scalar: Scalar,
}

#[derive(PartialEq, Clone)]
pub struct PublicKey {
    pub point: Point,
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> PublicKey {
        PublicKey {
            point: Point::from_bytes(bytes).unwrap(),
        }
    }
}

impl PrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.scalar.bn.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> PrivateKey {
        PrivateKey {
            scalar: Scalar::from_bytes(bytes).unwrap(),
        }
    }
}

pub fn create_keypair() -> (PublicKey, PrivateKey) {
    let s = Scalar::generate();
    let p = Point::from_scalar(&s);
    (PublicKey { point: p }, PrivateKey { scalar: s })
}

impl Scalar {
    pub fn from_u32(v: u32) -> Scalar {
        Scalar {
            bn: curve::Scalar::from_u64(v as u64),
        }
    }
    pub fn generate() -> Scalar {
        loop {
            let mut out = [0u8; 32];
            if let Err(_) = getrandom::getrandom(&mut out) {
                continue;
            }
            if let Some(scalar) = Scalar::from_bytes(&out) {
                return scalar;
            }
        }
    }

    pub fn multiplicative_identity() -> Scalar {
        Self::from_u32(1)
    }

    pub fn hash_points(points: Vec<Point>) -> Scalar {
        let mut context = cryptoxide::hashing::sha2::Context256::new();

        for p in points {
            context.update_mut(&p.to_bytes());
        }
        let dig = context.finalize();
        // TODO need to modularise dig !
        Scalar {
            bn: curve::Scalar::from_bytes(&dig).unwrap(),
        }
    }

    pub fn pow(&self, pow: u32) -> Scalar {
        Scalar {
            bn: self.bn.power_u64(pow as u64),
        }
    }

    pub fn inverse(&self) -> Scalar {
        Scalar {
            bn: self.bn.inverse(),
        }
    }

    pub fn from_bytes(slice: &[u8]) -> Option<Scalar> {
        let bytes = <&[u8; 32]>::try_from(slice).ok()?;
        curve::Scalar::from_bytes(bytes).map(|s| Scalar { bn: s })
    }
}

/*
impl Clone for Scalar {
    fn clone(&self) -> Scalar {
        Scalar {
            bn: BigNum::from_slice(&self.bn.to_vec()).unwrap(),
        }
    }
}
*/

impl Add for Scalar {
    type Output = Self;
    fn add(self, s: Self) -> Self {
        Scalar { bn: self.bn + s.bn }
    }
}

impl Sub for Scalar {
    type Output = Self;
    fn sub(self, s: Self) -> Self {
        Scalar { bn: self.bn - s.bn }
    }
}

impl Mul for Scalar {
    type Output = Self;
    fn mul(self, s: Self) -> Self {
        Scalar { bn: self.bn * s.bn }
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.bn.eq(&other.bn)
    }
}

impl Point {
    pub fn infinity() -> Point {
        Point {
            point: curve::Point::infinity(),
        }
    }

    pub fn generator() -> Point {
        Point {
            point: curve::Point::generator(),
        }
    }

    pub fn from_scalar(s: &Scalar) -> Point {
        let g = curve::Point::generator();
        Point { point: &g * &s.bn }
    }

    pub fn mul(&self, s: &Scalar) -> Point {
        Point {
            point: &self.point * &s.bn,
        }
    }

    pub fn inverse(&self) -> Point {
        Point {
            point: -self.point.clone(),
        }
    }

    pub fn from_bytes(slice: &[u8]) -> Option<Point> {
        if slice.len() != 33 {
            return None;
        }
        let sign = match slice[0] {
            0x2 => eccoxide::curve::Sign::Positive,
            0x3 => eccoxide::curve::Sign::Negative,
            _ => return None,
        };
        let bytes = <&[u8; 32]>::try_from(&slice[1..]).unwrap();
        let fe = curve::FieldElement::from_bytes(bytes)?;

        let pa = curve::PointAffine::decompress(&fe, sign)?;
        Some(Point {
            point: curve::Point::from_affine(&pa),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let p = self.point.to_affine().unwrap();
        let (fe, sign) = p.compress();
        let lead = match sign {
            eccoxide::curve::Sign::Positive => 0x2,
            eccoxide::curve::Sign::Negative => 0x3,
        };
        let mut out = vec![lead];
        out.extend_from_slice(&fe.to_bytes());
        out
    }
}

impl Add for Point {
    type Output = Self;
    fn add(self, p: Self) -> Self {
        Point {
            point: self.point + p.point,
        }
    }
}

impl Sub for Point {
    type Output = Self;
    fn sub(self, p: Self) -> Self {
        Point {
            point: self.point - p.point,
        }
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.point.eq(&other.point)
    }
}
