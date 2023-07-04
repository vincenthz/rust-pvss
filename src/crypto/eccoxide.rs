use cryptoxide::drg::chacha;
use cryptoxide::hashing::sha2::Sha256;
use eccoxide::curve::sec2::p256r1 as curve;
use std::convert::TryFrom;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;

// currently hardcode curve to P256R1, but in the future probably a good idea
// to generalize the interface, and make it more generics (with generics for all crypto types)
//pub const CURVE: openssl::nid::Nid = openssl::nid::Nid::X9_62_PRIME256V1;

pub struct Drg(chacha::Drg<8>);

impl Drg {
    pub fn new() -> Self {
        loop {
            let mut out = [0u8; 32];
            if let Err(_) = getrandom::getrandom(&mut out) {
                continue;
            }
            let drg = chacha::Drg::new(&out);
            return Drg(drg);
        }
    }
}

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
            scalar: Scalar::from_slice(bytes).unwrap(),
        }
    }
}

pub fn create_keypair(drg: &mut Drg) -> (PublicKey, PrivateKey) {
    let s = Scalar::generate(drg);
    let p = Point::from_scalar(&s);
    (PublicKey { point: p }, PrivateKey { scalar: s })
}

pub struct PointHasher {
    context: cryptoxide::hashing::sha2::Context256,
}

impl PointHasher {
    pub fn new() -> Self {
        PointHasher {
            context: cryptoxide::hashing::sha2::Context256::new(),
        }
    }

    pub fn update_mut(&mut self, p: &Point) {
        self.context.update_mut(&p.to_bytes());
    }

    pub fn update(self, p: &Point) -> Self {
        Self {
            context: self.context.update(&p.to_bytes()),
        }
    }

    pub fn update_iter<'a, I: Iterator<Item = &'a Point>>(self, it: I) -> Self {
        let mut context = self.context;
        for i in it {
            context = context.update(&i.to_bytes())
        }
        Self { context }
    }

    pub fn finalize(self) -> Scalar {
        let dig = self.context.finalize();
        // TODO need to modularise dig !
        Scalar {
            bn: curve::Scalar::from_bytes(&dig).unwrap(),
        }
    }
}

impl Scalar {
    pub fn from_u32(v: u32) -> Scalar {
        Scalar {
            bn: curve::Scalar::from_u64(v as u64),
        }
    }

    pub fn generate(drg: &mut Drg) -> Scalar {
        loop {
            let out = drg.0.bytes();
            if let Some(scalar) = Scalar::from_bytes(&out) {
                return scalar;
            }
        }
    }

    pub fn multiplicative_identity() -> Scalar {
        Self::from_u32(1)
    }

    pub fn hash_points(points: Vec<&Point>) -> Scalar {
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

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
        curve::Scalar::from_bytes(bytes).map(|s| Scalar { bn: s })
    }

    pub fn from_slice(slice: &[u8]) -> Option<Scalar> {
        let bytes = <&[u8; 32]>::try_from(slice).ok()?;
        curve::Scalar::from_bytes(bytes).map(|s| Scalar { bn: s })
    }
}

impl Add for Scalar {
    type Output = Self;
    fn add(self, s: Self) -> Self {
        Scalar { bn: self.bn + s.bn }
    }
}

impl<'a> Add for &'a Scalar {
    type Output = Scalar;
    fn add(self, s: Self) -> Self::Output {
        Scalar {
            bn: &self.bn + &s.bn,
        }
    }
}

impl Sub for Scalar {
    type Output = Self;
    fn sub(self, s: Self) -> Self {
        Scalar { bn: self.bn - s.bn }
    }
}

impl<'a> Sub for &'a Scalar {
    type Output = Scalar;
    fn sub(self, s: Self) -> Self::Output {
        Scalar {
            bn: &self.bn - &s.bn,
        }
    }
}

impl Mul for Scalar {
    type Output = Self;
    fn mul(self, s: Self) -> Self {
        Scalar { bn: self.bn * s.bn }
    }
}

impl<'a> Mul for &'a Scalar {
    type Output = Scalar;
    fn mul(self, s: Self) -> Self::Output {
        Scalar {
            bn: &self.bn * &s.bn,
        }
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

    pub fn try_hash_to_curve(slice: &[u8]) -> Option<Point> {
        let out = Sha256::new().update(slice).finalize();
        if let Some(x) = curve::FieldElement::from_bytes(&out) {
            if let Some(p) = curve::PointAffine::decompress(&x, eccoxide::curve::Sign::Positive) {
                return Some(Self {
                    point: curve::Point::from_affine(&p),
                });
            }
        }
        None
    }

    pub fn hash_to_curve(slice: &[u8]) -> Point {
        let mut counter_slice = [0u8];
        loop {
            let out = Sha256::new()
                .update(slice)
                .update(&counter_slice)
                .finalize();
            if let Some(x) = curve::FieldElement::from_bytes(&out) {
                if let Some(p) = curve::PointAffine::decompress(&x, eccoxide::curve::Sign::Positive)
                {
                    return Self {
                        point: curve::Point::from_affine(&p),
                    };
                }
            }

            counter_slice[0] = counter_slice[0] + 1;
        }
    }

    pub fn random_generator(drg: &mut Drg) -> Point {
        loop {
            let out = drg.0.bytes::<32>();
            if let Some(point) = Self::try_hash_to_curve(&out) {
                return point;
            }
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
