// Curve-agnostic cryptographic primitives used by the PVSS schemes.
//
// The elliptic curve is abstracted behind the [`EcOperation`] trait so a scheme
// can be instantiated over any curve (e.g. P-256, secp256k1, Ristretto255, ...)
// simply by providing an implementation of that trait. The scalar and point
// types used throughout the rest of the crate are the curve-generic wrappers
// [`Scalar<C>`] and [`Point<C>`], which delegate every operation to `C`.

mod ristretto;
mod sec2;

pub use self::ristretto::*;
pub use self::sec2::*;

use core::marker::PhantomData;
use cryptoxide::drg::chacha;
use cryptoxide::hashing::sha2;
use eccoxide::curve::field::Field;
use eccoxide::curve::group::CurveGroup;
use std::ops::{Add, Mul, Sub};

/// Deterministic random generator used to sample scalars and points.
pub struct Drg(chacha::Drg<8>);

impl Drg {
    pub fn new() -> Self {
        loop {
            let mut out = [0u8; 32];
            if let Err(_) = getrandom::fill(&mut out) {
                continue;
            }
            let drg = chacha::Drg::new(&out);
            return Drg(drg);
        }
    }
}

/// A Fiat–Shamir transcript: it absorbs the byte encodings of the protocol
/// messages (points and domain-separation labels) and squeezes out a scalar
/// challenge.
///
/// Making this an associated type of [`EcOperation`] keeps the hashing flexible:
/// an implementation is free to pick both the hash function and the reduction
/// to a scalar. [`HashTranscript`] is a ready-made, curve-size-agnostic
/// implementation that all the built-in curves use.
pub trait Transcript {
    /// Scalar type the transcript reduces to.
    type Scalar;
    /// Start a fresh transcript.
    fn new() -> Self;
    /// Start a fresh transcript seeded with a domain-separation label.
    fn new_sep(label: &[u8]) -> Self;
    /// Absorb a message chunk into the transcript.
    fn absorb(&mut self, bytes: &[u8]);
    /// Squeeze the challenge scalar out of the transcript.
    fn challenge(self) -> Self::Scalar;
}

/// A hash function that can drive a [`HashTranscript`].
///
/// It exposes an incremental hashing context (to absorb the transcript) and a
/// finalization to a digest. [`HashTranscript`] also runs it in counter mode
/// (see [`hash_expand`]) to squeeze out as many bytes as the scalar field needs,
/// so any fixed-length hash works for a curve of any size. [`Sha256`] and
/// [`Sha512`] are provided.
pub trait TranscriptHash {
    /// Incremental hashing state.
    type Context;
    /// Start a new hashing context.
    fn init() -> Self::Context;
    /// Absorb a message chunk.
    fn absorb(context: &mut Self::Context, bytes: &[u8]);
    /// Finalize into a digest.
    fn finalize(context: Self::Context) -> Vec<u8>;
}

/// SHA-256 as a [`TranscriptHash`].
pub enum Sha256 {}

impl TranscriptHash for Sha256 {
    type Context = sha2::Context256;
    fn init() -> Self::Context {
        sha2::Context256::new()
    }
    fn absorb(context: &mut Self::Context, bytes: &[u8]) {
        context.update_mut(bytes);
    }
    fn finalize(context: Self::Context) -> Vec<u8> {
        context.finalize().to_vec()
    }
}

/// SHA-512 as a [`TranscriptHash`].
pub enum Sha512 {}

impl TranscriptHash for Sha512 {
    type Context = sha2::Context512;
    fn init() -> Self::Context {
        sha2::Context512::new()
    }
    fn absorb(context: &mut Self::Context, bytes: &[u8]) {
        context.update_mut(bytes);
    }
    fn finalize(context: Self::Context) -> Vec<u8> {
        context.finalize().to_vec()
    }
}

/// Expand `parts` into `out.len()` bytes of output using the hash `H` in
/// counter mode (MGF1-style): `out = H(parts.. || 0u32) || H(parts.. || 1u32) || ...`.
///
/// A fixed-length hash (e.g. SHA-512, 64 bytes) can thus produce the arbitrary
/// byte count a larger curve needs — e.g. the `2 * SCALAR_BYTES` = 132 bytes
/// required to reduce into a P-521 scalar.
pub(crate) fn hash_expand<H: TranscriptHash>(parts: &[&[u8]], out: &mut [u8]) {
    let mut block: u32 = 0;
    let mut off = 0;
    while off < out.len() {
        let mut context = H::init();
        for p in parts {
            H::absorb(&mut context, p);
        }
        H::absorb(&mut context, &block.to_be_bytes());
        let digest = H::finalize(context);
        let n = core::cmp::min(digest.len(), out.len() - off);
        out[off..off + n].copy_from_slice(&digest[..n]);
        off += n;
        block = block.wrapping_add(1);
    }
}

/// A curve-size-agnostic Fiat–Shamir transcript, parameterized by its hash `H`.
///
/// The transcript is absorbed with `H`; on [`challenge`](Transcript::challenge)
/// the digest is expanded (see [`hash_expand`]) to `2 * C::SCALAR_BYTES` bytes
/// and reduced to a scalar via [`EcOperation::scalar_from_wide_bytes`]. The wide
/// input makes the reduction essentially unbiased for a field of any size, so
/// this works unchanged for 256-bit curves and for P-384 / P-521 alike.
pub struct HashTranscript<C: EcOperation, H: TranscriptHash> {
    context: H::Context,
    _curve: PhantomData<C>,
}

impl<C: EcOperation, H: TranscriptHash> Transcript for HashTranscript<C, H> {
    type Scalar = C::Scalar;

    fn new() -> Self {
        HashTranscript {
            context: H::init(),
            _curve: PhantomData,
        }
    }

    fn new_sep(label: &[u8]) -> Self {
        let mut context = H::init();
        H::absorb(&mut context, label);
        HashTranscript {
            context,
            _curve: PhantomData,
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        H::absorb(&mut self.context, bytes);
    }

    fn challenge(self) -> C::Scalar {
        let seed = H::finalize(self.context);
        let mut buf = vec![0u8; 2 * C::SCALAR_BYTES];
        hash_expand::<H>(&[&seed], &mut buf);
        C::scalar_from_wide_bytes(&buf)
    }
}

/// Abstraction over the elliptic-curve operations required by the PVSS schemes.
///
/// An implementor is a (usually zero-sized) marker type identifying a specific
/// curve. Rather than re-declaring the group and field arithmetic, this trait
/// builds directly on eccoxide's own abstractions: the associated
/// [`Scalar`](EcOperation::Scalar) is a [`Field`] and the associated
/// [`Point`](EcOperation::Point) is a [`CurveGroup`] over that field. Those two
/// traits already provide the arithmetic (`+ - *`, negation, inversion, scalar
/// multiplication, identity/generator, `From<u64>`, ...), which the
/// curve-generic wrappers [`Scalar<C>`] and [`Point<C>`] use directly.
///
/// What remains here are only the operations eccoxide's traits do *not* cover:
/// byte (de)serialization, hashing to the group, and the choice of Fiat–Shamir
/// [`Transcript`](EcOperation::Transcript).
///
/// # Adding a new curve
///
/// Provide a marker type and `impl EcOperation for MyCurve`. The rest of the
/// crate (`dleq`, `pdleq`, `simple`, `scrape`, ...) is generic over `C` and will
/// work without further changes.
pub trait EcOperation: Clone {
    /// Element of the scalar field (`Z/nZ` where `n` is the group order); its
    /// arithmetic is provided by eccoxide's [`Field`].
    type Scalar: Field;
    /// Element of the elliptic-curve group; its group law is provided by
    /// eccoxide's [`CurveGroup`], with scalars in [`Self::Scalar`].
    type Point: CurveGroup<Scalar = Self::Scalar>;
    /// Fiat–Shamir transcript used to derive challenge scalars for this curve.
    type Transcript: Transcript<Scalar = Self::Scalar>;

    /// Length in bytes of a scalar's canonical serialization (e.g. 32 for a
    /// 256-bit curve, 48 for P-384, 66 for P-521). No fixed width is assumed
    /// anywhere else in the crate.
    const SCALAR_BYTES: usize;

    /// Interpret a canonical scalar serialization (`SCALAR_BYTES` long),
    /// returning `None` if it is the wrong length or not a valid representation.
    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar>;
    /// Reduce a wide, uniformly-random buffer (`2 * SCALAR_BYTES` long) to a
    /// scalar. Used to derive challenge scalars and to sample random scalars
    /// without modulo bias, for a field of any size.
    fn scalar_from_wide_bytes(bytes: &[u8]) -> Self::Scalar;
    /// Serialize a scalar to its canonical byte representation.
    fn scalar_to_bytes(s: &Self::Scalar) -> Vec<u8>;

    /// Serialize a point to its canonical byte representation.
    fn point_to_bytes(p: &Self::Point) -> Vec<u8>;
    /// Deserialize a point from bytes, returning `None` on invalid input.
    fn point_from_bytes(bytes: &[u8]) -> Option<Self::Point>;

    /// Try to hash arbitrary bytes to a group element (may fail for a given input).
    fn point_try_hash_to_curve(data: &[u8]) -> Option<Self::Point>;
    /// Hash arbitrary bytes to a group element, retrying internally until it succeeds.
    fn point_hash_to_curve(data: &[u8]) -> Self::Point;
}

/// A scalar of the curve `C`.
pub struct Scalar<C: EcOperation> {
    inner: C::Scalar,
}

impl<C: EcOperation> Clone for Scalar<C> {
    fn clone(&self) -> Self {
        Scalar {
            inner: self.inner.clone(),
        }
    }
}

impl<C: EcOperation> PartialEq for Scalar<C> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<C: EcOperation> Scalar<C> {
    pub fn from_u32(v: u32) -> Scalar<C> {
        Scalar {
            inner: C::Scalar::from(v as u64),
        }
    }

    pub fn generate(drg: &mut Drg) -> Scalar<C> {
        // Sample `2 * SCALAR_BYTES` uniform bytes and reduce them: this is total
        // (no rejection loop) and unbiased for a field of any size.
        let mut buf = vec![0u8; 2 * C::SCALAR_BYTES];
        drg.0.fill_slice(&mut buf);
        Scalar {
            inner: C::scalar_from_wide_bytes(&buf),
        }
    }

    pub fn multiplicative_identity() -> Scalar<C> {
        Self::from_u32(1)
    }

    pub fn hash_points(points: Vec<&Point<C>>) -> Scalar<C> {
        let mut hasher = PointHasher::<C>::new();
        for p in points {
            hasher.update_mut(p);
        }
        hasher.finalize()
    }

    pub fn pow(&self, pow: u32) -> Scalar<C> {
        // square-and-multiply over the (public) exponent, using only the field
        // arithmetic from eccoxide's `Field` trait.
        let mut result = C::Scalar::ONE;
        let mut base = self.inner.clone();
        let mut exp = pow;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * &base;
            }
            exp >>= 1;
            if exp > 0 {
                base = base.square();
            }
        }
        Scalar { inner: result }
    }

    pub fn inverse(&self) -> Scalar<C> {
        Scalar {
            inner: self.inner.inverse(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Scalar<C>> {
        C::scalar_from_bytes(bytes).map(|inner| Scalar { inner })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        C::scalar_to_bytes(&self.inner)
    }
}

impl<C: EcOperation> Add for Scalar<C> {
    type Output = Scalar<C>;
    fn add(self, s: Self) -> Scalar<C> {
        Scalar {
            inner: self.inner + s.inner,
        }
    }
}

impl<'a, C: EcOperation> Add for &'a Scalar<C> {
    type Output = Scalar<C>;
    fn add(self, s: Self) -> Scalar<C> {
        Scalar {
            inner: self.inner.clone() + &s.inner,
        }
    }
}

impl<C: EcOperation> Sub for Scalar<C> {
    type Output = Scalar<C>;
    fn sub(self, s: Self) -> Scalar<C> {
        Scalar {
            inner: self.inner - s.inner,
        }
    }
}

impl<'a, C: EcOperation> Sub for &'a Scalar<C> {
    type Output = Scalar<C>;
    fn sub(self, s: Self) -> Scalar<C> {
        Scalar {
            inner: self.inner.clone() - &s.inner,
        }
    }
}

impl<C: EcOperation> Mul for Scalar<C> {
    type Output = Scalar<C>;
    fn mul(self, s: Self) -> Scalar<C> {
        Scalar {
            inner: self.inner * s.inner,
        }
    }
}

impl<'a, C: EcOperation> Mul for &'a Scalar<C> {
    type Output = Scalar<C>;
    fn mul(self, s: Self) -> Scalar<C> {
        Scalar {
            inner: self.inner.clone() * &s.inner,
        }
    }
}

/// A point of the curve `C`.
pub struct Point<C: EcOperation> {
    inner: C::Point,
}

impl<C: EcOperation> Clone for Point<C> {
    fn clone(&self) -> Self {
        Point {
            inner: self.inner.clone(),
        }
    }
}

impl<C: EcOperation> PartialEq for Point<C> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<C: EcOperation> Point<C> {
    pub fn infinity() -> Point<C> {
        Point {
            inner: C::Point::IDENTITY,
        }
    }

    pub fn generator() -> Point<C> {
        Point {
            inner: C::Point::GENERATOR,
        }
    }

    pub fn try_hash_to_curve(slice: &[u8]) -> Option<Point<C>> {
        C::point_try_hash_to_curve(slice).map(|inner| Point { inner })
    }

    pub fn hash_to_curve(slice: &[u8]) -> Point<C> {
        Point {
            inner: C::point_hash_to_curve(slice),
        }
    }

    pub fn random_generator(drg: &mut Drg) -> Point<C> {
        // Seed with as many random bytes as the field is wide, so the generator
        // is sampled with adequate entropy on curves of any size.
        let mut seed = vec![0u8; 2 * C::SCALAR_BYTES];
        loop {
            drg.0.fill_slice(&mut seed);
            if let Some(point) = Self::try_hash_to_curve(&seed) {
                return point;
            }
        }
    }

    pub fn from_scalar(s: &Scalar<C>) -> Point<C> {
        Point {
            inner: C::Point::mul_base(&s.inner),
        }
    }

    pub fn mul(&self, s: &Scalar<C>) -> Point<C> {
        Point {
            inner: self.inner.clone() * &s.inner,
        }
    }

    pub fn inverse(&self) -> Point<C> {
        Point {
            inner: -self.inner.clone(),
        }
    }

    pub fn from_bytes(slice: &[u8]) -> Option<Point<C>> {
        C::point_from_bytes(slice).map(|inner| Point { inner })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        C::point_to_bytes(&self.inner)
    }
}

impl<C: EcOperation> Add for Point<C> {
    type Output = Point<C>;
    fn add(self, p: Self) -> Point<C> {
        Point {
            inner: self.inner + p.inner,
        }
    }
}

impl<C: EcOperation> Sub for Point<C> {
    type Output = Point<C>;
    fn sub(self, p: Self) -> Point<C> {
        Point {
            inner: self.inner - p.inner,
        }
    }
}

/// Fiat–Shamir transcript hasher, specialized to absorb curve points.
///
/// Points are absorbed through their canonical byte encoding into the curve's
/// [`Transcript`](EcOperation::Transcript); [`finalize`](PointHasher::finalize)
/// squeezes out a challenge scalar of the curve `C`. The concrete hash function
/// is chosen by the curve, not hardcoded here.
pub struct PointHasher<C: EcOperation> {
    transcript: C::Transcript,
}

impl<C: EcOperation> PointHasher<C> {
    pub fn new() -> Self {
        PointHasher {
            transcript: C::Transcript::new(),
        }
    }

    pub fn new_sep(label: &[u8]) -> Self {
        PointHasher {
            transcript: C::Transcript::new_sep(label),
        }
    }

    pub fn update_mut(&mut self, p: &Point<C>) {
        self.transcript.absorb(&p.to_bytes());
    }

    pub fn update(mut self, p: &Point<C>) -> Self {
        self.transcript.absorb(&p.to_bytes());
        self
    }

    pub fn update_iter<'a, I: Iterator<Item = &'a Point<C>>>(mut self, it: I) -> Self
    where
        C: 'a,
    {
        for i in it {
            self.transcript.absorb(&i.to_bytes());
        }
        self
    }

    pub fn finalize(self) -> Scalar<C> {
        Scalar {
            inner: self.transcript.challenge(),
        }
    }
}

pub struct PrivateKey<C: EcOperation> {
    pub scalar: Scalar<C>,
}

pub struct PublicKey<C: EcOperation> {
    pub point: Point<C>,
}

impl<C: EcOperation> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        PublicKey {
            point: self.point.clone(),
        }
    }
}

impl<C: EcOperation> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl<C: EcOperation> PartialEq for PrivateKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.scalar == other.scalar
    }
}

impl<C: EcOperation> PublicKey<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> PublicKey<C> {
        PublicKey {
            point: Point::from_bytes(bytes).unwrap(),
        }
    }
}

impl<C: EcOperation> PrivateKey<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.scalar.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> PrivateKey<C> {
        PrivateKey {
            scalar: Scalar::from_bytes(bytes).unwrap(),
        }
    }
}

pub fn create_keypair<C: EcOperation>(drg: &mut Drg) -> (PublicKey<C>, PrivateKey<C>) {
    let s = Scalar::generate(drg);
    let p = Point::from_scalar(&s);
    (PublicKey { point: p }, PrivateKey { scalar: s })
}
