// Concrete [`EcOperation`] implementation for the ristretto255 prime-order
// group (RFC 9496), backed by the `eccoxide` crate.
//
// Unlike the SEC2 short-Weierstrass curves, ristretto255 has a 32-byte canonical
// encoding (no sign byte), an Elligator-based hash-to-group that never fails,
// and conventionally derives challenges with SHA-512 reduced modulo the group
// order `l`. The [`EcOperation`]/[`Transcript`] abstraction accommodates all of
// this without any change to the rest of the crate.

use super::{EcOperation, Transcript};
use cryptoxide::hashing::sha2::{Context512, Sha512};
use eccoxide::curve::curve25519::Scalar;
use eccoxide::curve::curve25519::ristretto255::RistrettoPoint;

/// The ristretto255 prime-order group (RFC 9496).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ristretto255;

/// A SHA-512 Fiat–Shamir transcript reducing to a ristretto255 scalar (mod `l`).
///
/// The 64-byte digest is reduced with the standard wide (64-byte) reduction,
/// which — unlike a 32-byte canonical parse — is total and essentially unbiased.
pub struct Sha512Transcript {
    context: Context512,
}

impl Transcript for Sha512Transcript {
    type Scalar = Scalar;

    fn new() -> Self {
        Sha512Transcript {
            context: Context512::new(),
        }
    }

    fn new_sep(label: &[u8]) -> Self {
        Sha512Transcript {
            context: Context512::new().update(label),
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        self.context.update_mut(bytes);
    }

    fn challenge(self) -> Scalar {
        Scalar::init_from_wide_bytes(self.context.finalize())
    }
}

impl EcOperation for Ristretto255 {
    type Scalar = Scalar;
    type Point = RistrettoPoint;
    type Transcript = Sha512Transcript;

    fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Self::Scalar> {
        Scalar::from_bytes(bytes)
    }

    fn scalar_to_bytes(s: &Self::Scalar) -> Vec<u8> {
        s.to_bytes().to_vec()
    }

    fn point_to_bytes(p: &Self::Point) -> Vec<u8> {
        p.compress().to_vec()
    }

    fn point_from_bytes(slice: &[u8]) -> Option<Self::Point> {
        let bytes = <&[u8; 32]>::try_from(slice).ok()?;
        RistrettoPoint::decompress(bytes).into_option()
    }

    fn point_try_hash_to_curve(slice: &[u8]) -> Option<Self::Point> {
        // The ristretto255 one-way map is total, so this never fails.
        Some(Self::point_hash_to_curve(slice))
    }

    fn point_hash_to_curve(slice: &[u8]) -> Self::Point {
        let digest = Sha512::new().update(slice).finalize();
        RistrettoPoint::from_uniform_bytes(&digest)
    }
}
