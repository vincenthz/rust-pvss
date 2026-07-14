// Concrete [`EcOperation`] implementation for the ristretto255 prime-order
// group (RFC 9496), backed by the `eccoxide` crate.
//
// Unlike the SEC2 short-Weierstrass curves, ristretto255 has a 32-byte canonical
// encoding (no sign byte) and an Elligator-based hash-to-group that never fails.
// Its scalar arithmetic comes from eccoxide's `Field`/`CurveGroup` traits (see
// `EcOperation`); challenge derivation uses the shared [`HashTranscript`], whose
// SHA-512 + wide reduction is exactly the standard ristretto255 construction
// (`2 * SCALAR_BYTES` = 64 bytes reduced modulo the group order `l`).

use super::{EcOperation, HashTranscript, Sha512};
use cryptoxide::hashing::sha2;
use eccoxide::curve::curve25519::Scalar;
use eccoxide::curve::curve25519::ristretto255::RistrettoPoint;

/// The ristretto255 prime-order group (RFC 9496).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ristretto255;

impl EcOperation for Ristretto255 {
    type Scalar = Scalar;
    type Point = RistrettoPoint;
    type Transcript = HashTranscript<Self, Sha512>;

    const SCALAR_BYTES: usize = Scalar::SIZE_BYTES;

    fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar> {
        let arr = <[u8; Scalar::SIZE_BYTES]>::try_from(bytes).ok()?;
        Scalar::from_bytes(&arr)
    }

    fn scalar_from_wide_bytes(bytes: &[u8]) -> Self::Scalar {
        Scalar::init_from_wide_bytes(
            bytes
                .try_into()
                .expect("wide scalar buffer must be 2 * SCALAR_BYTES"),
        )
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
        // ristretto's one-way map consumes exactly 64 uniform bytes, i.e. a
        // single SHA-512 digest (its standard hash-to-group instantiation).
        let digest = sha2::Sha512::new().update(slice).finalize();
        RistrettoPoint::from_uniform_bytes(&digest)
    }
}
