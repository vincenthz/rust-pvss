// [`EcOperation`] implementations for the SEC2 short-Weierstrass curves.
//
// The group and field arithmetic comes from eccoxide's `CurveGroup`/`Field`
// traits (see `EcOperation`), so all these implementations provide is the
// point/scalar byte encoding and the hash-to-curve. Everything is expressed in
// terms of the curve's own `SIZE_BYTES`, so the same macro instantiates a
// 256-bit curve or P-384 / P-521 without any width being hardcoded.

use super::{EcOperation, HashTranscript, Sha256, Sha512, hash_expand};
use eccoxide::curve::Sign;
use eccoxide::curve::sec2::{p256k1, p256r1, p384r1, p521r1};

/// Implement [`EcOperation`] for a SEC2 short-Weierstrass curve module.
///
/// `$curve` must be a module exposing the standard eccoxide `Scalar`, `Point`,
/// `PointAffine` and `FieldElement` types (as generated for every `sec2` curve).
/// `$hash` is the [`TranscriptHash`] this curve uses for challenge derivation
/// and hash-to-curve.
macro_rules! impl_sec2_weierstrass {
    ($(#[$meta:meta])* $name:ident => $curve:ident, $hash:ty) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name;

        impl EcOperation for $name {
            type Scalar = $curve::Scalar;
            type Point = $curve::Point;
            type Transcript = HashTranscript<$name, $hash>;

            const SCALAR_BYTES: usize = $curve::Scalar::SIZE_BYTES;

            fn scalar_from_bytes(bytes: &[u8]) -> Option<Self::Scalar> {
                let arr = <[u8; $curve::Scalar::SIZE_BYTES]>::try_from(bytes).ok()?;
                $curve::Scalar::from_bytes(&arr)
            }

            fn scalar_from_wide_bytes(bytes: &[u8]) -> Self::Scalar {
                // eccoxide's wide reduction reduces exactly `2 * SIZE_BYTES`
                // bytes modulo the group order; the array width is inferred.
                $curve::Scalar::init_from_wide_bytes(
                    bytes
                        .try_into()
                        .expect("wide scalar buffer must be 2 * SCALAR_BYTES"),
                )
            }

            fn scalar_to_bytes(s: &Self::Scalar) -> Vec<u8> {
                s.to_bytes().to_vec()
            }

            fn point_to_bytes(p: &Self::Point) -> Vec<u8> {
                // compressed encoding: a sign byte followed by the x coordinate,
                // whose length is the field's `SIZE_BYTES` (32, 48, 66, ...).
                let affine = p.to_affine().unwrap();
                let (fe, sign) = affine.compress();
                let lead = match sign {
                    Sign::Positive => 0x2,
                    Sign::Negative => 0x3,
                };
                let mut out = vec![lead];
                out.extend_from_slice(&fe.to_bytes());
                out
            }

            fn point_from_bytes(slice: &[u8]) -> Option<Self::Point> {
                if slice.len() != 1 + $curve::FieldElement::SIZE_BYTES {
                    return None;
                }
                let sign = match slice[0] {
                    0x2 => Sign::Positive,
                    0x3 => Sign::Negative,
                    _ => return None,
                };
                let arr = <[u8; $curve::FieldElement::SIZE_BYTES]>::try_from(&slice[1..]).ok()?;
                let fe = $curve::FieldElement::from_bytes(&arr)?;
                let pa = $curve::PointAffine::decompress(&fe, sign)?;
                Some($curve::Point::from_affine(&pa))
            }

            fn point_try_hash_to_curve(slice: &[u8]) -> Option<Self::Point> {
                let mut buf = vec![0u8; $curve::FieldElement::SIZE_BYTES];
                hash_expand::<$hash>(&[slice], &mut buf);
                let arr = <[u8; $curve::FieldElement::SIZE_BYTES]>::try_from(buf.as_slice())
                    .expect("expanded buffer is FieldElement::SIZE_BYTES long");
                let x = $curve::FieldElement::from_bytes(&arr)?;
                let pa = $curve::PointAffine::decompress(&x, Sign::Positive)?;
                Some($curve::Point::from_affine(&pa))
            }

            fn point_hash_to_curve(slice: &[u8]) -> Self::Point {
                // hash `slice || retry` to a field-sized candidate x coordinate,
                // incrementing `retry` until it lands on the curve.
                let mut retry: u32 = 0;
                loop {
                    let mut buf = vec![0u8; $curve::FieldElement::SIZE_BYTES];
                    hash_expand::<$hash>(&[slice, &retry.to_be_bytes()], &mut buf);
                    let arr = <[u8; $curve::FieldElement::SIZE_BYTES]>::try_from(buf.as_slice())
                        .expect("expanded buffer is FieldElement::SIZE_BYTES long");
                    if let Some(x) = $curve::FieldElement::from_bytes(&arr) {
                        if let Some(p) = $curve::PointAffine::decompress(&x, Sign::Positive) {
                            return $curve::Point::from_affine(&p);
                        }
                    }
                    retry = retry.wrapping_add(1);
                }
            }
        }
    };
}

impl_sec2_weierstrass!(
    /// The NIST P-256 curve (a.k.a. secp256r1 / prime256v1).
    P256r1 => p256r1, Sha256
);

impl_sec2_weierstrass!(
    /// The secp256k1 curve, as used by Bitcoin and Ethereum.
    P256k1 => p256k1, Sha256
);

impl_sec2_weierstrass!(
    /// The NIST P-384 curve (a.k.a. secp384r1).
    P384r1 => p384r1, Sha512
);

impl_sec2_weierstrass!(
    /// The NIST P-521 curve (a.k.a. secp521r1).
    P521r1 => p521r1, Sha512
);
