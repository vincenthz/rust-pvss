// [`EcOperation`] implementations for the SEC2 short-Weierstrass curves.
//
// The group and field arithmetic comes from eccoxide's `CurveGroup`/`Field`
// traits (see `EcOperation`), so all these implementations need to provide is
// the point/scalar byte encoding, the hash-to-curve, and the SHA-256 transcript.
// The SEC2 curves share the exact same generated API, so a single macro
// instantiates the trait for each of them.

use super::{EcOperation, Transcript};
use core::marker::PhantomData;
use cryptoxide::hashing::sha2::{Context256, Sha256};
use eccoxide::curve::Sign;
use eccoxide::curve::sec2::{p256k1, p256r1};

/// A SHA-256 Fiat–Shamir transcript reducing to the scalar field of the curve
/// `C`. Reusable by any curve whose transcript is SHA-256 based; the SEC2
/// curves below use it.
///
/// The 32-byte digest is interpreted as a canonical scalar; for the ~256-bit
/// order SEC2 curves the probability of a digest landing outside the field is
/// negligible, matching the crate's original challenge derivation.
pub struct Sha256Transcript<C: EcOperation> {
    context: Context256,
    _curve: PhantomData<C>,
}

impl<C: EcOperation> Transcript for Sha256Transcript<C> {
    type Scalar = C::Scalar;

    fn new() -> Self {
        Sha256Transcript {
            context: Context256::new(),
            _curve: PhantomData,
        }
    }

    fn new_sep(label: &[u8]) -> Self {
        Sha256Transcript {
            context: Context256::new().update(label),
            _curve: PhantomData,
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        self.context.update_mut(bytes);
    }

    fn challenge(self) -> C::Scalar {
        C::scalar_from_bytes(&self.context.finalize()).unwrap()
    }
}

/// Implement [`EcOperation`] for a SEC2 short-Weierstrass curve module.
///
/// `$curve` must be a module exposing the standard eccoxide `Scalar`, `Point`,
/// `PointAffine` and `FieldElement` types (as generated for every `sec2` curve).
macro_rules! impl_sec2_weierstrass {
    ($(#[$meta:meta])* $name:ident => $curve:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name;

        impl EcOperation for $name {
            type Scalar = $curve::Scalar;
            type Point = $curve::Point;
            type Transcript = Sha256Transcript<$name>;

            fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Self::Scalar> {
                $curve::Scalar::from_bytes(bytes)
            }

            fn scalar_to_bytes(s: &Self::Scalar) -> Vec<u8> {
                s.to_bytes().to_vec()
            }

            fn point_to_bytes(p: &Self::Point) -> Vec<u8> {
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
                if slice.len() != 33 {
                    return None;
                }
                let sign = match slice[0] {
                    0x2 => Sign::Positive,
                    0x3 => Sign::Negative,
                    _ => return None,
                };
                let bytes = <&[u8; 32]>::try_from(&slice[1..]).unwrap();
                let fe = $curve::FieldElement::from_bytes(bytes)?;
                let pa = $curve::PointAffine::decompress(&fe, sign)?;
                Some($curve::Point::from_affine(&pa))
            }

            fn point_try_hash_to_curve(slice: &[u8]) -> Option<Self::Point> {
                let out = Sha256::new().update(slice).finalize();
                let x = $curve::FieldElement::from_bytes(&out)?;
                let pa = $curve::PointAffine::decompress(&x, Sign::Positive)?;
                Some($curve::Point::from_affine(&pa))
            }

            fn point_hash_to_curve(slice: &[u8]) -> Self::Point {
                let mut counter_slice = [0u8];
                loop {
                    let out = Sha256::new()
                        .update(slice)
                        .update(&counter_slice)
                        .finalize();
                    if let Some(x) = $curve::FieldElement::from_bytes(&out) {
                        if let Some(p) = $curve::PointAffine::decompress(&x, Sign::Positive) {
                            return $curve::Point::from_affine(&p);
                        }
                    }
                    counter_slice[0] = counter_slice[0] + 1;
                }
            }
        }
    };
}

impl_sec2_weierstrass!(
    /// The NIST P-256 curve (a.k.a. secp256r1 / prime256v1).
    P256r1 => p256r1
);

impl_sec2_weierstrass!(
    /// The secp256k1 curve, as used by Bitcoin and Ethereum.
    P256k1 => p256k1
);
