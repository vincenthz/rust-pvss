// implementation of SCRAPE: Scalable Randomness Attested by Public Entities
// https://eprint.iacr.org/2017/216.pdf

use super::crypto::*;
use super::dleq;
use super::math;
use super::pdleq;
use super::types::*;

pub type Secret = Point;

// a new escrowing context.
// this contains secret values (polynomial & secret) that are newly created.
// this also contains by-product (extra_generator & proof) which are useful for
// the protocol
#[derive(Clone)]
pub struct Escrow {
    pub threshold: Threshold,
    pub extra_generator: Point,
    pub polynomial: math::Polynomial,
    pub secret: Secret,
    pub proof: dleq::Proof,
}

// Public values for a successful run of secret sharing.
//
// This contains everything for self verification and
// and the shares of each participants
//
// there should be N encrypted_shares and N commitments
// the parallel proofs should N elements too.
#[derive(Clone)]
pub struct PublicShares {
    pub threshold: Threshold,
    pub extra_generator: Point,
    pub secret_proof: dleq::Proof,
    pub encrypted_shares: Vec<EncryptedShare>,
    pub commitments: Vec<Commitment>,
    pub proofs: pdleq::Proof,
}

#[derive(Clone)]
pub struct Commitment {
    point: Point,
}

#[derive(Clone)]
pub struct EncryptedShare {
    pub id: ShareId,
    encrypted_val: Point,
}

#[derive(Clone)]
pub struct DecryptedShare {
    pub id: ShareId,
    decrypted_val: Point,
    proof: dleq::Proof,
}

// create a new escrow parameter.
// the only parameter needed is the threshold necessary to be able to reconstruct.
pub fn escrow(drg: &mut Drg, t: Threshold) -> Escrow {
    assert!(t >= 1, "threshold is invalid; < 1");

    let poly = math::Polynomial::generate(drg, t - 1);
    let gen = Point::random_generator(drg);

    let secret = poly.at_zero();
    let g_s = Point::from_scalar(&secret);

    let challenge = Scalar::generate(drg);
    let dleq = dleq::DLEQ {
        g1: &Point::generator(),
        h1: &g_s.clone(),
        g2: &gen.clone(),
        h2: &gen.mul(&secret),
    };
    let proof = dleq::Proof::create(&challenge, &secret, dleq);

    Escrow {
        threshold: t,
        extra_generator: gen,
        polynomial: poly,
        secret: g_s,
        proof,
    }
}

pub fn create_shares(drg: &mut Drg, escrow: &Escrow, pubs: &[PublicKey]) -> PublicShares {
    let n = pubs.len();
    let mut shares = Vec::with_capacity(n);
    let mut commitments = Vec::with_capacity(n);
    let mut sis = Vec::with_capacity(n);
    let mut pparams = Vec::with_capacity(n);

    for (i, public) in ShareIdsSequence::new().zip(pubs.iter()) {
        let si = escrow.polynomial.evaluate(i.to_scalar());
        let esi = public.point.mul(&si);
        let vi = escrow.extra_generator.mul(&si);

        shares.push(EncryptedShare {
            id: i,
            encrypted_val: esi,
        });
        commitments.push(Commitment { point: vi });
        sis.push(si);
    }

    for (((s, c), public), si) in shares
        .iter()
        .zip(commitments.iter())
        .zip(pubs.iter())
        .zip(sis.iter())
    {
        {
            let w = Scalar::generate(drg);
            let dleq = dleq::DLEQ {
                g1: &escrow.extra_generator,
                h1: &c.point,
                g2: &public.point,
                h2: &s.encrypted_val,
            };
            pparams.push((w, si, dleq));
        }
    }

    // now create the parallel proof for all shares
    let pdleq = pdleq::Proof::create(pparams.as_slice());

    PublicShares {
        threshold: escrow.threshold,
        extra_generator: escrow.extra_generator.clone(),
        secret_proof: escrow.proof.clone(),
        encrypted_shares: shares,
        commitments,
        proofs: pdleq,
    }
}

impl PublicShares {
    pub fn number_participants(&self) -> u32 {
        self.commitments.len() as u32
    }

    pub fn verify(&self, drg: &mut Drg, publics: &[PublicKey]) -> bool {
        // recreate all the DLEQs
        let mut dleqs = Vec::with_capacity(publics.len());
        for (i, public) in publics.iter().enumerate() {
            let vi = &self.commitments[i].point;
            let esi = &self.encrypted_shares[i].encrypted_val;
            let dleq = dleq::DLEQ {
                g1: &self.extra_generator,
                h1: &vi,
                g2: &public.point,
                h2: &esi,
            };
            dleqs.push(dleq);
        }
        // verify the parallel proof
        if !self.proofs.verify(dleqs.as_slice()) {
            return false;
        }

        // reed solomon check
        let n = self.number_participants();
        let poly = math::Polynomial::generate(drg, n - self.threshold - 1);

        let mut v = Point::infinity();
        for i in 0..n {
            let idx = i as usize;

            let mut cperp = poly.evaluate(Scalar::from_u32(i));
            for j in 0..n {
                if i != j {
                    cperp = cperp * (Scalar::from_u32(i) - Scalar::from_u32(j)).inverse();
                }
            }

            let commitment = &self.commitments[idx];
            v = v + commitment.point.mul(&cperp);
        }

        v == Point::infinity()
    }
}

impl DecryptedShare {
    pub fn verify(&self, public: &PublicKey, eshare: &EncryptedShare) -> bool {
        let dleq = dleq::DLEQ {
            g1: &Point::generator(),
            h1: &public.point,
            g2: &self.decrypted_val,
            h2: &eshare.encrypted_val,
        };
        self.proof.verify(&dleq)
    }
}

pub fn decrypt_share(
    drg: &mut Drg,
    private: &PrivateKey,
    public: &PublicKey,
    share: &EncryptedShare,
) -> DecryptedShare {
    let challenge = Scalar::generate(drg);
    let xi = private.scalar.clone();
    let yi = public.point.clone();
    let lifted_yi = share.encrypted_val.clone();
    let si = lifted_yi.mul(&xi.inverse());
    let dleq = dleq::DLEQ {
        g1: &Point::generator(),
        h1: &yi,
        g2: &si,
        h2: &lifted_yi,
    };
    let proof = dleq::Proof::create(&challenge, &xi, dleq);
    DecryptedShare {
        id: share.id,
        decrypted_val: si,
        proof,
    }
}

fn interpolate_one(t: Threshold, sid: usize, shares: &[DecryptedShare]) -> Scalar {
    let mut v = Scalar::multiplicative_identity();
    for j in 0..(t as usize) {
        if j != sid {
            let sj = shares[j].id.to_scalar();
            let si = shares[sid].id.to_scalar();
            let d = sj.clone() - si;
            v = v * sj * d.inverse();
        }
    }
    v
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
    Ok(result)
}

pub fn verify_secret(secret: Secret, public_shares: &PublicShares) -> bool {
    let mut commitment_interpolate = Point::infinity();
    for i in 0..(public_shares.threshold as usize) {
        let x = public_shares.commitments[i].point.clone();
        let li = {
            let mut v = Scalar::multiplicative_identity();
            for j in 0..(public_shares.threshold as usize) {
                if j != i {
                    let sj = Scalar::from_u32((j + 1) as u32);
                    let si = Scalar::from_u32((i + 1) as u32);
                    let d = sj.clone() - si;
                    v = v * sj * d.inverse();
                }
            }
            v
        };
        commitment_interpolate = commitment_interpolate + x.mul(&li);
    }
    let dleq = dleq::DLEQ {
        g1: &Point::generator(),
        h1: &secret,
        g2: &public_shares.extra_generator,
        h2: &commitment_interpolate,
    };
    public_shares.secret_proof.verify(&dleq)
}
