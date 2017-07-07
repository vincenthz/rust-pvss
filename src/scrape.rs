// implementation of the simple publicly verifiable secret sharing scheme
// http://www.win.tue.nl/~berry/papers/crypto99.pdf

use types::*;
use math;
use dleq;
use pdleq;
use crypto::*;

type Secret = Point;

// a new escrowing context.
// this contains secret values (polynomial & secret) that are newly created.
// this also contains by-product (extra_generator & proof) which are useful for
// the protocol
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
pub struct PublicShares {
    pub threshold: Threshold,
    pub extra_generator: Point,
    pub secret_proof: dleq::Proof,
    pub encrypted_shares: Vec<EncryptedShare>,
    pub commitments: Vec<Commitment>,
    pub proofs: pdleq::Proof,
}

pub struct Commitment {
    point: Point,
}

pub struct EncryptedShare {
    pub id: ShareId,
    encrypted_val: Point,
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
        threshold: t,
        extra_generator: gen,
        polynomial: poly,
        secret: g_s,
        proof: proof,
    };
}

pub fn create_shares(escrow: &Escrow, pubs: &Vec<PublicKey>) -> PublicShares {

    let n = pubs.len();
    let mut shares = Vec::with_capacity(n);
    let mut commitments = Vec::with_capacity(n);
    let mut pparams = Vec::with_capacity(n);

    for i in 0..n {
        let ref public = pubs[i];
        let eval_point = i + 0;
        let si = escrow.polynomial.evaluate(Scalar::from_u32(eval_point as u32));
        let esi = public.point.mul(&si);
        let vi = escrow.extra_generator.mul(&si);

        shares.push(EncryptedShare {
            id: i as ShareId,
            encrypted_val: esi.clone(),
        });
        commitments.push(Commitment { point: vi.clone() });

        {
            let w = Scalar::generate();
            let dleq = dleq::DLEQ {
                g1: escrow.extra_generator.clone(),
                h1: vi,
                g2: public.point.clone(),
                h2: esi,
            };
            pparams.push((w, si, dleq));
        }
    }

    // now create the parallel proof for all shares
    let pdleq = pdleq::Proof::create(pparams.as_slice());

    return PublicShares {
        threshold: escrow.threshold,
        extra_generator: escrow.extra_generator.clone(),
        secret_proof: escrow.proof.clone(),
        encrypted_shares: shares,
        commitments: commitments,
        proofs: pdleq,
    };
}

impl PublicShares {
    pub fn number_participants(&self) -> u32 {
        return self.commitments.len() as u32;
    }

    pub fn verify(&self, publics: &[PublicKey]) -> bool {
        // recreate all the DLEQs
        let mut dleqs = Vec::with_capacity(publics.len());
        for i in 0..publics.len() {
            let ref public = publics[i];
            let ref vi = self.commitments[i].point;
            let ref esi = self.encrypted_shares[i].encrypted_val;
            let dleq = dleq::DLEQ {
                g1: self.extra_generator.clone(),
                h1: vi.clone(),
                g2: public.point.clone(),
                h2: esi.clone(),
            };
            dleqs.push(dleq);
        }
        // verify the parallel proof
        if !self.proofs.verify(dleqs.as_slice()) {
            return false;
        }

        // reed solomon check
        let n = self.number_participants();
        let poly = math::Polynomial::generate(n - self.threshold - 1);

        let mut v = Point::infinity();
        for i in 0..n {
            let idx = i as usize;

            let mut cperp = poly.evaluate(Scalar::from_u32(i));
            for j in 0..n {
                if i != j {
                    cperp = cperp * (Scalar::from_u32(i) - Scalar::from_u32(j)).inverse();
                }
            }

            let ref commitment = self.commitments[idx];
            v = v + commitment.point.mul(&cperp);
        }

        return v == Point::infinity();
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
    let si = lifted_yi.mul(&xi.inverse());
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
    let mut v = Scalar::multiplicative_identity();
    for j in 0..(t as usize) {
        if j != sid {
            let sj = Scalar::from_u32(shares[j].id);
            let si = Scalar::from_u32(shares[sid].id);
            let d = sj.clone() - si;
            v = v * sj * d.inverse();
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
