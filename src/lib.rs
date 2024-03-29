pub mod crypto;

mod dleq;
mod math;
mod pdleq;
pub mod scrape;
pub mod simple;
mod types;

#[cfg(test)]
mod tests {
    use super::crypto;
    use super::crypto::*;
    use super::dleq;
    use super::scrape;
    use super::simple;

    pub const NB_TESTS: usize = 100;
    #[test]
    fn crypto_point_add_identity() {
        let mut drg = Drg::new();
        for _ in 0..NB_TESTS {
            let i = Scalar::generate(&mut drg);
            let p = Point::from_scalar(&i);
            assert!(p.clone() + Point::infinity() == p);
        }
    }

    #[test]
    fn crypto_point_generator() {
        let g = Point::generator();
        let mut drg = Drg::new();
        for _ in 0..NB_TESTS {
            let i = Scalar::generate(&mut drg);
            let p1 = Point::from_scalar(&i);
            let p2 = g.mul(&i);
            assert!(p1 == p2);
        }
    }

    #[test]
    fn dleq_works() {
        let mut drg = Drg::new();
        for _ in 0..NB_TESTS {
            let a = Scalar::generate(&mut drg);
            let w = Scalar::generate(&mut drg);
            let extra_gen = Point::from_scalar(&Scalar::generate(&mut drg));

            let lifted_a = Point::from_scalar(&a);
            let lifted_extra_a = extra_gen.mul(&a);

            let dleq = dleq::DLEQ {
                g1: &Point::generator(),
                h1: &lifted_a,
                g2: &extra_gen,
                h2: &lifted_extra_a,
            };
            let proof = dleq::Proof::create(&w, &a, &dleq);
            assert!(proof.verify(&dleq));
        }
    }

    #[test]
    fn pvss_works() {
        let tests = [
            (1, 4),
            (5, 5),
            (2, 8),
            (10, 50),
            (48, 50),
            (2, 20),
            (10, 100),
        ];
        let mut drg = Drg::new();
        for test in tests.iter() {
            let &(t, nb_keys) = test;
            println!("t={} n={}", t, nb_keys);

            let mut keys = Vec::with_capacity(nb_keys);
            let mut pubs = Vec::with_capacity(nb_keys);
            for _ in 0..nb_keys {
                let (public, private) = crypto::create_keypair(&mut drg);
                keys.push(private);
                pubs.push(public);
            }

            let escrow = simple::escrow(&mut drg, t);

            let commitments = simple::commitments(&escrow);
            let shares = simple::create_shares(&mut drg, &escrow, &pubs);

            let mut decrypted = Vec::with_capacity(100);

            assert_eq!(t as usize, commitments.len());
            assert_eq!(pubs.len(), shares.len());

            for share in shares {
                /* share ids start at 1 */
                let idx = share.id.as_index();
                let verified_encrypted =
                    share.verify(share.id, &pubs[idx], &escrow.extra_generator, &commitments);
                assert!(
                    verified_encrypted,
                    "encrypted share {:?} verification failed",
                    share.id
                );

                let d = simple::decrypt_share(&mut drg, &keys[idx], &pubs[idx], &share);
                let verified_decrypted = d.verify(&pubs[idx], &share);
                assert!(verified_decrypted);
                decrypted.push(d);
            }

            let recovered = simple::recover(t, decrypted.as_slice()).unwrap();

            assert!(recovered == escrow.secret);
            let verify_secret = simple::verify_secret(
                recovered,
                escrow.extra_generator,
                &commitments,
                escrow.proof,
            );
            assert!(verify_secret, "secret not verified");
        }
    }

    #[test]
    fn scrape_works() {
        let tests = [(1, 4), (2, 8), (10, 50), (48, 50), (2, 20), (10, 100)];
        let mut drg = Drg::new();
        for test in tests.iter() {
            let &(t, nb_keys) = test;
            println!("t={} n={}", t, nb_keys);

            let mut keys = Vec::with_capacity(nb_keys);
            let mut pubs = Vec::with_capacity(nb_keys);
            for _ in 0..nb_keys {
                let (public, private) = crypto::create_keypair(&mut drg);
                keys.push(private);
                pubs.push(public);
            }

            let escrow = scrape::escrow(&mut drg, t);

            let public_shares = scrape::create_shares(&mut drg, &escrow, &pubs);

            let mut decrypted = Vec::with_capacity(100);

            assert_eq!(nb_keys, public_shares.commitments.len());
            assert_eq!(nb_keys, public_shares.encrypted_shares.len());

            assert!(public_shares.verify(&mut drg, &pubs));

            for share in &public_shares.encrypted_shares {
                let idx = share.id.as_index();
                let d = scrape::decrypt_share(&mut drg, &keys[idx], &pubs[idx], &share);
                let verified_decrypted = d.verify(&pubs[idx], &share);
                assert!(verified_decrypted);
                decrypted.push(d);
            }

            let recovered = scrape::recover(t, decrypted.as_slice()).unwrap();
            assert!(recovered == escrow.secret);

            let verify_secret = scrape::verify_secret(recovered, &public_shares);
            assert!(verify_secret, "secret not verified");
        }
    }
}
