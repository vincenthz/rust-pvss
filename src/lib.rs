extern crate openssl;
pub mod crypto;

mod types;
mod math;
mod dleq;
mod pdleq;
pub mod simple;
pub mod scrape;

#[cfg(test)]
mod tests {
    use crypto::*;
    use crypto;
    use dleq;
    use simple;
    use scrape;

    pub const NB_TESTS: usize = 100;
    #[test]
    fn crypto_point_add_identity() {
        for _ in 0..NB_TESTS {
            let i = Scalar::generate();
            let p = Point::from_scalar(&i);
            assert!(p.clone() + Point::infinity() == p);
        }
    }

    #[test]
    fn crypto_point_generator() {
        let g = Point::generator();
        for _ in 0..NB_TESTS {
            let i = Scalar::generate();
            let p1 = Point::from_scalar(&i);
            let p2 = g.mul(&i);
            assert!(p1 == p2);
        }
    }

    #[test]
    fn dleq_works() {
        for _ in 0..NB_TESTS {
            let a = Scalar::generate();
            let w = Scalar::generate();
            let extra_gen = Point::from_scalar(&Scalar::generate());

            let lifted_a = Point::from_scalar(&a);
            let lifted_extra_a = extra_gen.mul(&a);

            let dleq = dleq::DLEQ {
                g1: Point::generator(),
                h1: lifted_a,
                g2: extra_gen,
                h2: lifted_extra_a,
            };
            let proof = dleq::Proof::create(w, a, dleq.clone());
            assert!(proof.verify(dleq));
        }
    }

    #[test]
    fn pvss_works() {
        let tests = [(1, 4), (5, 5), (2, 8), (10, 50), (48, 50), (2, 20), (10, 100)];
        for test in tests.iter() {
            let &(t, nb_keys) = test;
            println!("t={} n={}", t, nb_keys);

            let mut keys = Vec::with_capacity(nb_keys);
            let mut pubs = Vec::with_capacity(nb_keys);
            for _ in 0..nb_keys {
                let (public, private) = crypto::create_keypair();
                keys.push(private);
                pubs.push(public);
            }

            let escrow = simple::escrow(t);

            let commitments = simple::commitments(&escrow);
            let shares = simple::create_shares(&escrow, &pubs);

            let mut decrypted = Vec::with_capacity(100);

            assert_eq!(t as usize, commitments.len());
            assert_eq!(pubs.len(), shares.len());

            for share in shares {
                /* share ids start at 1 */
                assert!(share.id > 0);
                let idx = (share.id - 1) as usize;
                let verified_encrypted =
                    share.verify(share.id, &pubs[idx], &escrow.extra_generator, &commitments);
                assert!(verified_encrypted,
                        "encrypted share {} verification failed",
                        share.id);

                let d = simple::decrypt_share(&keys[idx], &pubs[idx], &share);
                let verified_decrypted = d.verify(&pubs[idx], &share);
                assert!(verified_decrypted);
                decrypted.push(d);
            }

            let recovered = simple::recover(t, decrypted.as_slice()).unwrap();

            assert!(recovered == escrow.secret);
            let verify_secret = simple::verify_secret(recovered,
                                                      escrow.extra_generator,
                                                      &commitments,
                                                      escrow.proof);
            assert!(verify_secret, "secret not verified");
        }
    }

    #[test]
    fn scrape_works() {
        let tests = [(1, 4), (2, 8), (10, 50), (48, 50), (2, 20), (10, 100)];
        for test in tests.iter() {
            let &(t, nb_keys) = test;
            println!("t={} n={}", t, nb_keys);

            let mut keys = Vec::with_capacity(nb_keys);
            let mut pubs = Vec::with_capacity(nb_keys);
            for _ in 0..nb_keys {
                let (public, private) = crypto::create_keypair();
                keys.push(private);
                pubs.push(public);
            }

            let escrow = scrape::escrow(t);

            let public_shares = scrape::create_shares(&escrow, &pubs);

            let mut decrypted = Vec::with_capacity(100);

            assert_eq!(nb_keys, public_shares.commitments.len());
            assert_eq!(nb_keys, public_shares.encrypted_shares.len());

            assert!(public_shares.verify(&pubs));

            for share in public_shares.encrypted_shares {
                assert!(share.id > 0);
                let idx = (share.id - 1) as usize;
                let d = scrape::decrypt_share(&keys[idx], &pubs[idx], &share);
                let verified_decrypted = d.verify(&pubs[idx], &share);
                assert!(verified_decrypted);
                decrypted.push(d);
            }

            let recovered = scrape::recover(t, decrypted.as_slice()).unwrap();
            assert!(recovered == escrow.secret);
        }
    }
}
