extern crate pvss;

fn main() {
    let t = 10;

    let mut keys = Vec::with_capacity(100);
    let mut pubs = Vec::with_capacity(100);
    for _ in 0..100 {
        let (public, private) = pvss::crypto::create_keypair();

        keys.push(private);
        pubs.push(public);
    }

    // Round trip public key through bytes
    let pub_bytes = pubs[0].to_bytes();
    println!("pub_bytes = {:?}", pub_bytes);
    let pub_0 = pvss::crypto::PublicKey::from_bytes(&pub_bytes);
    assert!(pub_0 == pubs[0]);

    // Round trip private key through bytes
    let priv_bytes = keys[0].to_bytes();
    println!("priv_bytes = {:?}", priv_bytes);
    let priv_0 = pvss::crypto::PrivateKey::from_bytes(&priv_bytes);
    assert!(priv_0 == keys[0]);

    let escrow = pvss::simple::escrow(t);

    let commitments = pvss::simple::commitments(&escrow);
    let shares = pvss::simple::create_shares(&escrow, &pubs);

    let mut decrypted = Vec::with_capacity(100);

    println!("publickeys: {nb_keys}", nb_keys = pubs.len());
    println!("shares: {nb_shares}", nb_shares = shares.len());

    for share in shares {
        let idx = share.id as usize;
        let verified_encrypted =
            share.verify(share.id, &pubs[idx], &escrow.extra_generator, &commitments);
        println!("encrypted share {id}: {verified}",
                 id = share.id,
                 verified = verified_encrypted);

        let d = pvss::simple::decrypt_share(&keys[idx], &pubs[idx], &share);
        let verified_decrypted = d.verify(&pubs[idx], &share);
        println!("decrypted share {id}: {verified}",
                 id = share.id,
                 verified = verified_decrypted);
        decrypted.push(d);
    }

    let recovered = pvss::simple::recover(t, decrypted.as_slice()).unwrap();
    println!("equal: {b}", b = (recovered == escrow.secret));
}
