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

    let escrow = pvss::escrow(t);

    let commitments = pvss::commitments(&escrow);
    let shares = pvss::create_shares(&escrow, &pubs);

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

        let d = pvss::decrypt_share(&keys[idx], &pubs[idx], &share);
        let verified_decrypted = d.verify(&pubs[idx], &share);
        println!("decrypted share {id}: {verified}",
                 id = share.id,
                 verified = verified_decrypted);
        decrypted.push(d);
    }

    let recovered = pvss::recover(t, decrypted.as_slice()).unwrap();
    println!("equal: {b}", b = (recovered == escrow.secret));
}
