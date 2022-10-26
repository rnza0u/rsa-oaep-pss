use sha2::Digest;

fn main() {
    let mut rng = rand::rngs::OsRng;

    println!("generating keys...");

    let (public_key, private_key) =
        rsa_oaep_pss::generate_rsa_keys(&mut rng, 2048).expect("keys generation error");

    let message = b"some secret message";

    let mut oaep = rsa_oaep_pss::RsaOaep::new(rand::rngs::OsRng, &sha2::Sha256::new());

    println!("encrypting message...");

    let ciphertext = oaep
        .encrypt(&public_key, message)
        .expect("encryption error");

    println!(
        "encrypted {} bytes to {} bytes of ciphertext...",
        message.len(),
        ciphertext.len()
    );

    println!("decrypting message...");

    let recovered = oaep
        .decrypt(&private_key, &ciphertext)
        .expect("decryption error");

    assert_eq!(recovered, message);

    println!("decryption OK");
}
