use sha2::Digest;

fn main() {
    let mut rng = rand::rngs::OsRng;

    println!("Generating keys...");

    let (public_key, private_key) =
        rsa_oaep_pss::generate_rsa_keys(&mut rng, 2048).expect("keys generation error");

    let message = b"some secret";

    let mut oaep = rsa_oaep_pss::RsaOaep::new(rand::rngs::OsRng, &sha2::Sha256::new());

    println!("Encrypting message...");

    let ciphertext = oaep
        .encrypt(&public_key, message)
        .expect("encryption error");

    println!("Encrypted {} bytes to {} bytes of ciphertext", message.len(), ciphertext.len());

    println!("Decrypting message...");

    let recovered = oaep
        .decrypt(&private_key, &ciphertext)
        .expect("decryption error");

    assert_eq!(recovered, message);

    println!("Decryption OK");
}
