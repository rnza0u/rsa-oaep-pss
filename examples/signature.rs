use sha2::Digest;
fn main() {
    let mut rng = rand::rngs::OsRng;

    println!("Generating keys...");

    let (public_key, private_key) =
        rsa_oaep_pss::generate_rsa_keys(&mut rng, 2048).expect("keys generation error");

    let message = b"message to sign";

    let mut pss = rsa_oaep_pss::RsaPss::new(rand::rngs::OsRng, &sha2::Sha256::new());

    println!("Signing message...");

    let signature = pss.sign(&private_key, message).expect("signature error");

    println!("Verifying signature...");

    let verification = pss.verify(&public_key, message, &signature);

    assert!(verification.is_ok());

    println!("Signature OK");
}
