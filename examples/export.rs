
use sha2::Digest;
use rsa_oaep_pss::ToPem;

fn main() {
    
    let mut rng = rand::rngs::OsRng;

    println!("generating keys...");

    let (public_key, private_key) =
        rsa_oaep_pss::generate_rsa_keys(&mut rng, 4096).expect("keys generation error");

    println!("exporting key...");

    let pem = public_key.to_pem().expect("PEM export error");

    println!("{}", pem);
}