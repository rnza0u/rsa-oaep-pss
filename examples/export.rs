use rsa_oaep_pss::ToPem;

fn main() {
    let mut rng = rand::rngs::OsRng;

    println!("generating keys...");

    let (public_key, private_key) =
        rsa_oaep_pss::generate_rsa_keys(&mut rng, 2048).expect("keys generation error");

    println!("exporting key...");

    let public_key_pem = public_key.to_pem().expect("PEM export error");
    let private_key_pem = private_key.to_pem().expect("PEM export error");

    println!("{}", public_key_pem);
    println!("{}", private_key_pem);
}
