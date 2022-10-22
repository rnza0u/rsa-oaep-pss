use paste::paste;
use rand::thread_rng;
use rsa_oaep_pss::{generate_rsa_keys, RsaError, RsaOaep, RsaPss};
use sha2::{Digest, Sha256};

macro_rules! generate_rsa_tests {

    ($key_size:literal) => {

        paste! {

            #[test]
            fn [<key_generation_ $key_size>]() -> Result<(), RsaError> {
                generate_rsa_keys(&mut thread_rng(), $key_size).expect("result is expected");
                Ok(())
            }

            #[test]
            fn [<oaep_encrypt_and_decrypt_with_custom_label_ $key_size>]() -> Result<(), RsaError> {

                let message = [0x00_u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07].repeat(10);

                let (public_key, private_key) = generate_rsa_keys(&mut thread_rng(), $key_size).unwrap();

                let mut oaep_encryption = RsaOaep::new(thread_rng(), &Sha256::new());

                let ciphertext = oaep_encryption.encrypt_with_label(&public_key, &message, b"some label")?;

                let recovered = oaep_encryption.decrypt_with_label(&private_key, &ciphertext, b"some label")?;

                assert_eq!(recovered, message);

                Ok(())
            }

            #[test]
            fn [<oaep_encrypt_and_decrypt_without_label_ $key_size>]() -> Result<(), RsaError> {

                let message = [0x00_u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07].repeat(19);

                let (public_key, private_key) = generate_rsa_keys(&mut thread_rng(), $key_size).unwrap();

                let mut oaep_encryption = RsaOaep::new(thread_rng(), &Sha256::new());

                let ciphertext = oaep_encryption.encrypt(&public_key, &message)?;

                let recovered = oaep_encryption.decrypt(&private_key, &ciphertext)?;

                assert_eq!(recovered, message);

                Ok(())
            }

            #[test]
            fn [<oaep_decryption_error_when_label_is_incorrect_ $key_size>]() -> Result<(), RsaError> {

                let message = [0x00_u8, 0x01, 0x02, 0x03, 0x04];

                let (public_key, private_key) = generate_rsa_keys(&mut thread_rng(), $key_size).unwrap();

                let mut oaep_encryption = RsaOaep::new(thread_rng(), &Sha256::new());

                let ciphertext = oaep_encryption.encrypt_with_label(&public_key, &message, b"some label")?;

                let recovered = oaep_encryption.decrypt_with_label(&private_key, &ciphertext, b"other label");

                assert!(recovered.is_err());

                Ok(())
            }

            #[test]
            fn [<oaep_decryption_error_when_ciphertext_is_tampered_ $key_size>]() -> Result<(), RsaError> {

                let message = [0x00_u8, 0x01, 0x02, 0x03, 0x04];

                let (public_key, private_key) = generate_rsa_keys(&mut thread_rng(), $key_size).unwrap();

                let mut oaep_encryption = RsaOaep::new(thread_rng(), &Sha256::new());

                let mut ciphertext = oaep_encryption.encrypt_with_label(&public_key, &message, b"some label")?;

                ciphertext[5] = if ciphertext[5] == 0  { 1 } else { 0 };

                let recovered = oaep_encryption.decrypt_with_label(&private_key, &ciphertext, b"other label");

                assert!(recovered.is_err());

                Ok(())
            }

            #[test]
            fn [<pss_create_signature_and_verify_ $key_size>]() -> Result<(), RsaError>{

                let message = b"message to sign";

                let (public_key, private_key) = generate_rsa_keys(&mut thread_rng(), $key_size).unwrap();

                let mut pss = RsaPss::new(thread_rng(), &Sha256::new());

                let signature = pss.sign(&private_key, message)?;

                pss.verify(&public_key, message, &signature)?;

                Ok(())
            }

            #[test]
            fn [<pss_invalid_signature_when_tampered_ $key_size>]() -> Result<(), RsaError>{

                let message = b"message to sign";

                let (public_key, private_key) = generate_rsa_keys(&mut thread_rng(), $key_size).unwrap();

                let mut pss = RsaPss::new(thread_rng(), &Sha256::new());

                let mut signature = pss.sign(&private_key, message)?;

                signature[5] = if signature[5] == 0  { 1 } else { 0 };

                let verification = pss.verify(&public_key, message, &signature);

                assert!(verification.is_err());

                Ok(())
            }

        }
    };
}

generate_rsa_tests!(2048);
generate_rsa_tests!(3072);
generate_rsa_tests!(4096);
