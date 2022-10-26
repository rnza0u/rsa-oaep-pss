use crate::{
    arithmetic::{modular_inverse, modular_pow},
    errors::RsaError,
    generation::generate_prime,
};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero};
use rand_core::{CryptoRng, RngCore};

pub(crate) const PUBLIC_EXPONENT: u32 = 65537;

/// An RSA public key.
/// Contains the modulus (n) and the public exponent(e).
#[derive(Debug)]
pub struct RsaPublicKey {
    modulus: BigUint,
    public_exponent: BigUint,
}

impl RsaPublicKey {
    pub(crate) fn rsaep(&self, message: &BigUint) -> Result<BigUint, RsaError> {
        check_message_representative(message, &self.modulus)?;
        Ok(modular_pow(message, &self.public_exponent, &self.modulus))
    }

    pub(crate) fn rsavp(&self, message: &BigUint) -> Result<BigUint, RsaError> {
        check_message_representative(message, &self.modulus)?;
        Ok(modular_pow(message, &self.public_exponent, &self.modulus))
    }

    /// Get the modulus (n) size in bytes.
    pub fn get_modulus_size(&self) -> usize {
        (self.modulus.bits() as usize) / 8
    }
}

/// An RSA private key.
/// Contains the modulus (n) and the private exponent (d)
#[derive(Debug)]
pub struct RsaPrivateKey {
    modulus: BigUint,
    private_exponent: BigUint,
}

impl RsaPrivateKey {
    pub(crate) fn rsadp(&self, ciphertext: &BigUint) -> Result<BigUint, RsaError> {
        check_message_representative(ciphertext, &self.modulus)?;
        Ok(modular_pow(
            ciphertext,
            &self.private_exponent,
            &self.modulus,
        ))
    }

    pub(crate) fn rsasp(&self, ciphertext: &BigUint) -> Result<BigUint, RsaError> {
        check_message_representative(ciphertext, &self.modulus)?;
        Ok(modular_pow(
            ciphertext,
            &self.private_exponent,
            &self.modulus,
        ))
    }

    ///  Get the modulus (n) size in bytes.
    pub fn get_modulus_size(&self) -> usize {
        (self.modulus.bits() as usize) / 8
    }
}

fn check_message_representative(r: &BigUint, m: &BigUint) -> Result<(), RsaError> {
    if r >= m {
        return Err(RsaError::message_representative_out_of_range());
    }
    Ok(())
}

/// Generate a pair of RSA keys using the provided RNG and modulus length in bits.
/// Acceptable modulus length are 2048, 3072 or 4096.
pub fn generate_rsa_keys<T>(
    rng: &mut T,
    modulus_length: usize,
) -> Result<(RsaPublicKey, RsaPrivateKey), RsaError>
where
    T: CryptoRng + RngCore,
{
    let n_bytes_length = match modulus_length {
        2048 | 3072 | 4096 => modulus_length / 8,
        _ => return Err(RsaError::invalid_key_size()),
    };

    let p = generate_prime(rng, n_bytes_length / 2)?;
    let q = generate_prime(rng, n_bytes_length / 2)?;

    let n = &p * &q;

    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

    let e = BigUint::from_u32(PUBLIC_EXPONENT).unwrap();

    if (&phi_n % &e) == BigUint::zero() {
        return generate_rsa_keys(rng, modulus_length);
    }

    let d = match modular_inverse(&e, &phi_n) {
        Some(d) => d,
        None => return Err(RsaError::arithmetic_error()),
    };

    Ok((
        RsaPublicKey {
            modulus: n.clone(),
            public_exponent: e,
        },
        RsaPrivateKey {
            modulus: n.clone(),
            private_exponent: d,
        },
    ))
}

#[test]
fn encryption_and_decryption() {
    use num_traits::FromPrimitive;

    let public_key = RsaPublicKey {
        modulus: BigUint::from_u8(119).unwrap(),
        public_exponent: BigUint::from_u8(5).unwrap(),
    };

    let private_key = RsaPrivateKey {
        modulus: BigUint::from_u8(119).unwrap(),
        private_exponent: BigUint::from_u8(77).unwrap(),
    };

    let message = BigUint::from_u8(19).unwrap();

    let ciphertext = public_key.rsaep(&message).unwrap();
    assert_eq!(ciphertext, BigUint::from_u8(66).unwrap());

    let recovered = private_key.rsadp(&ciphertext).unwrap();
    assert_eq!(recovered, message);
}

#[test]
fn sign_and_verify() {
    use num_traits::FromPrimitive;

    let public_key = RsaPublicKey {
        modulus: BigUint::from_u8(119).unwrap(),
        public_exponent: BigUint::from_u8(5).unwrap(),
    };

    let private_key = RsaPrivateKey {
        modulus: BigUint::from_u8(119).unwrap(),
        private_exponent: BigUint::from_u8(77).unwrap(),
    };

    let message = BigUint::from_u8(19).unwrap();

    let signature = private_key.rsasp(&message).unwrap();
    assert_eq!(signature, BigUint::from_u8(66).unwrap());

    let verification = public_key.rsavp(&signature).unwrap();
    assert_eq!(verification, message);
}
