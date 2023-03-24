use crate::{
    arithmetic::{ceil_div, modular_inverse, modular_pow},
    convert::{i2osp, os2ip},
    errors::{RsaError, RsaError::*},
    generation::generate_prime
};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero};
use rand_core::{CryptoRng, RngCore};

const PUBLIC_EXPONENT: u32 = 65537;

/// An RSA public key.
/// Contains the modulus (n) and the public exponent(e).
#[derive(Debug)]
pub struct RsaPublicKey {
    pub(crate) modulus: BigUint,
    pub(crate) public_exponent: BigUint,
}

impl RsaPublicKey {
    pub fn from_params(modulus: &[u8], public_exponent: &[u8]) -> Result<Self, RsaError> {
        let n = os2ip(modulus)?;
        let e = os2ip(public_exponent)?;

        Ok(RsaPublicKey {
            modulus: n,
            public_exponent: e,
        })
    }

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

    /// Get the modulus (n) as a low endian bytes vector.
    pub fn get_modulus(&self) -> Result<Vec<u8>, RsaError> {
        i2osp(&self.modulus, self.get_modulus_size())
    }

    /// Get the public exponent(e) as a low endian bytes vector.
    pub fn get_public_exponent(&self) -> Result<Vec<u8>, RsaError> {
        i2osp(
            &self.public_exponent,
            ceil_div(self.public_exponent.bits() as usize, 8),
        )
    }
}

/// An RSA private key.
/// Contains the modulus (n) and the private exponent (d).
#[derive(Debug)]
pub struct RsaPrivateKey {
    pub(crate) modulus: BigUint,
    pub(crate) private_exponent: BigUint,
    pub(crate) public_exponent: BigUint,
    pub(crate) p: BigUint,
    pub(crate) q: BigUint,
    pub(crate) exp_p: BigUint,
    pub(crate) exp_q: BigUint,
    pub(crate) coefficient: BigUint,
}

impl RsaPrivateKey {
    /// Import a private key from individuals primes in low-endian format.
    pub fn from_primes(p: &[u8], q: &[u8]) -> Result<Self, RsaError> {
        let biguint_p = os2ip(p)?;
        let biguint_q = os2ip(q)?;

        let n = &biguint_p * &biguint_q;

        let phi_n = (&biguint_p - BigUint::one()) * (&biguint_q - BigUint::one());

        let e = BigUint::from_u32(PUBLIC_EXPONENT).unwrap();

        if (&phi_n % &e) == BigUint::zero() {
            return Err(ParamsError);
        }

        let d = match modular_inverse(&e, &phi_n) {
            Some(d) => d,
            None => return Err(ArithmeticError),
        };

        let coefficient = match modular_inverse(&biguint_q, &biguint_p) {
            Some(coeff) => coeff,
            None => return Err(ArithmeticError),
        };

        Ok(RsaPrivateKey {
            modulus: n,
            public_exponent: e,
            private_exponent: d.clone(),
            p: biguint_p.clone(),
            q: biguint_q.clone(),
            exp_p: &d % (&biguint_p - &BigUint::one()),
            exp_q: &d % (&biguint_q - &BigUint::one()),
            coefficient: coefficient,
        })
    }

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
        Err(RsaError::MessageRepresentativeOutOfRange)
    } else {
        Ok(())
    }
}

/// Generate a pair of RSA keys using the provided RNG and modulus length in bits.
/// Acceptable modulus lengths are 2048, 3072 or 4096.
pub fn generate_rsa_keys<T>(
    rng: &mut T,
    modulus_length: usize,
) -> Result<(RsaPublicKey, RsaPrivateKey), RsaError>
where
    T: CryptoRng + RngCore,
{
    let n_bytes_length = match modulus_length {
        2048 | 3072 | 4096 => modulus_length / 8,
        _ => return Err(ParamsError),
    };

    let p = generate_prime(rng, n_bytes_length / 2)?;
    let q = generate_prime(rng, n_bytes_length / 2)?;

    let private_key = match RsaPrivateKey::from_primes(&p.to_bytes_be(), &q.to_bytes_be()) {
        Ok(private_key) => private_key,
        Err(ParamsError) => return generate_rsa_keys(rng, modulus_length),
        Err(any) => return Err(any),
    };

    let public_key = RsaPublicKey::from_params(
        &private_key.modulus.to_bytes_be(),
        &private_key.public_exponent.to_bytes_be(),
    )?;

    Ok((public_key, private_key))
}