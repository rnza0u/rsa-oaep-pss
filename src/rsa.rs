use crate::{
    arithmetic::{modular_inverse, modular_pow},
    errors::{RsaError,RsaError::*},
    generation::generate_prime, 
    import::{FromPem, FromDer}, 
    export::{ToDer, ToPem}, convert::{os2ip},
};
use asn1::WriteError;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero};
use rand_core::{CryptoRng, RngCore};
use base64::{decode as base64_decode, encode as base64_encode};

const PUBLIC_EXPONENT: u32 = 65537;

const PEM_BOUNDARIES_DELIMITERS: &str = "-----";

/// An RSA public key.
/// Contains the modulus (n) and the public exponent(e).
#[derive(Debug)]
pub struct RsaPublicKey {
    modulus: BigUint,
    public_exponent: BigUint,
}

const RSA_PUBLIC_KEY_PEM_IDENTIFIER: &str = "RSA PUBLIC KEY";

impl RsaPublicKey {

    pub fn from_params(modulus: &[u8], public_exponent: &[u8]) -> Result<Self, RsaError> {
        
        let n = os2ip(modulus)?;
        let e = os2ip(public_exponent)?;
        
        Ok(RsaPublicKey {
            modulus: n,
            public_exponent: e
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
}

impl FromDer for RsaPublicKey {
    fn from_der(der_encoded: &[u8]) -> Result<Self, RsaError> {
        
        let (modulus, public_exponent) = match asn1::parse(
            der_encoded, 
            |parser| parser.read_element::<asn1::Sequence>()?.parse(
                |sequence| {
                    let n = sequence.read_element::<asn1::BigUint>()?;
                    let e = sequence.read_element::<asn1::BigUint>()?;
                    Ok::<(asn1::BigUint, asn1::BigUint), asn1::ParseError>((n, e))
                }
            )
        ) {
            Ok((n, e)) => (n.as_bytes(), e.as_bytes()),
            Err(_) => return Err(ImportError)
        };

        let mut cloned_modulus = modulus.to_vec(); 
        let mut cloned_public_exponent = public_exponent.to_vec();

        cloned_modulus.reverse();
        cloned_public_exponent.reverse();
        
        RsaPublicKey::from_params(&cloned_modulus, &cloned_public_exponent)
    }
}

fn format_der_integer(x: &BigUint) -> Vec<u8> {
    [vec![0x00], x.to_bytes_be()].concat()
}

fn der_integer_to_asn1_biguint<'a>(der: &'a [u8]) -> Result<asn1::BigUint, RsaError> {
    match asn1::BigUint::new(&der) {
        Some(asn_biguint) => Ok(asn_biguint),
        None => Err(ImportError)
    }
}

impl ToDer for RsaPublicKey {
    fn to_der(&self) -> Result<Vec<u8>, RsaError> {

        let der_integers: Vec<Vec<u8>> = [
            &self.modulus,
            &self.public_exponent
        ].iter().map(|param| format_der_integer(*param)).collect();
        
        match asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                der_integers.iter()
                    .flat_map(|der_integer| der_integer_to_asn1_biguint(der_integer))
                    .map(|asn1_biguint| w.write_element(&asn1_biguint))
                    .collect::<Result<(), WriteError>>()
            }))
        }) {
            Ok(der) => Ok(der.to_vec()),
            Err(_) => Err(ExportError)
        }
    }
}

impl FromPem for RsaPublicKey {
    
    fn from_pem(pem_encoded: &str) -> Result<Self, RsaError> {
        let base64_decoded = match base64_decode(pem_encoded) {
            Ok(decoded) => decoded,
            Err(_) => return Err(ImportError)
        };
        Self::from_der(&base64_decoded)
    }
}

impl ToPem for RsaPublicKey {
    fn to_pem(&self) -> Result<String, RsaError> {
        
        let der = self.to_der()?;

        format_pem(RSA_PUBLIC_KEY_PEM_IDENTIFIER, &der)
    }
}

const RSA_PRIVATE_KEY_PEM_IDENTIFIER: &str = "RSA PRIVATE KEY";

/// An RSA private key.
/// Contains the modulus (n) and the private exponent (d).
#[derive(Debug)]
pub struct RsaPrivateKey {
    modulus: BigUint,
    private_exponent: BigUint,
    public_exponent: BigUint,
    p: BigUint,
    q: BigUint,
    exp_p: BigUint,
    exp_q: BigUint,
    coefficient: BigUint
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
            return Err(ParamsError)
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
            coefficient: coefficient
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

impl FromDer for RsaPrivateKey {
    
    fn from_der(der_encoded: &[u8]) -> Result<Self, RsaError> {
        todo!()
    }
}

impl ToDer for RsaPrivateKey {
    
    fn to_der(&self) -> Result<Vec<u8>, RsaError> {
        todo!()
    }
}

impl FromPem for RsaPrivateKey {
    
    fn from_pem(pem_encoded: &str) -> Result<Self, RsaError> {
        let base64_decoded = match base64_decode(pem_encoded) {
            Ok(decoded) => decoded,
            Err(_) => return Err(ImportError)
        };
        Self::from_der(&base64_decoded)
    }
}

impl ToPem for RsaPrivateKey {
    
    fn to_pem(&self) -> Result<String, RsaError> {
        let der = self.to_der()?;
        format_pem(RSA_PRIVATE_KEY_PEM_IDENTIFIER, &der)
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
        _ => return Err(ParamsError),
    };

    let p = generate_prime(rng, n_bytes_length / 2)?;
    let q = generate_prime(rng, n_bytes_length / 2)?;

    let private_key = match RsaPrivateKey::from_primes(&p.to_bytes_be(), &q.to_bytes_be()) {
        Ok(private_key) => private_key,
        Err(ParamsError) => return generate_rsa_keys(rng, modulus_length),
        Err(any) => return Err(any)
    };

    let public_key = RsaPublicKey::from_params(
        &private_key.modulus.to_bytes_be(), 
        &private_key.public_exponent.to_bytes_be()
    )?;

    Ok((public_key, private_key))
}

#[test]
fn encryption_and_decryption() {
    use num_traits::FromPrimitive;

    /*let public_key = RsaPublicKey {
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
    assert_eq!(recovered, message);*/
}

#[test]
fn sign_and_verify() {
    use num_traits::FromPrimitive;

    /*let public_key = RsaPublicKey {
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
    assert_eq!(verification, message);*/
}

fn format_pem(identifier: &str, data: &[u8]) -> Result<String, RsaError> {
    Ok([
        format_pem_begin(identifier), 
        match base64_encode(data)
            .as_bytes()
            .chunks(64)
            .map(std::str::from_utf8)
            .collect::<Result<Vec<&str>, _>>() 
        {
            Ok(base64_lines) => base64_lines.join("\n"),
            Err(_) => return Err(ExportError)
        }, 
        format_pem_end(identifier)
    ].map(|part| part + "\n").join(""))
}

const PEM_BEGIN: &str= "BEGIN";

fn format_pem_begin(identifier: &str) -> String {
    format!("{}{} {}{}", PEM_BOUNDARIES_DELIMITERS, PEM_BEGIN, identifier, PEM_BOUNDARIES_DELIMITERS)
}

const PEM_END: &str = "END";

fn format_pem_end(identifier: &str) -> String {
    format!("{}{} {}{}", PEM_BOUNDARIES_DELIMITERS, PEM_END, identifier, PEM_BOUNDARIES_DELIMITERS)
}

fn parse_pem(pem: String) -> Result<Vec<u8>, RsaError> {
    
    let mut lines = pem.lines();

    // first line
    match lines.next() {
        Some(_) => (),
        None => return Err(ImportError)
    };

    let mut base64_lines: Vec<&str> = vec![];

    loop {
        match lines.next() {
            Some(line) => base64_lines.push(line),
            None => {
                break;
            }
        };
    }

    // end line
    if base64_lines.pop().is_none() {
        return Err(ImportError);
    }

    match base64_decode(&base64_lines.join("")){
        Ok(der) => Ok(der),
        Err(_) => Err(ImportError)
    }
} 