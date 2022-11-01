use asn1::{ParseError, WriteError};
use num_bigint::BigUint;

use crate::{FromDer, ToDer, RsaPrivateKey, RsaError, RsaError::*, RsaPublicKey, arithmetic::ceil_div, convert::i2osp};

impl FromDer for RsaPrivateKey {
    
    fn from_der(der_encoded: &[u8]) -> Result<Self, RsaError> {
        let (p, q) = match asn1::parse(der_encoded, |parser| {
            parser.read_element::<asn1::Sequence>()?.parse(|sequence| {
                let version = sequence.read_element::<u8>()?;
                if version != 0 {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }
                let _modulus = sequence.read_element::<asn1::BigUint>()?;
                let _public_exponent = sequence.read_element::<asn1::BigUint>()?;
                let _private_exponent = sequence.read_element::<asn1::BigUint>()?;
                let p = sequence.read_element::<asn1::BigUint>()?;
                let q = sequence.read_element::<asn1::BigUint>()?;
                let _exp_p = sequence.read_element::<asn1::BigUint>()?;
                let _exp_q = sequence.read_element::<asn1::BigUint>()?;
                let _coeff = sequence.read_element::<asn1::BigUint>()?;
                Ok::<(asn1::BigUint, asn1::BigUint), asn1::ParseError>((p, q))
            })
        }) {
            Ok((n, e)) => (n.as_bytes(), e.as_bytes()),
            Err(_) => return Err(ImportError),
        };

        RsaPrivateKey::from_primes(&p, &q)
    }
}

impl ToDer for RsaPrivateKey {
    fn to_der(&self) -> Result<Vec<u8>, RsaError> {
        let integers = [
            &self.modulus,
            &self.public_exponent,
            &self.private_exponent,
            &self.p,
            &self.q,
            &self.exp_p,
            &self.exp_q,
            &self.coefficient,
        ];

        match asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element::<u32>(&0)?;
                integers
                    .iter()
                    .flat_map(|integer| biguint_to_der(integer))
                    // TODO: no panic
                    .map(|der_integer| w.write_element(&asn1::BigUint::new(&der_integer).unwrap()))
                    .collect::<Result<(), WriteError>>()
            }))
        }) {
            Ok(der) => Ok(der),
            Err(_) => Err(ExportError),
        }
    }
}

impl FromDer for RsaPublicKey {
    fn from_der(der_encoded: &[u8]) -> Result<Self, RsaError> {
        let (modulus, public_exponent) = match asn1::parse(der_encoded, |parser| {
            parser.read_element::<asn1::Sequence>()?.parse(|sequence| {
                let n = sequence.read_element::<asn1::BigUint>()?;
                let e = sequence.read_element::<asn1::BigUint>()?;
                Ok::<(asn1::BigUint, asn1::BigUint), asn1::ParseError>((n, e))
            })
        }) {
            Ok((n, e)) => (n.as_bytes(), e.as_bytes()),
            Err(_) => return Err(ImportError),
        };

        RsaPublicKey::from_params(&modulus, &public_exponent)
    }
}

impl ToDer for RsaPublicKey {
    fn to_der(&self) -> Result<Vec<u8>, RsaError> {
        match asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                [&self.modulus, &self.public_exponent]
                    .iter()
                    .flat_map(|integer| biguint_to_der(integer))
                    // TODO: no panic
                    .map(|der_integer| w.write_element(&asn1::BigUint::new(&der_integer).unwrap()))
                    .collect()
            }))
        }) {
            Ok(der) => Ok(der),
            Err(_) => Err(ExportError),
        }
    }
}

fn biguint_to_der(n: &BigUint) -> Result<Vec<u8>, RsaError> {
    let bytes = i2osp(n, ceil_div(n.bits() as usize, 8))?;
    match bytes.get(0) {
        Some(byte) => {
            if byte & 0b10000000 > 0 {
                Ok([vec![0x00], bytes].concat())
            } else {
                Ok(bytes)
            }
        }
        None => Err(RsaError::ExportError),
    }
}