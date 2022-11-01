use base64::{decode as base64_decode, encode as base64_encode};
use crate::{FromPem, ToPem, RsaPublicKey, RsaPrivateKey, RsaError, RsaError::*, FromDer, ToDer};

const PEM_BOUNDARIES_DELIMITERS: &str = "-----";
const PEM_BEGIN: &str = "BEGIN";
const PEM_END: &str = "END";

const RSA_PUBLIC_KEY_PEM_IDENTIFIER: &str = "RSA PUBLIC KEY";

impl FromPem for RsaPublicKey {
    fn from_pem(pem_encoded: &str) -> Result<Self, RsaError> {
        let der = parse_pem(pem_encoded)?;
        Self::from_der(&der)
    }
}

impl ToPem for RsaPublicKey {
    fn to_pem(&self) -> Result<String, RsaError> {
        let der = self.to_der()?;
        format_pem(RSA_PUBLIC_KEY_PEM_IDENTIFIER, &der)
    }
}

const RSA_PRIVATE_KEY_PEM_IDENTIFIER: &str = "RSA PRIVATE KEY";

impl FromPem for RsaPrivateKey {
    fn from_pem(pem_encoded: &str) -> Result<Self, RsaError> {
        let der = parse_pem(pem_encoded)?;
        Self::from_der(&der)
    }
}

impl ToPem for RsaPrivateKey {
    fn to_pem(&self) -> Result<String, RsaError> {
        let der = self.to_der()?;
        format_pem(RSA_PRIVATE_KEY_PEM_IDENTIFIER, &der)
    }
}

fn format_pem_begin(identifier: &str) -> String {
    format!(
        "{}{} {}{}",
        PEM_BOUNDARIES_DELIMITERS, PEM_BEGIN, identifier, PEM_BOUNDARIES_DELIMITERS
    )
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
            Err(_) => return Err(ExportError),
        },
        format_pem_end(identifier),
    ]
    .map(|part| part + "\n")
    .join(""))
}

fn format_pem_end(identifier: &str) -> String {
    format!(
        "{}{} {}{}",
        PEM_BOUNDARIES_DELIMITERS, PEM_END, identifier, PEM_BOUNDARIES_DELIMITERS
    )
}

fn parse_pem(pem: &str) -> Result<Vec<u8>, RsaError> {
    let mut lines = pem.lines();

    // first line
    match lines.next() {
        Some(_) => (),
        None => return Err(ImportError),
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

    match base64_decode(&base64_lines.join("")) {
        Ok(der) => Ok(der),
        Err(_) => Err(ImportError),
    }
}
