use crate::RsaError;

pub trait ToDer {
    /// Export to PEM format.
    fn to_der(&self) -> Result<Vec<u8>, RsaError>;
}

pub trait ToPem {
    /// Export to DER format.
    fn to_pem(&self) -> Result<String, RsaError>;
}
