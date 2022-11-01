use crate::RsaError;

pub trait FromPem
where
    Self: Sized,
{
    /// Import from PEM encoded message.
    fn from_pem(pem_encoded: &str) -> Result<Self, RsaError>;
}

pub trait FromDer
where
    Self: Sized,
{
    /// Import from DER encoded message.
    fn from_der(der_encoded: &[u8]) -> Result<Self, RsaError>;
}
