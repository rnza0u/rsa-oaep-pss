/// An RSA error object.
#[derive(Debug)]
pub enum RsaError {
    IntegerTooLarge,
    OctetStringEmpty,
    MessageRepresentativeOutOfRange,
    MessageTooLong,
    InvalidBufferSize,
    InvalidKeySize,
    MaskTooLong,
    DecryptionError,
    EncodingError,
    InvalidSignature,
    ArithmeticError,
    ImportError,
    ExportError,
    ParamsError,
    RandomGeneratorFailure,
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            RsaError::IntegerTooLarge => "integer too large",
            RsaError::OctetStringEmpty => "octet string empty",
            RsaError::MessageRepresentativeOutOfRange => "message representative out of range",
            RsaError::MessageTooLong => "message too long",
            RsaError::InvalidKeySize => "invalid key size",
            RsaError::InvalidBufferSize => "invalid buffer size",
            RsaError::MaskTooLong => "mask too long",
            RsaError::DecryptionError => "decryption error",
            RsaError::EncodingError => "encoding error",
            RsaError::InvalidSignature => "invalid signature",
            RsaError::ArithmeticError => "arithmetic error",
            RsaError::ImportError => "import error",
            RsaError::ExportError => "export error",
            RsaError::ParamsError => "params error",
            RsaError::RandomGeneratorFailure => "random generator failure",
        };

        f.write_fmt(format_args!("{}", message))
    }
}

impl std::error::Error for RsaError {}
