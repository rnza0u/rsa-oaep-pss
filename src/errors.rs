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
            Self::IntegerTooLarge => "integer too large",
            Self::OctetStringEmpty => "octet string empty",
            Self::MessageRepresentativeOutOfRange => "message representative out of range",
            Self::MessageTooLong => "message too long",
            Self::InvalidKeySize => "invalid key size",
            Self::InvalidBufferSize => "invalid buffer size",
            Self::MaskTooLong => "mask too long",
            Self::DecryptionError => "decryption error",
            Self::EncodingError => "encoding error",
            Self::InvalidSignature => "invalid signature",
            Self::ArithmeticError => "arithmetic error",
            Self::ImportError => "import error",
            Self::ExportError => "export error",
            Self::ParamsError => "params error",
            Self::RandomGeneratorFailure => "random generator failure"
        };

        f.write_fmt(format_args!("{}", message))
    }
}

impl std::error::Error for RsaError {}
