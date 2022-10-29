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
    RandomGeneratorFailure
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        let message = match self {
            IntegerTooLarge => "integer too large",
            OctetStringEmpty => "octet string empty",
            MessageRepresentativeOutOfRange => "message representative out of range",
            MessageTooLong => "message too long",
            InvalidKeySize => "invalid key size",
            InvalidBufferSize => "invalid buffer size",
            MaskTooLong => "mask too long",
            DecryptionError => "decryption error",
            EncodingError => "encoding error",
            InvalidSignature => "invalid signature",
            ArithmeticError => "arithmetic error",
            ImportError => "import error",
            ExportError => "export error",
            ParamsError => "params error",
            RandomGeneratorFailure => "random generator failure"
        };

        f.write_fmt(format_args!("{}", message))
    }
}

impl std::error::Error for RsaError {}
