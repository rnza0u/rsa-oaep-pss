/// An RSA error object.
#[derive(Debug)]
pub struct RsaError {
    message: String,
}

impl RsaError {
    pub(crate) fn new(msg: &str) -> Self {
        RsaError {
            message: msg.to_string(),
        }
    }

    pub(crate) fn integer_too_large() -> Self {
        Self::new("integer too large")
    }

    pub(crate) fn octet_string_empty() -> Self {
        Self::new("octet string empty")
    }

    pub(crate) fn message_representative_out_of_range() -> Self {
        Self::new("message representative out of range")
    }

    pub(crate) fn random_generator_failure() -> Self {
        Self::new("random generator failure")
    }

    pub(crate) fn message_too_long() -> Self {
        Self::new("message too long")
    }

    pub(crate) fn invalid_buffer_size() -> Self {
        Self::new("invalid buffer size")
    }

    pub(crate) fn mask_too_long() -> Self {
        Self::new("mask too long")
    }

    pub(crate) fn decryption_error() -> Self {
        Self::new("decryption error")
    }

    pub(crate) fn invalid_key_size() -> Self {
        Self::new("invalid key size")
    }

    pub(crate) fn encoding_error() -> Self {
        Self::new("encoding error")
    }

    pub(crate) fn invalid_signature() -> Self {
        Self::new("invalid signature")
    }

    pub(crate) fn arithmetic_error() -> Self {
        Self::new("arithmetic error")
    }
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.message))
    }
}

impl std::error::Error for RsaError {}
