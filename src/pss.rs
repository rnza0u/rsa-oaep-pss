use digest::DynDigest;
use rand_core::{CryptoRng, RngCore};

use crate::{
    arithmetic::ceil_div,
    convert::{i2osp, os2ip, xor_buffers},
    mgf::Mgf1,
    RsaPrivateKey, RsaPublicKey,
    {RsaError, RsaError::*},
};

/// A Probabilistic Signature Scheme object used for signature and verification.
pub struct RsaPss<T>
where
    T: RngCore + CryptoRng,
{
    rng: T,
    hash: Box<dyn DynDigest>,
    mgf: Mgf1,
    s_len: usize,
}

impl<T> RsaPss<T>
where
    T: RngCore + CryptoRng,
{
    /// Create a new [`RsaPss`] object using the provided RNG and hash function.
    pub fn new(rng: T, hash: &dyn DynDigest) -> Self {
        Self::new_with_salt_length(rng, hash, 32)
    }

    /// Create a new [`RsaPss`] object using the provided RNG, hash function and salt length.
    pub fn new_with_salt_length(rng: T, hash: &dyn DynDigest, salt_length: usize) -> Self {
        RsaPss {
            rng,
            mgf: Mgf1::new(hash),
            hash: hash.box_clone(),
            s_len: salt_length,
        }
    }

    ///  Sign a message.
    pub fn sign(
        &mut self,
        private_key: &RsaPrivateKey,
        message: &[u8],
    ) -> Result<Vec<u8>, RsaError> {
        let k = private_key.get_modulus_size();

        let em = self.emsa_pss_encode(message, (k * 8) - 1)?;

        let m = os2ip(&em)?;

        let s = private_key.rsasp(&m)?;

        let output = i2osp(&s, k)?;

        Ok(output)
    }

    ///  Verify a signature against a message.
    pub fn verify(
        &mut self,
        public_key: &RsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), RsaError> {
        let k = public_key.get_modulus_size();

        if signature.len() != k {
            return Err(InvalidSignature);
        }

        let s = os2ip(signature)?;

        let m = public_key.rsavp(&s)?;

        let em = i2osp(&m, ceil_div(k * 8 - 1, 8))?;

        match self.emsa_pss_verify(&message, &em, (k * 8) - 1) {
            true => Ok(()),
            false => Err(InvalidSignature),
        }
    }

    fn emsa_pss_encode(&mut self, m: &[u8], em_bits: usize) -> Result<Vec<u8>, RsaError> {
        // TODO: check max size of hash function

        let em_len = ceil_div(em_bits, 8);
        let h_len = self.hash.output_size();

        let mut m_hash = vec![0_u8; h_len];
        self.hash.update(m);
        match self.hash.finalize_into_reset(&mut m_hash) {
            Ok(()) => (),
            Err(_) => return Err(InvalidBufferSize),
        };

        if em_len < h_len + self.s_len + 2 {
            return Err(EncodingError);
        }

        let mut salt = vec![0_u8; self.s_len];

        match self.rng.try_fill_bytes(&mut salt) {
            Ok(()) => (),
            Err(_) => return Err(RandomGeneratorFailure),
        }

        let p_mh_s = [[0x00].repeat(8), m_hash, salt.clone()].concat();

        let mut p_mh_s_h = vec![0_u8; h_len];
        self.hash.update(&p_mh_s);
        match self.hash.finalize_into_reset(&mut p_mh_s_h) {
            Ok(()) => (),
            Err(_) => return Err(InvalidBufferSize),
        };

        let ps = vec![0_u8; em_len - self.s_len - h_len - 2];

        let db = [ps, [0x01].to_vec(), salt.clone()].concat();

        let mut db_mask = vec![0_u8; db.len()];
        self.mgf.mask(&p_mh_s_h, &mut db_mask)?;

        let mut masked_db = xor_buffers(&db, &db_mask)?;

        let mut zeroes = u8::MAX;
        zeroes >>= (8 * em_len) - em_bits;
        masked_db[0] &= zeroes;

        Ok([masked_db, p_mh_s_h, [0xbc].to_vec()].concat())
    }

    fn emsa_pss_verify(&mut self, m: &[u8], em: &[u8], em_bits: usize) -> bool {
        // TODO: check max hash input

        let em_len = ceil_div(em_bits, 8);
        let h_len = self.hash.output_size();

        let mut m_hash = vec![0_u8; h_len];
        self.hash.update(m);
        match self.hash.finalize_into_reset(&mut m_hash) {
            Ok(_) => (),
            Err(_) => return false,
        };

        if em_len < h_len + self.s_len + 2 {
            return false;
        }

        if !em.last().map(|l| *l == 0xbc).unwrap_or(false) {
            return false;
        }

        let masked_db = em[0..em_len - h_len - 1].to_vec();
        let h = &em[em_len - h_len - 1..em_len - h_len - 1 + h_len];

        let mut db_mask = vec![0_u8; masked_db.len()];
        match self.mgf.mask(&h, &mut db_mask) {
            Ok(_) => (),
            Err(_) => return false,
        };

        let mut db = match xor_buffers(&masked_db, &db_mask) {
            Ok(db) => db,
            Err(_) => return false,
        };

        let mut zeroes = u8::MAX;
        zeroes >>= (8 * em_len) - em_bits;
        db[0] &= zeroes;

        if db[0..em_len - h_len - self.s_len - 2]
            .iter()
            .any(|x| *x != 0)
        {
            return false;
        }

        let salt = &db[(db.len() - self.s_len)..];

        let mp = [[0x00].repeat(8), m_hash, salt.to_vec()].concat();

        let mut mp_hash = vec![0_u8; h_len];
        self.hash.update(&mp);
        match self.hash.finalize_into_reset(&mut mp_hash) {
            Ok(_) => (),
            Err(_) => return false,
        };

        h == mp_hash
    }
}
