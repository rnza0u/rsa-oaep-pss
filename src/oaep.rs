use digest::DynDigest;
use rand_core::{CryptoRng, RngCore};

use crate::{
    mgf::Mgf1,
    utils::{i2osp, os2ip, xor_buffers},
    RsaError, RsaPrivateKey, RsaPublicKey,
};

pub struct RsaOaep<T>
where
    T: CryptoRng + RngCore,
{
    rng: T,
    hash: Box<dyn DynDigest>,
    mgf: Mgf1,
}

impl<T> RsaOaep<T>
where
    T: CryptoRng + RngCore,
{
    pub fn new(rng: T, hash: &dyn DynDigest) -> Self {
        Self {
            rng,
            hash: hash.box_clone(),
            mgf: Mgf1::new(hash),
        }
    }

    pub fn encrypt(
        &mut self,
        public_key: &RsaPublicKey,
        message: &[u8]
    ) -> Result<Vec<u8>, RsaError> {
        self.encrypt_with_label(public_key, message, b"")
    }

    pub fn encrypt_with_label(
        &mut self,
        public_key: &RsaPublicKey,
        message: &[u8],
        label: &[u8],
    ) -> Result<Vec<u8>, RsaError> {
        let hash_length = self.hash.output_size();
        let two_hash_length = 2 * hash_length;

        // TODO: check for max hash input size

        let k = public_key.get_modulus_size();

        if message.len() > k - two_hash_length - 2 {
            return Err(RsaError::message_too_long());
        }

        let mut label_hash = vec![0_u8; hash_length];

        self.hash.update(label);

        match self.hash.finalize_into_reset(&mut label_hash) {
            Err(_) => return Err(RsaError::invalid_buffer_size()),
            _ => (),
        };

        let ps = vec![0_u8; k - message.len() - two_hash_length - 2];
        let mut db = [label_hash, ps].concat();
        db.push(0x01);
        db.extend_from_slice(message);

        let mut seed = vec![0_u8; hash_length];

        match self.rng.try_fill_bytes(&mut seed) {
            Err(_) => return Err(RsaError::random_generator_failure()),
            _ => (),
        };

        let mut db_mask = vec![0_u8; k - hash_length - 1];
        self.mgf.mask(&seed, &mut db_mask)?;

        let masked_db = xor_buffers(&db, &db_mask)?;

        let mut seed_mask = vec![0_u8; hash_length];
        self.mgf.mask(&masked_db, &mut seed_mask)?;

        let masked_seed = xor_buffers(&seed, &seed_mask)?;

        let em = vec![&[0x00_u8][..], &masked_seed[..], &masked_db[..]].concat();

        let m = os2ip(&em)?;

        let c = public_key.rsaep(&m)?;

        i2osp(&c, k)
    }


    pub fn decrypt(
        &mut self,
        private_key: &RsaPrivateKey,
        ciphertext: &[u8]
    ) -> Result<Vec<u8>, RsaError> {
        self.decrypt_with_label(private_key, ciphertext, b"")
    }

    pub fn decrypt_with_label(
        &mut self,
        private_key: &RsaPrivateKey,
        ciphertext: &[u8],
        label: &[u8],
    ) -> Result<Vec<u8>, RsaError> {
        // TODO: check for max hash input size

        let k = private_key.get_modulus_size();
        let hash_length = self.hash.output_size();

        if [ciphertext.len() != k, k < 2 * hash_length + 2]
            .iter()
            .any(|check| *check)
        {
            return Err(RsaError::decryption_error());
        }

        let ciphertext_as_biguint = os2ip(&ciphertext)?;

        let m = match private_key.rsadp(&ciphertext_as_biguint) {
            Ok(m) => m,
            Err(_) => return Err(RsaError::decryption_error()),
        };

        let em = i2osp(&m, k)?;

        let mut label_hash = vec![0_u8; hash_length];

        self.hash.update(label);

        match self.hash.finalize_into_reset(&mut label_hash) {
            Err(_) => return Err(RsaError::invalid_buffer_size()),
            _ => (),
        };

        let mut offset = 1;
        let y = em[0];

        if y != 0 {
            return Err(RsaError::decryption_error());
        }

        let mut masked_seed = vec![0_u8; hash_length];
        masked_seed.copy_from_slice(&em[offset..(offset + hash_length)]);
        offset += hash_length;

        let db_length = k - hash_length - 1;
        let mut masked_db = vec![0_u8; db_length];
        masked_db.copy_from_slice(&em[offset..offset + db_length]);

        let mut seed_mask = vec![0_u8; hash_length];
        self.mgf.mask(&masked_db, &mut seed_mask)?;

        let seed = xor_buffers(&masked_seed, &seed_mask)?;

        let mut db_mask = vec![0_u8; db_length];
        self.mgf.mask(&seed, &mut db_mask)?;

        let db = xor_buffers(&masked_db, &db_mask)?;

        let mut label_hash_in_db = vec![0_u8; hash_length];
        label_hash_in_db.copy_from_slice(&db[0..hash_length]);

        if label_hash_in_db != label_hash {
            return Err(RsaError::decryption_error());
        }

        let mut message_start = hash_length;
        loop {
            match db[message_start] {
                0x00 => message_start += 1,
                0x01 => break,
                _ => return Err(RsaError::decryption_error()),
            };
            if message_start == db.len() - 1 {
                return Err(RsaError::decryption_error());
            }
        }
        message_start += 1;

        let mut message = vec![0_u8; db.len() - message_start];
        message.copy_from_slice(&db[message_start..]);

        Ok(message)
    }
}