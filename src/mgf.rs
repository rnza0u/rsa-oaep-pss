use digest::DynDigest;
use num_bigint::BigUint;
use num_traits::FromPrimitive;

use crate::{
    convert::i2osp,
    {RsaError, RsaError::*},
};

pub struct Mgf1 {
    hash: Box<dyn DynDigest>,
}

impl Mgf1 {
    pub fn new(hash: &dyn DynDigest) -> Self {
        Self {
            hash: hash.box_clone(),
        }
    }

    pub fn mask(&mut self, seed: &[u8], output: &mut [u8]) -> Result<(), RsaError> {
        if output.len() > (2_usize).pow(32) {
            return Err(MaskTooLong);
        }

        let hash_length = self.hash.output_size();
        let mut offset: usize = 0;

        for i in 0..output.len() / hash_length - 1 {
            let c = i2osp(&BigUint::from_usize(i).unwrap(), 4)?;
            let seed_c = [seed, &c].concat();
            self.hash.update(&seed_c);
            let mut hash = vec![0_u8; hash_length];
            match self.hash.finalize_into_reset(&mut hash) {
                Err(_) => return Err(InvalidBufferSize),
                _ => (),
            };
            output[offset..offset + hash_length].copy_from_slice(&hash);
            offset += self.hash.output_size();
        }

        Ok(())
    }
}
