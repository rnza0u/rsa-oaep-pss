use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};
use rand_core::{CryptoRng, RngCore};

use crate::{arithmetic::modular_pow, convert::os2ip};

use super::errors::RsaError;

/// Generate a probable prime number using the given RNG as a source of randomness.
/// This function will use multithreading.
/// Error can happen if the RNG fails to generate randomn data, otherwise
/// a prime number of the given length will eventually be returned.
pub fn generate_prime<T>(rng: &mut T, length: usize) -> Result<BigUint, RsaError>
where
    T: RngCore + CryptoRng,
{
    const NUMBERS_PER_THREAD: usize = 5;

    let threads_count = num_cpus::get();
    let mut random_bytes = vec![0_u8; length * NUMBERS_PER_THREAD * threads_count];

    loop {
        match rng.try_fill_bytes(&mut random_bytes) {
            Err(_) => return Err(RsaError::RandomGeneratorFailure),
            _ => (),
        };

        for i in (0..random_bytes.len()).step_by(length) {
            random_bytes[i] |= 0b11000000;
            random_bytes[i + length - 1] |= 0b00000001;
        }

        let mut threads = Vec::with_capacity(threads_count);

        for i in 0..threads_count {
            let mut candidates: Vec<BigUint> = Vec::with_capacity(NUMBERS_PER_THREAD);

            for y in 0..NUMBERS_PER_THREAD {
                let offset = (length * y) + (i * NUMBERS_PER_THREAD * length);
                let candidate_bytes = &random_bytes[offset..(offset + length)];
                let candidate = os2ip(candidate_bytes)?;
                candidates.push(candidate);
            }

            threads.push(std::thread::spawn(|| {
                for candidate in candidates {
                    if is_prime(&candidate) {
                        return Some(candidate);
                    }
                }
                None
            }));
        }

        for thread in threads {
            match thread.join().unwrap() {
                Some(n) => return Ok(n),
                _ => (),
            }
        }
    }
}

/// Check if n is prime or composite.
/// Returns false if n is composite, true if the n is likely to be a prime.
/// We use the little Fermat theorem to check if the numbers [2, 3, 5, 7], each raised to the power of phi(n) are
/// congruent to 1, using n as a modulus.
fn is_prime(n: &BigUint) -> bool {
    let witnesses = [2_u8, 3, 5, 7].map(|witness| BigUint::from_u8(witness).unwrap());
    let phi_n = n - BigUint::one();

    for base in witnesses {
        if !modular_pow(&base, &phi_n, n).is_one() {
            return false;
        }
    }

    true
}
