use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, ToPrimitive, Zero};

/// Elevate `base` to the power of `exp` using m as a modulus.
/// This function uses the square and multiply method.
pub(crate) fn modular_pow(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    let mut result = BigUint::one();
    let mut _exp = exp.clone();
    let mut _base = base.clone();

    while _exp.gt(&BigUint::zero()) {
        result = if _exp.bit(0) {
            (&result * &_base) % m
        } else {
            result
        };
        _exp >>= 1;
        _base = (&_base * &_base) % m;
    }

    result
}

/// Find the modular inverse of a with n as a modulus.
/// If GCD(a, n) is not equal to zero, then None will be returned.
pub(crate) fn modular_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    let mut s = BigInt::one();
    let mut old_s = BigInt::zero();

    let mut r = a.clone();
    let mut old_r = n.clone();

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let quotient_as_bigint = quotient.to_bigint().unwrap();

        let saved_r = r.clone();
        r = old_r - &quotient * r;
        old_r = saved_r;

        let saved_s = s.clone();
        s = old_s - &quotient_as_bigint * &s;
        old_s = saved_s;
    }

    if !old_r.is_one() {
        return None;
    }

    let n_as_bigint = n.to_bigint().unwrap();
    let reduced_inverse = &old_s - (&n_as_bigint * (&old_s / &n_as_bigint));

    Some(
        if reduced_inverse.gt(&BigInt::zero()) {
            reduced_inverse
        } else {
            reduced_inverse + &n_as_bigint
        }
        .to_biguint()
        .unwrap(),
    )
}

pub fn ceil_div(a: usize, b: usize) -> usize {
    ((a as f64) / (b as f64)).ceil().to_usize().unwrap()
}
