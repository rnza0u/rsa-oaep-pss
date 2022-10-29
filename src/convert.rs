use num_bigint::{BigUint, ToBigUint};
use num_traits::{FromPrimitive, ToPrimitive, Zero};

use crate::{errors::RsaError::*, RsaError};

#[inline]
pub(crate) fn i2osp(x: &BigUint, size: usize) -> Result<Vec<u8>, RsaError> {
    if size == 0 {
        return Err(IntegerTooLarge);
    }

    let mut _x = x.clone();
    let mut output = vec![0_u8; size];

    for i in 0..size {
        output[size - 1 - i] = (&_x & &BigUint::from_u8(0xff).unwrap()).to_u8().unwrap();
        _x >>= 8;
    }

    if _x.is_zero() {
        Ok(output)
    } else {
        Err(IntegerTooLarge)
    }
}

#[test]
fn i2osp_with_one_byte() {
    let n = BigUint::from_u8(255).unwrap();

    let bytes = i2osp(&n, 1).expect("result is expected");

    assert_eq!(bytes, [0xff]);
}

#[test]
fn i2osp_with_zero() {
    let bytes = i2osp(&BigUint::zero(), 1).expect("result is expected");
    assert_eq!(bytes, [0]);
}

#[test]
fn i2osp_with_zero_and_extra_padding() {
    let bytes = i2osp(&BigUint::zero(), 4).expect("result is expected");
    assert_eq!(bytes, [0, 0, 0, 0]);
}

#[test]
fn i2osp_with_too_large_number() {
    let result = i2osp(&BigUint::from_u16(256).unwrap(), 1);
    assert!(result.is_err());
}

#[test]
fn i2osp_with_large_number() {
    use std::str::FromStr;

    let n = BigUint::from_str("18446744073709551612").unwrap();
    let bytes = i2osp(&n, 8).expect("result is expected");
    assert_eq!(bytes, [255_u8, 255, 255, 255, 255, 255, 255, 252]);
}

#[inline]
pub(crate) fn os2ip(x: &[u8]) -> Result<BigUint, RsaError> {
    let length = x.len();

    if length == 0 {
        return Err(OctetStringEmpty);
    }

    let mut output = BigUint::zero();

    for i in x {
        output <<= u8::BITS;
        output += i.to_biguint().unwrap();
    }

    Ok(output)
}

#[test]
fn octet_string_to_unsigned_integer_with_few_bytes() {
    let bytes = [0xff, 0xff, 0xff, 0xff];
    let n = os2ip(&bytes).expect("result is expected");
    assert_eq!(n, BigUint::from_usize(4_294_967_295).unwrap());
}

#[test]
fn octet_string_to_unsigned_integer_with_lots_of_zeroes() {
    let bytes = [0].repeat(100);
    let n = os2ip(&bytes).expect("result is expected");
    assert_eq!(n, BigUint::zero());
}

#[test]
fn octet_string_to_unsigned_integer_with_empty_octet_string() {
    let bytes: [u8; 0] = [];
    let error = os2ip(&bytes);
    assert!(error.is_err());
}

#[test]
fn double_conversion() {
    let n = BigUint::from_u64(13425232878441541).unwrap();
    let bytes = i2osp(&n, 32).expect("result is expected");
    let back_to_n = os2ip(&bytes).expect("result is expected");
    assert_eq!(n, back_to_n);
}

pub fn xor_buffers(a: &[u8], b: &[u8]) -> Result<Vec<u8>, RsaError> {
    if a.len() != b.len() {
        return Err(InvalidBufferSize);
    }
    let mut output = a.to_vec();
    for (i, x) in b.iter().enumerate() {
        output[i] ^= x;
    }
    Ok(output)
}
