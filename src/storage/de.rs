use std::array::TryFromSliceError;
use std::convert::TryInto;

use cosmwasm_std::{Addr, StdError, StdResult};

use crate::storage::int_key::CwIntKey;

pub trait KeyDeserialize {
    type Output: Sized;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output>;

    fn from_slice(value: &[u8]) -> StdResult<Self::Output> {
        Self::from_vec(value.to_vec())
    }
}

impl KeyDeserialize for () {
    type Output = ();

    #[inline(always)]
    fn from_vec(_value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(())
    }
}

impl KeyDeserialize for Vec<u8> {
    type Output = Vec<u8>;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(value)
    }
}

impl KeyDeserialize for &Vec<u8> {
    type Output = Vec<u8>;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(value)
    }
}

impl KeyDeserialize for &[u8] {
    type Output = Vec<u8>;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(value)
    }
}

impl KeyDeserialize for String {
    type Output = String;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value).map_err(StdError::invalid_utf8)
    }
}

impl KeyDeserialize for &String {
    type Output = String;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Self::Output::from_vec(value)
    }
}

impl KeyDeserialize for &str {
    type Output = String;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Self::Output::from_vec(value)
    }
}

impl KeyDeserialize for Addr {
    type Output = Addr;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(Addr::unchecked(String::from_vec(value)?))
    }
}

impl KeyDeserialize for &Addr {
    type Output = Addr;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Self::Output::from_vec(value)
    }
}

macro_rules! integer_de {
    (for $($t:ty),+) => {
        $(impl KeyDeserialize for $t {
            type Output = $t;

            #[inline(always)]
            fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
                Ok(<$t>::from_cw_bytes(value.as_slice().try_into()
                    .map_err(|err: TryFromSliceError| StdError::generic_err(err.to_string()))?))
            }
        })*
    }
}

integer_de!(for i8, u8, i16, u16, i32, u32, i64, u64, i128, u128);

fn parse_length(value: &[u8]) -> StdResult<usize> {
    Ok(u16::from_be_bytes(
        value
            .try_into()
            .map_err(|_| StdError::generic_err("Could not read 2 byte length"))?,
    )
    .into())
}

impl<T: KeyDeserialize, U: KeyDeserialize> KeyDeserialize for (T, U) {
    type Output = (T::Output, U::Output);

    #[inline(always)]
    fn from_vec(mut value: Vec<u8>) -> StdResult<Self::Output> {
        let mut tu = value.split_off(2);
        let t_len = parse_length(&value)?;
        let u = tu.split_off(t_len);

        Ok((T::from_vec(tu)?, U::from_vec(u)?))
    }
}

impl<T: KeyDeserialize, U: KeyDeserialize, V: KeyDeserialize> KeyDeserialize for (T, U, V) {
    type Output = (T::Output, U::Output, V::Output);

    #[inline(always)]
    fn from_vec(mut value: Vec<u8>) -> StdResult<Self::Output> {
        let mut tuv = value.split_off(2);
        let t_len = parse_length(&value)?;
        let mut len_uv = tuv.split_off(t_len);

        let mut uv = len_uv.split_off(2);
        let u_len = parse_length(&len_uv)?;
        let v = uv.split_off(u_len);

        Ok((T::from_vec(tuv)?, U::from_vec(uv)?, V::from_vec(v)?))
    }
}
