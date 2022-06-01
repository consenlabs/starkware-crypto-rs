// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Public and secret keys

use core::{fmt, str};

use crate::utils::{from_hex};
// use super::Error::{self, InvalidPublicKey, InvalidSecretKey};
// use Signing;
// use Verification;
use crate::{constants, Error};
use crate::{impl_array_newtype, impl_pretty_debug, impl_raw_debug};
use crate::CPtr;
// use ffi::{self, CPtr};
use crate::constants::{SECRET_KEY_SIZE, MAX_BUFFER_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE};

use std::convert::TryInto;

fn convert_vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
  v.try_into()
    .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}


/// Secret 256-bit key used as `x` in an ECDSA signature
pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE);
impl_pretty_debug!(SecretKey);

impl fmt::LowerHex for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    for ch in &self.0[..] {
      write!(f, "{:02x}", *ch)?;
    }
    Ok(())
  }
}

impl fmt::Display for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::LowerHex::fmt(self, f)
  }
}

impl str::FromStr for SecretKey {
  type Err = Error;
  fn from_str(s: &str) -> Result<SecretKey, Error> {
    let mut res = [0; constants::SECRET_KEY_SIZE];
    match from_hex(s, &mut res) {
      Ok(constants::SECRET_KEY_SIZE) => SecretKey::from_slice(&res),
      _ => Err(Error::InvalidSecretKey)
    }
  }
}

/// The number 1 encoded as a secret key
pub const ONE_KEY: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 1]);

// #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct PublicKey([u8; 64]);
impl_array_newtype!(PublicKey, u8, 64);
impl_raw_debug!(PublicKey);

// /// A Secp256k1 public key, used for verification of signatures
// #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
// #[repr(transparent)]
// pub struct PublicKey(ffi::PublicKey);

impl fmt::LowerHex for PublicKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let ser = self.serialize();
    for ch in &ser[..] {
      write!(f, "{:02x}", *ch)?;
    }
    Ok(())
  }
}

impl fmt::Display for PublicKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    fmt::LowerHex::fmt(self, f)
  }
}

impl str::FromStr for PublicKey {
  type Err = Error;
  fn from_str(s: &str) -> Result<PublicKey, Error> {
    let mut res = [0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
    match from_hex(s, &mut res) {
      Ok(constants::PUBLIC_KEY_SIZE) => {
        PublicKey::from_slice(
          &res[0..constants::PUBLIC_KEY_SIZE]
        )
      }
      Ok(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE) => {
        PublicKey::from_slice(&res)
      }
      _ => Err(Error::InvalidPublicKey)
    }
  }
}

fn random_32_bytes<R: Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
  let mut ret = [0u8; 32];
  rng.fill_bytes(&mut ret);
  ret
}


fn is_sk_validation(data: &[u8]) -> bool {
  let mut buffer = [0u8; MAX_BUFFER_SIZE];
  let mut sk = data.to_vec().clone();
  sk.reverse();
  unsafe {
    let res = SeckeyValidate(sk.as_ptr(), buffer.as_mut_ptr());
    return res == 0;
  }
}


use ::std::os::raw::{c_uchar, c_int};
use std::os::raw::c_uint;
use std::ptr;
use std::sync::atomic;
use generic_array::GenericArray;
use rand::Rng;
use zeroize::Zeroize;
use crate::Error::InvalidTweak;

extern "C" {
  // keys
  fn SeckeyValidate(sk: *const c_uchar, out: *mut c_uchar) -> c_int;
  fn SeckeyNegate(sk: *const c_uchar, out: *mut c_uchar) -> c_int;
  fn SeckeyInvert(sk: *const c_uchar, out: *mut c_uchar) -> c_int;
  fn SeckeyTweakAdd(sk: *const c_uchar, other: *const c_uchar, out: *mut c_uchar) -> c_int;
  fn SeckeyTweakMul(sk: *const c_uchar, other: *const c_uchar, out: *mut c_uchar) -> c_int;

  fn PubkeyParse(pubkey: *const c_uchar, size: ::std::os::raw::c_int, out: *mut c_uchar) -> c_int;
  // fn PubkeySerialize(pubkey: *const c_uchar, out: *mut c_uchar, out_len: *mut c_uint, compressed: c_int) -> c_int;
  fn PubkeyNegate(pubkey: *const c_uchar, out: *mut c_uchar) -> c_int;
  fn PubkeyTweakAdd(pubkey: *const c_uchar, other: *const c_uchar, out: *mut c_uchar) -> c_int;
  fn PubkeyTweakMul(pubkey: *const c_uchar, other: *const c_uchar, out: *mut c_uchar) -> c_int;
  // fn PubkeyCombine(pubkey: *mut c_uchar, other: *const *const c_uchar, len: c_uint) -> c_int;

  fn GetPublicKey(private_key: *const c_uchar, out: *mut c_uchar) -> c_int;
}

impl Zeroize for SecretKey {
  fn zeroize(&mut self) {
    let sk = self.as_mut_ptr();
    let sk_bytes = unsafe { std::slice::from_raw_parts_mut(sk, 32) };
    sk_bytes.zeroize()
  }
}

impl Zeroize for PublicKey {
  fn zeroize(&mut self) {
    // let zeroed = [0u8; 64].as_ptr();
    unsafe { ptr::write_volatile(self.0.as_mut_ptr(), 0) };
    atomic::compiler_fence(atomic::Ordering::SeqCst);
  }
}

impl SecretKey {
  /// Creates a new random secret key. Requires compilation with the "rand" feature.
  #[inline]
  pub fn new<R: Rng + ?Sized>(rng: &mut R) -> SecretKey {
    let mut data = [0u8; constants::SECRET_KEY_SIZE];
    while !is_sk_validation(&data) {
      data = random_32_bytes(rng);
    }
    SecretKey(data)
  }

  pub fn zero() -> Self {
    SecretKey([0u8; SECRET_KEY_SIZE])
  }

  pub fn is_zero(&self) -> bool {
    return self.0 == [0u8; SECRET_KEY_SIZE];
  }

  /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key
  #[inline]
  pub fn from_slice(data: &[u8]) -> Result<SecretKey, Error> {
    if (data == [0u8; SECRET_KEY_SIZE]) {
      return Ok(Self::zero());
    }
    match data.len() {
      constants::SECRET_KEY_SIZE => {
        let mut ret = [0; constants::SECRET_KEY_SIZE];
        if !is_sk_validation(&data) {
          return Err(Error::InvalidSecretKey);
        }
        ret[..].copy_from_slice(data);
        Ok(SecretKey(ret))
      }
      _ => Err(Error::InvalidSecretKey)
    }
  }

  pub fn to_bytes(&self) -> GenericArray<u8, typenum::U32> {
    GenericArray::from_slice(&self.0).clone()
  }

  #[inline]
  pub fn invert_assign(&mut self) -> Result<(), Error> {
    let mut buffer = [0u8; MAX_BUFFER_SIZE];
    unsafe {
      self.0.reverse();
      let res = SeckeyInvert(
        self.as_c_ptr(),
        buffer.as_mut_ptr(),
      );
      if res == 0 {
        self.0.copy_from_slice(&buffer[0..SECRET_KEY_SIZE]);
        self.0.reverse();
        return Ok(());
      } else {
        self.0.reverse();
        return Err(Error::InvalidTweak);
      }
    };
  }

  #[inline]
  /// Negates one secret key.
  pub fn negate_assign(&mut self) -> Result<(), Error> {
    let mut buffer = [0u8; MAX_BUFFER_SIZE];
    unsafe {
      self.0.reverse();
      let res = SeckeyNegate(
        self.as_c_ptr(),
        buffer.as_mut_ptr(),
      );
      if res == 0 {
        self.0.copy_from_slice(&buffer[0..SECRET_KEY_SIZE]);
        self.0.reverse();
        return Ok(());
      } else {
        self.0.reverse();
        return Err(Error::InvalidTweak);
      }
    };
  }

  #[inline]
  /// Adds one secret key to another, modulo the curve order. WIll
  /// return an error if the resulting key would be invalid or if
  /// the tweak was not a 32-byte length slice.
  pub fn add_assign(
    &mut self,
    other: &Self,
  ) -> Result<(), Error> {
    if other.len() != 32 {
      return Err(Error::InvalidTweak);
    }
    let mut buffer = [0u8; MAX_BUFFER_SIZE];
    unsafe {
      self.0.reverse();
      let mut other_copy = other.0.clone();
      other_copy.reverse();
      if SeckeyTweakAdd(
        self.as_c_ptr(),
        other_copy.as_c_ptr(),
        buffer.as_mut_ptr(),
      ) != 0
      {
        self.0.reverse();
        Err(Error::InvalidTweak)
      } else {
        self.0.copy_from_slice(&buffer[0..SECRET_KEY_SIZE]);
        self.0.reverse();
        Ok(())
      }
    }
  }

  #[inline]
  /// Multiplies one secret key by another, modulo the curve order. Will
  /// return an error if the resulting key would be invalid or if
  /// the tweak was not a 32-byte length slice.
  pub fn mul_assign(
    &mut self,
    &other: &Self,
  ) -> Result<(), Error> {
    if other.len() != 32 {
      return Err(Error::InvalidTweak);
    }
    let mut buffer = [0u8; MAX_BUFFER_SIZE];
    unsafe {
      self.0.reverse();
      let mut other_copy = other.0.clone();
      other_copy.reverse();
      if SeckeyTweakMul(
        self.as_mut_c_ptr(),
        other_copy.as_c_ptr(),
        buffer.as_mut_ptr(),
      ) != 0
      {
        self.0.reverse();
        Err(Error::InvalidTweak)
      } else {
        self.0.copy_from_slice(&buffer[0..SECRET_KEY_SIZE]);
        self.0.reverse();
        Ok(())
      }
    }
  }
}
//
// impl ::serde::Serialize for SecretKey {
//   fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
//     if s.is_human_readable() {
//       s.collect_str(self)
//     } else {
//       s.serialize_bytes(&self[..])
//     }
//   }
// }
//
// impl<'de> ::serde::Deserialize<'de> for SecretKey {
//   fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
//     if d.is_human_readable() {
//       d.deserialize_str(super::serde_util::FromStrVisitor::new(
//         "a hex string representing 32 byte SecretKey"
//       ))
//     } else {
//       d.deserialize_bytes(super::serde_util::BytesVisitor::new(
//         "raw 32 bytes SecretKey",
//         SecretKey::from_slice,
//       ))
//     }
//   }
// }

impl PublicKey {
  // /// Obtains a raw const pointer suitable for use with FFI functions
  // #[inline]
  // pub fn as_ptr(&self) -> *const u8 {
  //   self.0.as_ptr()
  // }
  //
  // /// Obtains a raw mutable pointer suitable for use with FFI functions
  // #[inline]
  // pub fn as_mut_ptr(&mut self) -> *mut u8 {
  //   self.0.as_mut_ptr()
  // }

  pub fn zero() -> Self {
    let zero = [0u8; 64];
    PublicKey(zero)
  }

  pub fn is_zero(&self) -> bool {
    self == &Self::zero()
  }


  /// Creates a new public key from a secret key.
  #[inline]
  pub fn from_secret_key(sk: &SecretKey) -> PublicKey {
    let mut buffer = [0u8; MAX_BUFFER_SIZE];

    unsafe {
      let mut sk_in_le = sk.0.clone();
      sk_in_le.reverse();
      let res = GetPublicKey(
        sk_in_le.as_ptr(),
        buffer.as_mut_ptr(),
      );
      debug_assert_eq!(res, 0);
      Self::parse_pk_from_le(&buffer)
    }
  }

  fn parse_pk_from_le(buffer: &[u8; MAX_BUFFER_SIZE]) -> PublicKey {
    let mut output = [0u8; 64];
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&buffer[0..32]);
    x_bytes.reverse();

    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(&buffer[32..64]);
    y_bytes.reverse();

    output.copy_from_slice(&[x_bytes, y_bytes].concat());
    PublicKey(output)
  }

  fn convert_pk_to_le(data: &[u8]) -> Vec<u8> {
    let mut pub_key_bytes = vec!();
    match data.len() {
      33 => {
        let mut x_bytes = [0u8; SECRET_KEY_SIZE];
        x_bytes.copy_from_slice(&data[1..33]);
        x_bytes.reverse();
        pub_key_bytes = [&data[0..1], &x_bytes].concat();
        pub_key_bytes
      }
      64 | 1024 => {
        let mut x_bytes = [0u8; SECRET_KEY_SIZE];
        x_bytes.copy_from_slice(&data[0..32]);
        x_bytes.reverse();
        let mut y_bytes = [0u8; SECRET_KEY_SIZE];
        y_bytes.copy_from_slice(&data[32..64]);
        y_bytes.reverse();
        pub_key_bytes = [x_bytes, y_bytes].concat();
        pub_key_bytes
      }
      65 => {
        let mut x_bytes = [0u8; SECRET_KEY_SIZE];
        x_bytes.copy_from_slice(&data[1..33]);
        x_bytes.reverse();
        let mut y_bytes = [0u8; SECRET_KEY_SIZE];
        y_bytes.copy_from_slice(&data[33..65]);
        y_bytes.reverse();
        pub_key_bytes.extend_from_slice(&data[0..1]);
        pub_key_bytes.extend_from_slice(&x_bytes);
        pub_key_bytes.extend_from_slice(&y_bytes);
        // pub_key_bytes = [data[0..1], x_bytes, y_bytes].concat();
        pub_key_bytes
      }
      _ => data.to_vec()
    }
  }

  /// Creates a public key directly from a slice
  #[inline]
  pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
    if data.is_empty() { return Err(Error::InvalidPublicKey); }
    let mut buffer = [0u8; 1024];
    unsafe {
      let pk_in_le = Self::convert_pk_to_le(data);
      let res = PubkeyParse(pk_in_le.as_ptr(), pk_in_le.len() as i32, buffer.as_mut_ptr());
      if res == 0 {
        let pub_key = Self::parse_pk_from_le(&buffer);
        Ok(pub_key)
      } else {
        Err(Error::InvalidPublicKey)
      }
    }
  }

  #[inline]
  /// Serialize the key as a byte-encoded pair of values. In compressed form
  /// the y-coordinate is represented by only a single bit, as x determines
  /// it up to one bit.
  pub fn serialize(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
    let mut ret = vec![];

    if self.0[63] & 0x1 == 1 {
      ret = [&[0x03], &self.0[0..32]].concat();
    } else {
      ret = [&[0x02], &self.0[0..32]].concat();
    }

    convert_vec_to_array(ret)
  }

  /// Serialize the key as a byte-encoded pair of values, in uncompressed form
  pub fn serialize_uncompressed(&self) -> [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] {
    let mut ret = vec![];
    ret = [&[0x04], self.0.as_slice()].concat();
    convert_vec_to_array(ret)
  }

  #[inline]
  /// Negates the pk to the pk `self` in place
  /// Will return an error if the pk would be invalid.
  pub fn negate_assign(&mut self) {
    let mut buffer = [0u8; 1024];
    unsafe {
      let pk_in_le = Self::convert_pk_to_le(&self.0);
      let res = PubkeyNegate(pk_in_le.as_ptr(), buffer.as_mut_ptr());
      debug_assert_eq!(res, 0);
      let pk_in_be = Self::parse_pk_from_le(&buffer);
      self.0.copy_from_slice(&pk_in_be.0[0..64]);
    }
  }

  #[inline]
  /// Adds the pk corresponding to `other` to the pk `self` in place
  /// Will return an error if the resulting key would be invalid or
  /// if the tweak was not a 32-byte length slice.
  pub fn add_exp_assign(&mut self, other: &PublicKey) -> Result<(), Error> {
    let mut buffer = [0u8; 1024];
    unsafe {
      let pk_in_le = Self::convert_pk_to_le(&self.0);
      let other_pk_in_le = Self::convert_pk_to_le(&other.0);
      if PubkeyTweakAdd(pk_in_le.as_c_ptr(), other_pk_in_le.as_ptr(), buffer.as_mut_ptr()) == 0 {
        let pk_in_be = Self::parse_pk_from_le(&buffer);
        self.0.copy_from_slice(&pk_in_be.0[0..64]);
        Ok(())
      } else {
        Err(Error::InvalidTweak)
      }
    }
  }

  /// Adds a second key to this one, returning the sum. Returns an error if
  /// the result would be the point at infinity, i.e. we are adding this point
  /// to its own negation
  // todo: no a real combine
  pub fn combine(&self, other: &PublicKey) -> Result<PublicKey, Error> {
    let mut buffer = [0u8; 1024];
    if self.is_zero() {
      if other.is_zero() {
        return Ok(Self::zero());
      } else {
        return Ok(other.clone());
      }
    }

    if other.is_zero() {
      if self.is_zero() {
        return Ok(Self::zero());
      } else {
        return Ok(self.clone());
      }
    }
    unsafe {
      let pk_in_le = Self::convert_pk_to_le(&self.0);
      let other_pk_in_le = Self::convert_pk_to_le(&other.0);
      if PubkeyTweakAdd(pk_in_le.as_c_ptr(), other_pk_in_le.as_ptr(), buffer.as_mut_ptr()) == 0 {
        let pk_in_be = Self::parse_pk_from_le(&buffer);
        Ok(pk_in_be)
      } else {
        Ok(Self::zero())
      }
    }
  }

  #[inline]
  /// Muliplies the pk `self` in place by the scalar `other`
  /// Will return an error if the resulting key would be invalid or
  /// if the tweak was not a 32-byte length slice.
  pub fn mul_assign(&mut self, other: &SecretKey) -> Result<(), Error> {
    if other.len() != 32 {
      return Err(Error::InvalidTweak);
    }
    if other.0 == [0u8; SECRET_KEY_SIZE] || self.is_zero() {
      self.0 = [0u8; 64];
      return Ok(());
    }
    let mut buffer = [0u8; 1024];
    unsafe {
      let pk_in_le = Self::convert_pk_to_le(&self.0);
      let mut other_bytes = [0u8; SECRET_KEY_SIZE];
      other_bytes.copy_from_slice(&other.0);
      other_bytes.reverse();

      if PubkeyTweakMul(pk_in_le.as_c_ptr(), other_bytes.as_ptr(), buffer.as_mut_ptr()) == 0 {
        let pk_in_be = Self::parse_pk_from_le(&buffer);
        self.0.copy_from_slice(&pk_in_be.0[0..64]);
        Ok(())
      } else {
        Err(Error::InvalidTweak)
      }
    }
  }

  // /// Adds a second key to this one, returning the sum. Returns an error if
  // /// the result would be the point at infinity, i.e. we are adding this point
  // /// to its own negation
  // pub fn combine(&self, other: &PublicKey) -> Result<PublicKey, Error> {
  //   PublicKey::combine_keys(&[self, other])
  // }
  //
  // /// Adds the keys in the provided slice together, returning the sum. Returns
  // /// an error if the result would be the point at infinity, i.e. we are adding
  // /// a point to its own negation
  // pub fn combine_keys(keys: &[&PublicKey]) -> Result<PublicKey, Error> {
  //   use core::mem::transmute;
  //   use core::i32::MAX;
  //
  //   debug_assert!(keys.len() < MAX as usize);
  //   unsafe {
  //     let mut ret = [0u8; 64];
  //     let ptrs: &[*const c_uchar] =
  //       transmute::<&[&PublicKey], &[*const c_uchar]>(keys);
  //     if PubkeyCombine(
  //       ret.as_mut_ptr(),
  //       ptrs.as_c_ptr(),
  //       keys.len() as u32,
  //     ) == 1
  //     {
  //       Ok(PublicKey(ret))
  //     } else {
  //       Err(Error::InvalidPublicKey)
  //     }
  //   }
  // }
}

// impl CPtr for PublicKey {
//   type Target = u8;
//   fn as_c_ptr(&self) -> *const Self::Target {
//     self.as_ptr()
//   }
//
//   fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
//     self.as_mut_ptr()
//   }
// }


// /// Creates a new public key from a FFI public key
// impl From<ffi::PublicKey> for PublicKey {
//   #[inline]
//   fn from(pk: ffi::PublicKey) -> PublicKey {
//     PublicKey(pk)
//   }
// }
//
// impl ::serde::Serialize for PublicKey {
//   fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
//     if s.is_human_readable() {
//       s.collect_str(self)
//     } else {
//       s.serialize_bytes(&self.serialize())
//     }
//   }
// }
//
// impl<'de> ::serde::Deserialize<'de> for PublicKey {
//   fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
//     if d.is_human_readable() {
//       d.deserialize_str(super::serde_util::FromStrVisitor::new(
//         "an ASCII hex string representing a public key"
//       ))
//     } else {
//       d.deserialize_bytes(super::serde_util::BytesVisitor::new(
//         "a bytestring representing a public key",
//         PublicKey::from_slice,
//       ))
//     }
//   }
// }
//
// impl PartialOrd for PublicKey {
//   fn partial_cmp(&self, other: &PublicKey) -> Option<::core::cmp::Ordering> {
//     self.serialize().partial_cmp(&other.serialize())
//   }
// }
//
// impl Ord for PublicKey {
//   fn cmp(&self, other: &PublicKey) -> ::core::cmp::Ordering {
//     self.serialize().cmp(&other.serialize())
//   }
// }
//

#[cfg(test)]
mod test {
  use hex_literal::hex;
  use crate::{PublicKey, SecretKey};
  use crate::key::convert_vec_to_array;
  use super::is_sk_validation;

  #[test]
  fn test_is_sk_validation() {
    let zero = [0u8; 32];
    assert_eq!(false, is_sk_validation(&zero));
  }

  #[test]
  fn test_from_sk() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");
    let sk_one = SecretKey::from_slice(&one);
    let pk = PublicKey::from_secret_key(&sk_one.unwrap());
    assert_eq!("0301ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca", hex::encode(pk.serialize()));
  }

  #[test]
  fn test_parse_pubkey() {
    let compressed_pk = hex!("03053bbcaee4f23084e173fc2df3e50d2c2d7bccd5ce626b2158e324df1eb60125");
    let cpk = PublicKey::from_slice(&compressed_pk);
    assert!(cpk.is_ok());


    assert_eq!(hex!("03053bbcaee4f23084e173fc2df3e50d2c2d7bccd5ce626b2158e324df1eb60125"), cpk.unwrap().serialize());

    let even_compressed_pk = hex!("020523658a604e7383f7ae24c011b1f94973a294303f8d7adfde4bbac56e434344");
    let cpk = PublicKey::from_slice(&even_compressed_pk);

    assert_eq!(hex!("020523658a604e7383f7ae24c011b1f94973a294303f8d7adfde4bbac56e434344"), cpk.unwrap().serialize());
  }

  #[test]
  fn test_pubkey_add() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    let two = hex!("0000000000000000000000000000000000000000000000000000000000000002");
    let three = hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let sk_one = SecretKey::from_slice(&one).unwrap();
    let sk_two = SecretKey::from_slice(&two).unwrap();
    let sk_three = SecretKey::from_slice(&three).unwrap();
    let mut pub_key_one = PublicKey::from_secret_key(&sk_one);
    let mut pub_key_two = PublicKey::from_secret_key(&sk_two);


    assert_eq!(PublicKey::from_secret_key(&sk_three), pub_key_one.combine(&pub_key_two).unwrap());

    pub_key_one.add_exp_assign(&pub_key_two);
    assert_eq!(PublicKey::from_secret_key(&sk_three), pub_key_one);
  }


  #[test]
  fn test_pubkey_mul() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    let two = hex!("0000000000000000000000000000000000000000000000000000000000000002");
    let three = hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let sk_one = SecretKey::from_slice(&one).unwrap();
    let sk_three = SecretKey::from_slice(&three).unwrap();
    let mut pub_key_one = PublicKey::from_secret_key(&sk_one);
    pub_key_one.mul_assign(&sk_three);
    assert_eq!(PublicKey::from_secret_key(&sk_three), pub_key_one);
  }

  #[test]
  fn test_sk_add() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    let two = hex!("0000000000000000000000000000000000000000000000000000000000000002");
    let three = hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let mut sk_one = SecretKey::from_slice(&one).unwrap();
    let sk_two = SecretKey::from_slice(&two).unwrap();
    let sk_three = SecretKey::from_slice(&three).unwrap();
    sk_one.add_assign(&sk_two);
    assert_eq!(sk_three, sk_one );
  }

  #[test]
  fn test_sk_mul() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    let two = hex!("0000000000000000000000000000000000000000000000000000000000000002");
    let three = hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let mut sk_one = SecretKey::from_slice(&one).unwrap();
    let sk_two = SecretKey::from_slice(&two).unwrap();
    let sk_three = SecretKey::from_slice(&three).unwrap();
    sk_one.mul_assign(&sk_three);
    assert_eq!(sk_three, sk_one);
  }

  #[test]
  fn test_sk_negate() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    let negate_one = hex!("0800000000000011000000000000000000000000000000000000000000000000");
    let mut sk_one = SecretKey::from_slice(&one).unwrap();
    let mut sk_negate_one = SecretKey::from_slice(&negate_one).unwrap();
    sk_one.negate_assign();

    // let sk_three = SecretKey::from_slice(&three).unwrap();
    // sk_one.mul_assign(&sk_three.0);
    assert_eq!("", hex::encode(sk_one.0));
  }

  #[test]
  fn test_pk_negate() {
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    let two = hex!("0000000000000000000000000000000000000000000000000000000000000002");
    let three = hex!("0000000000000000000000000000000000000000000000000000000000000003");
    let mut sk_one = SecretKey::from_slice(&one).unwrap();
    let mut sk_two = SecretKey::from_slice(&two).unwrap();
    sk_one.negate_assign();

    // let sk_three = SecretKey::from_slice(&three).unwrap();
    // sk_one.mul_assign(&sk_three.0);
    assert_eq!(sk_two, sk_one);
  }

  #[test]
  fn test_bigint_mul() {
    let left = hex::decode("07fb56a3668cd6dcdaf91d986675a1f3cacd66af4eced9f3791ea739934a752e").unwrap();
    let right = hex::decode("03c16ceac5293e0bf8a29e5a628f567bf5cff88175f292a8e9c9ce07d3d8d489").unwrap();
    let mut left_key = SecretKey::from_slice(&left).unwrap();
    let right_key = SecretKey::from_slice(&right).unwrap();

    let mut left_mul_right = left_key.clone();
    left_mul_right.mul_assign(&right_key).unwrap();

    let mut left_point = PublicKey::from_secret_key(&left_mul_right);

    let mut right_point = PublicKey::from_secret_key(&left_key);
    right_point.mul_assign(&right_key);


    // let num_from_mod_n = hex::decode("07b97fbd845284402f5fec9c02a61c9fdde835f9605cd3d875f0a735a927035b").unwrap();
    // let sk_from_mod_n = SecretKey::from_slice(&num_from_mod_n).unwrap();
    // let mut point2 = PublicKey::from_secret_key(&sk_from_mod_n);
    assert_eq!(hex::encode(left_point.serialize_uncompressed()), hex::encode(right_point.serialize_uncompressed()));
  }

  #[test]
  fn test_from_scala() {
    let scala = hex::decode("053ce0e384325169d57e2e42afe9301dd95b830f75043c75394912284303d5d5").unwrap();
    let sk = SecretKey::from_slice(&scala);
    assert!(sk.is_ok());
  }

}
// #[cfg(test)]
// mod test {
//   use super::super::Error::{InvalidPublicKey, InvalidSecretKey};
//   use super::{PublicKey, SecretKey};
//   use super::super::constants;
//
//   use rand::{Error, ErrorKind, RngCore, thread_rng};
//   use std::iter;
//   use std::str::FromStr;
//
//   #[cfg(target_arch = "wasm32")]
//   use wasm_bindgen_test::wasm_bindgen_test as test;
//
//   macro_rules! hex {
//         ($hex:expr) => ({
//             let mut result = vec![0; $hex.len() / 2];
//             from_hex($hex, &mut result).expect("valid hex string");
//             result
//         });
//     }
//
//   #[test]
//   fn skey_from_slice() {
//     let sk = SecretKey::from_slice(&[1; 31]);
//     assert_eq!(sk, Err(InvalidSecretKey));
//
//     let sk = SecretKey::from_slice(&[1; 32]);
//     assert!(sk.is_ok());
//   }
//
//   #[test]
//   fn pubkey_from_slice() {
//     assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
//     assert_eq!(PublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));
//
//     let uncompressed = PublicKey::from_slice(&[4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188]);
//     assert!(uncompressed.is_ok());
//
//     let compressed = PublicKey::from_slice(&[3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41, 111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78]);
//     assert!(compressed.is_ok());
//   }
//
//   #[test]
//   fn keypair_slice_round_trip() {
//     let s = Secp256k1::new();
//
//     let (sk1, pk1) = s.generate_keypair(&mut thread_rng());
//     assert_eq!(SecretKey::from_slice(&sk1[..]), Ok(sk1));
//     assert_eq!(PublicKey::from_slice(&pk1.serialize()[..]), Ok(pk1));
//     assert_eq!(PublicKey::from_slice(&pk1.serialize_uncompressed()[..]), Ok(pk1));
//   }
//
//   #[test]
//   fn invalid_secret_key() {
//     // Zero
//     assert_eq!(SecretKey::from_slice(&[0; 32]), Err(InvalidSecretKey));
//     assert_eq!(
//       SecretKey::from_str(&format!("0000000000000000000000000000000000000000000000000000000000000000")),
//       Err(InvalidSecretKey)
//     );
//     // -1
//     assert_eq!(SecretKey::from_slice(&[0xff; 32]), Err(InvalidSecretKey));
//     // Top of range
//     assert!(SecretKey::from_slice(&[
//       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
//       0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
//       0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
//     ]).is_ok());
//     // One past top of range
//     assert!(SecretKey::from_slice(&[
//       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
//       0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
//       0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
//     ]).is_err());
//   }
//
//   #[test]
//   fn test_out_of_range() {
//     struct BadRng(u8);
//     impl RngCore for BadRng {
//       fn next_u32(&mut self) -> u32 { unimplemented!() }
//       fn next_u64(&mut self) -> u64 { unimplemented!() }
//       // This will set a secret key to a little over the
//       // group order, then decrement with repeated calls
//       // until it returns a valid key
//       fn fill_bytes(&mut self, data: &mut [u8]) {
//         let group_order: [u8; 32] = [
//           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
//           0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
//           0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41];
//         assert_eq!(data.len(), 32);
//         data.copy_from_slice(&group_order[..]);
//         data[31] = self.0;
//         self.0 -= 1;
//       }
//       fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
//         self.fill_bytes(dest);
//         Ok(())
//       }
//     }
//
//     let s = Secp256k1::new();
//     s.generate_keypair(&mut BadRng(0xff));
//   }
//
//   #[test]
//   fn test_pubkey_from_bad_slice() {
//     // Bad sizes
//     assert_eq!(
//       PublicKey::from_slice(&[0; constants::PUBLIC_KEY_SIZE - 1]),
//       Err(InvalidPublicKey)
//     );
//     assert_eq!(
//       PublicKey::from_slice(&[0; constants::PUBLIC_KEY_SIZE + 1]),
//       Err(InvalidPublicKey)
//     );
//     assert_eq!(
//       PublicKey::from_slice(&[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE - 1]),
//       Err(InvalidPublicKey)
//     );
//     assert_eq!(
//       PublicKey::from_slice(&[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 1]),
//       Err(InvalidPublicKey)
//     );
//
//     // Bad parse
//     assert_eq!(
//       PublicKey::from_slice(&[0xff; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
//       Err(InvalidPublicKey)
//     );
//     assert_eq!(
//       PublicKey::from_slice(&[0x55; constants::PUBLIC_KEY_SIZE]),
//       Err(InvalidPublicKey)
//     );
//     assert_eq!(
//       PublicKey::from_slice(&[]),
//       Err(InvalidPublicKey)
//     );
//   }
//
//   #[test]
//   fn test_seckey_from_bad_slice() {
//     // Bad sizes
//     assert_eq!(
//       SecretKey::from_slice(&[0; constants::SECRET_KEY_SIZE - 1]),
//       Err(InvalidSecretKey)
//     );
//     assert_eq!(
//       SecretKey::from_slice(&[0; constants::SECRET_KEY_SIZE + 1]),
//       Err(InvalidSecretKey)
//     );
//     // Bad parse
//     assert_eq!(
//       SecretKey::from_slice(&[0xff; constants::SECRET_KEY_SIZE]),
//       Err(InvalidSecretKey)
//     );
//     assert_eq!(
//       SecretKey::from_slice(&[0x00; constants::SECRET_KEY_SIZE]),
//       Err(InvalidSecretKey)
//     );
//     assert_eq!(
//       SecretKey::from_slice(&[]),
//       Err(InvalidSecretKey)
//     );
//   }
//
//   #[test]
//   fn test_debug_output() {
//     struct DumbRng(u32);
//     impl RngCore for DumbRng {
//       fn next_u32(&mut self) -> u32 {
//         self.0 = self.0.wrapping_add(1);
//         self.0
//       }
//       fn next_u64(&mut self) -> u64 {
//         self.next_u32() as u64
//       }
//       fn fill_bytes(&mut self, dest: &mut [u8]) {
//         impls::fill_bytes_via_next(self, dest);
//       }
//
//       fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
//         Err(Error::new(ErrorKind::Unavailable, "not implemented"))
//       }
//     }
//
//     let s = Secp256k1::new();
//     let (sk, _) = s.generate_keypair(&mut DumbRng(0));
//
//     assert_eq!(&format!("{:?}", sk),
//                "SecretKey(0100000000000000020000000000000003000000000000000400000000000000)");
//   }
//
//   #[test]
//   fn test_display_output() {
//     static SK_BYTES: [u8; 32] = [
//       0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
//       0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//       0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
//       0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
//     ];
//
//     let s = Secp256k1::signing_only();
//     let sk = SecretKey::from_slice(&SK_BYTES).expect("sk");
//
//     // In fuzzing mode secret->public key derivation is different, so
//     // hard-code the epected result.
//     #[cfg(not(fuzzing))]
//       let pk = PublicKey::from_secret_key(&s, &sk);
//     #[cfg(fuzzing)]
//       let pk = PublicKey::from_slice(&[0x02, 0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f, 0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d, 0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54, 0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66]).expect("pk");
//
//     assert_eq!(
//       sk.to_string(),
//       "01010101010101010001020304050607ffff0000ffff00006363636363636363"
//     );
//     assert_eq!(
//       SecretKey::from_str("01010101010101010001020304050607ffff0000ffff00006363636363636363").unwrap(),
//       sk
//     );
//     assert_eq!(
//       pk.to_string(),
//       "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
//     );
//     assert_eq!(
//       PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166").unwrap(),
//       pk
//     );
//     assert_eq!(
//       PublicKey::from_str("04\
//                 18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
//                 84B84DB303A340CD7D6823EE88174747D12A67D2F8F2F9BA40846EE5EE7A44F6"
//       ).unwrap(),
//       pk
//     );
//
//     assert!(SecretKey::from_str("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").is_err());
//     assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff0000636363636363636363").is_err());
//     assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff0000636363636363636").is_err());
//     assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff000063636363636363").is_err());
//     assert!(SecretKey::from_str("01010101010101010001020304050607ffff0000ffff000063636363636363xx").is_err());
//     assert!(PublicKey::from_str("0300000000000000000000000000000000000000000000000000000000000000000").is_err());
//     assert!(PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16601").is_err());
//     assert!(PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16").is_err());
//     assert!(PublicKey::from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1").is_err());
//     assert!(PublicKey::from_str("xx0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1").is_err());
//
//     let long_str: String = iter::repeat('a').take(1024 * 1024).collect();
//     assert!(SecretKey::from_str(&long_str).is_err());
//     assert!(PublicKey::from_str(&long_str).is_err());
//   }
//
//   #[test]
//   // In fuzzing mode the Y coordinate is expected to match the X, so this
//   // test uses invalid public keys.
//   #[cfg(not(fuzzing))]
//   fn test_pubkey_serialize() {
//     struct DumbRng(u32);
//     impl RngCore for DumbRng {
//       fn next_u32(&mut self) -> u32 {
//         self.0 = self.0.wrapping_add(1);
//         self.0
//       }
//       fn next_u64(&mut self) -> u64 {
//         self.next_u32() as u64
//       }
//       fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
//         Err(Error::new(ErrorKind::Unavailable, "not implemented"))
//       }
//
//       fn fill_bytes(&mut self, dest: &mut [u8]) {
//         impls::fill_bytes_via_next(self, dest);
//       }
//     }
//
//     let s = Secp256k1::new();
//     let (_, pk1) = s.generate_keypair(&mut DumbRng(0));
//     assert_eq!(&pk1.serialize_uncompressed()[..],
//                &[4, 124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9, 181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229, 185, 28, 165, 110, 27, 3, 162, 126, 238, 167, 157, 242, 221, 76, 251, 237, 34, 231, 72, 39, 245, 3, 191, 64, 111, 170, 117, 103, 82, 28, 102, 163][..]);
//     assert_eq!(&pk1.serialize()[..],
//                &[3, 124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9, 181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229][..]);
//   }
//
//   #[test]
//   fn test_addition() {
//     let s = Secp256k1::new();
//
//     let (mut sk1, mut pk1) = s.generate_keypair(&mut thread_rng());
//     let (mut sk2, mut pk2) = s.generate_keypair(&mut thread_rng());
//
//     assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);
//     assert!(sk1.add_assign(&sk2[..]).is_ok());
//     assert!(pk1.add_exp_assign(&s, &sk2[..]).is_ok());
//     assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);
//
//     assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
//     assert!(sk2.add_assign(&sk1[..]).is_ok());
//     assert!(pk2.add_exp_assign(&s, &sk1[..]).is_ok());
//     assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
//   }
//
//   #[test]
//   fn test_multiplication() {
//     let s = Secp256k1::new();
//
//     let (mut sk1, mut pk1) = s.generate_keypair(&mut thread_rng());
//     let (mut sk2, mut pk2) = s.generate_keypair(&mut thread_rng());
//
//     assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);
//     assert!(sk1.mul_assign(&sk2[..]).is_ok());
//     assert!(pk1.mul_assign(&s, &sk2[..]).is_ok());
//     assert_eq!(PublicKey::from_secret_key(&s, &sk1), pk1);
//
//     assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
//     assert!(sk2.mul_assign(&sk1[..]).is_ok());
//     assert!(pk2.mul_assign(&s, &sk1[..]).is_ok());
//     assert_eq!(PublicKey::from_secret_key(&s, &sk2), pk2);
//   }
//
//   #[test]
//   fn test_negation() {
//     let s = Secp256k1::new();
//
//     let (mut sk, mut pk) = s.generate_keypair(&mut thread_rng());
//
//     let original_sk = sk;
//     let original_pk = pk;
//
//     assert_eq!(PublicKey::from_secret_key(&s, &sk), pk);
//     sk.negate_assign();
//     pk.negate_assign(&s);
//     assert_ne!(original_sk, sk);
//     assert_ne!(original_pk, pk);
//     sk.negate_assign();
//     pk.negate_assign(&s);
//     assert_eq!(original_sk, sk);
//     assert_eq!(original_pk, pk);
//     assert_eq!(PublicKey::from_secret_key(&s, &sk), pk);
//   }
//
//   #[test]
//   fn pubkey_hash() {
//     use std::collections::hash_map::DefaultHasher;
//     use std::hash::{Hash, Hasher};
//     use std::collections::HashSet;
//
//     fn hash<T: Hash>(t: &T) -> u64 {
//       let mut s = DefaultHasher::new();
//       t.hash(&mut s);
//       s.finish()
//     }
//
//     let s = Secp256k1::new();
//     let mut set = HashSet::new();
//     const COUNT: usize = 1024;
//     for _ in 0..COUNT {
//       let (_, pk) = s.generate_keypair(&mut thread_rng());
//       let hash = hash(&pk);
//       assert!(!set.contains(&hash));
//       set.insert(hash);
//     };
//     assert_eq!(set.len(), COUNT);
//   }
//
//   #[cfg_attr(not(fuzzing), test)]
//   fn pubkey_combine() {
//     let compressed1 = PublicKey::from_slice(
//       &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
//     ).unwrap();
//     let compressed2 = PublicKey::from_slice(
//       &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
//     ).unwrap();
//     let exp_sum = PublicKey::from_slice(
//       &hex!("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07"),
//     ).unwrap();
//
//     let sum1 = compressed1.combine(&compressed2);
//     assert!(sum1.is_ok());
//     let sum2 = compressed2.combine(&compressed1);
//     assert!(sum2.is_ok());
//     assert_eq!(sum1, sum2);
//     assert_eq!(sum1.unwrap(), exp_sum);
//   }
//
//   #[cfg_attr(not(fuzzing), test)]
//   fn pubkey_combine_keys() {
//     let compressed1 = PublicKey::from_slice(
//       &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
//     ).unwrap();
//     let compressed2 = PublicKey::from_slice(
//       &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
//     ).unwrap();
//     let compressed3 = PublicKey::from_slice(
//       &hex!("03e74897d8644eb3e5b391ca2ab257aec2080f4d1a95cad57e454e47f021168eb0")
//     ).unwrap();
//     let exp_sum = PublicKey::from_slice(
//       &hex!("0252d73a47f66cf341e5651542f0348f452b7c793af62a6d8bff75ade703a451ad"),
//     ).unwrap();
//
//     let sum1 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
//     assert!(sum1.is_ok());
//     let sum2 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
//     assert!(sum2.is_ok());
//     assert_eq!(sum1, sum2);
//     assert_eq!(sum1.unwrap(), exp_sum);
//   }
//
//   #[test]
//   fn create_pubkey_combine() {
//     let s = Secp256k1::new();
//
//     let (mut sk1, pk1) = s.generate_keypair(&mut thread_rng());
//     let (sk2, pk2) = s.generate_keypair(&mut thread_rng());
//
//     let sum1 = pk1.combine(&pk2);
//     assert!(sum1.is_ok());
//     let sum2 = pk2.combine(&pk1);
//     assert!(sum2.is_ok());
//     assert_eq!(sum1, sum2);
//
//     assert!(sk1.add_assign(&sk2.as_ref()[..]).is_ok());
//     let sksum = PublicKey::from_secret_key(&s, &sk1);
//     assert_eq!(Ok(sksum), sum1);
//   }
//
//   #[test]
//   fn pubkey_equal() {
//     let pk1 = PublicKey::from_slice(
//       &hex!("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"),
//     ).unwrap();
//     let pk2 = pk1;
//     let pk3 = PublicKey::from_slice(
//       &hex!("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"),
//     ).unwrap();
//
//     assert!(pk1 == pk2);
//     assert!(pk1 <= pk2);
//     assert!(pk2 <= pk1);
//     assert!(!(pk2 < pk1));
//     assert!(!(pk1 < pk2));
//
//     assert!(pk3 > pk1);
//     assert!(pk1 < pk3);
//     assert!(pk3 >= pk1);
//     assert!(pk1 <= pk3);
//   }
//
//   #[cfg(feature = "serde")]
//   #[test]
//   fn test_serde() {
//     use serde_test::{Configure, Token, assert_tokens};
//     static SK_BYTES: [u8; 32] = [
//       1, 1, 1, 1, 1, 1, 1, 1,
//       0, 1, 2, 3, 4, 5, 6, 7,
//       0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
//       99, 99, 99, 99, 99, 99, 99, 99
//     ];
//     static SK_STR: &'static str = "\
//             01010101010101010001020304050607ffff0000ffff00006363636363636363\
//         ";
//     static PK_BYTES: [u8; 33] = [
//       0x02,
//       0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
//       0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
//       0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
//       0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66,
//     ];
//     static PK_STR: &'static str = "\
//             0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
//         ";
//
//     let s = Secp256k1::new();
//     let sk = SecretKey::from_slice(&SK_BYTES).unwrap();
//
//     // In fuzzing mode secret->public key derivation is different, so
//     // hard-code the epected result.
//     #[cfg(not(fuzzing))]
//       let pk = PublicKey::from_secret_key(&s, &sk);
//     #[cfg(fuzzing)]
//       let pk = PublicKey::from_slice(&PK_BYTES).expect("pk");
//
//     assert_tokens(&sk.compact(), &[Token::BorrowedBytes(&SK_BYTES[..])]);
//     assert_tokens(&sk.compact(), &[Token::Bytes(&SK_BYTES)]);
//     assert_tokens(&sk.compact(), &[Token::ByteBuf(&SK_BYTES)]);
//
//     assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
//     assert_tokens(&sk.readable(), &[Token::Str(SK_STR)]);
//     assert_tokens(&sk.readable(), &[Token::String(SK_STR)]);
//
//     assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
//     assert_tokens(&pk.compact(), &[Token::Bytes(&PK_BYTES)]);
//     assert_tokens(&pk.compact(), &[Token::ByteBuf(&PK_BYTES)]);
//
//     assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
//     assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
//     assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);
//   }
// }
