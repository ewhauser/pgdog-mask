//! Built-in proxy masks.
use aes::{Aes128, Aes192, Aes256};
use fpe::ff1::{FF1, FlexibleNumeralString};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{Datum, MaskError, Options, ProxyMask, Registry};
use crate::mask::{TypeFamily, TypeFamily::Text};

pub(super) fn register(registry: &mut Registry) {
    registry.register("hmac_sha256", HmacSha256::new);
    registry.register("ff1", Ff1::new);
}

fn text(value: Datum) -> Result<String, MaskError> {
    match value {
        Datum::Text(text) => Ok(text),
        other => Err(MaskError::new(format!(
            "expected text, got {}",
            other.data_type()
        ))),
    }
}

/// `hmac_sha256`: the hex HMAC-SHA256 of the value, with a secret key. The same
/// value always masks to the same digest, so masked columns can still be
/// joined, grouped and counted by clients, but not reversed without the key.
///
/// Options: `key_env` or `key_file`; `length`, to keep only the first
/// `length` hex digits.
pub struct HmacSha256 {
    key: Vec<u8>,
    length: Option<usize>,
}

impl HmacSha256 {
    pub fn new(options: &Options) -> Result<Self, MaskError> {
        let key = options.secret()?.into_bytes();
        if key.is_empty() {
            return Err(MaskError::new("hmac_sha256 key is empty"));
        }
        let length = match options.integer("length")? {
            None => None,
            Some(length @ 1..=64) => Some(length as usize),
            Some(_) => return Err(MaskError::new("length must be between 1 and 64")),
        };
        Ok(Self { key, length })
    }
}

impl ProxyMask for HmacSha256 {
    fn accepts(&self, data_type: &str) -> bool {
        TypeFamily::of(data_type) == Text
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        let value = text(value)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|err| MaskError::new(err.to_string()))?;
        mac.update(value.as_bytes());
        let mut digest = hex::encode(mac.finalize().into_bytes());
        if let Some(length) = self.length {
            digest.truncate(length);
        }
        Ok(Datum::Text(digest))
    }
}

enum Cipher {
    Aes128(FF1<Aes128>),
    Aes192(FF1<Aes192>),
    Aes256(FF1<Aes256>),
}

/// `ff1`: format-preserving encryption (NIST SP 800-38G FF1 with AES). Characters
/// of the alphabet are encrypted in place and everything else is kept, so
/// `123-45-6789` masks to another `NNN-NN-NNNN`. Values with too few alphabet
/// characters for FF1 (fewer than 6 digits, for example) are replaced with `*`.
///
/// Options: `key_env` or `key_file`, holding a hex AES key of 16, 24 or 32 bytes;
/// `alphabet`: `digits` (default), `alphanumeric`, or the characters themselves;
/// `tweak`, an optional string mixed into the encryption.
pub struct Ff1 {
    cipher: Cipher,
    alphabet: Vec<char>,
    tweak: Vec<u8>,
}

impl Ff1 {
    pub fn new(options: &Options) -> Result<Self, MaskError> {
        let key = hex::decode(options.secret()?.trim())
            .map_err(|_| MaskError::new("ff1 key must be hex"))?;
        let alphabet: Vec<char> = match options.string("alphabet")?.unwrap_or("digits") {
            "digits" => ('0'..='9').collect(),
            "alphanumeric" => ('0'..='9').chain('A'..='Z').chain('a'..='z').collect(),
            custom => custom.chars().collect(),
        };
        let mut unique = alphabet.clone();
        unique.sort_unstable();
        unique.dedup();
        if alphabet.len() < 2 || unique.len() != alphabet.len() {
            return Err(MaskError::new(
                "ff1 alphabet needs at least 2 distinct characters",
            ));
        }
        let radix = alphabet.len() as u32;
        let invalid = |err: fpe::ff1::InvalidRadix| MaskError::new(err.to_string());
        let cipher = match key.len() {
            16 => Cipher::Aes128(FF1::new(&key, radix).map_err(invalid)?),
            24 => Cipher::Aes192(FF1::new(&key, radix).map_err(invalid)?),
            32 => Cipher::Aes256(FF1::new(&key, radix).map_err(invalid)?),
            _ => return Err(MaskError::new("ff1 key must be 16, 24 or 32 bytes")),
        };
        Ok(Self {
            cipher,
            alphabet,
            tweak: options.string("tweak")?.unwrap_or("").as_bytes().to_vec(),
        })
    }

    fn encrypt(&self, numerals: Vec<u16>) -> Option<Vec<u16>> {
        let numerals = FlexibleNumeralString::from(numerals);
        let encrypted = match &self.cipher {
            Cipher::Aes128(ff1) => ff1.encrypt(&self.tweak, &numerals),
            Cipher::Aes192(ff1) => ff1.encrypt(&self.tweak, &numerals),
            Cipher::Aes256(ff1) => ff1.encrypt(&self.tweak, &numerals),
        };
        encrypted.ok().map(Vec::from)
    }
}

impl ProxyMask for Ff1 {
    fn accepts(&self, data_type: &str) -> bool {
        TypeFamily::of(data_type) == Text
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        let value = text(value)?;
        let numerals: Vec<u16> = value
            .chars()
            .filter_map(|c| self.alphabet.iter().position(|a| *a == c))
            .map(|index| index as u16)
            .collect();

        // Too short for FF1: hide the alphabet characters.
        let Some(encrypted) = self.encrypt(numerals) else {
            return Ok(Datum::Text(
                value
                    .chars()
                    .map(|c| if self.alphabet.contains(&c) { '*' } else { c })
                    .collect(),
            ));
        };

        let mut encrypted = encrypted.into_iter();
        let masked = value
            .chars()
            .map(|c| match self.alphabet.contains(&c) {
                true => encrypted
                    .next()
                    .map(|index| self.alphabet[index as usize])
                    .unwrap_or('*'),
                false => c,
            })
            .collect();
        Ok(Datum::Text(masked))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY_ENV: &str = "PGDOG_MASK_BUILTIN_TEST_KEY";

    fn options(table: toml::Table) -> Options {
        // SAFETY: tests in this module only set this variable, always to the same value.
        unsafe { std::env::set_var(KEY_ENV, "2b7e151628aed2a6abf7158809cf4f3c") };
        let mut table = table;
        table.insert("key_env".into(), KEY_ENV.into());
        Options::new(table)
    }

    #[test]
    fn test_hmac() {
        let mask = HmacSha256::new(&options(toml::Table::new())).unwrap();
        let a = mask.mask(Datum::Text("123-45-6789".into())).unwrap();
        let b = mask.mask(Datum::Text("123-45-6789".into())).unwrap();
        let c = mask.mask(Datum::Text("123-45-6780".into())).unwrap();
        assert_eq!(a, b, "deterministic");
        assert_ne!(a, c);
        let Datum::Text(digest) = a else { panic!() };
        assert_eq!(digest.len(), 64);

        let short = HmacSha256::new(&options(toml::toml! { length = 12 })).unwrap();
        let Datum::Text(digest) = short.mask(Datum::Text("x".into())).unwrap() else {
            panic!()
        };
        assert_eq!(digest.len(), 12);
        assert!(mask.mask(Datum::Integer(1)).is_err());
        assert!(mask.accepts("character varying"));
        assert!(!mask.accepts("bigint"));
    }

    #[test]
    fn test_ff1() {
        let mask = Ff1::new(&options(toml::Table::new())).unwrap();
        let Datum::Text(masked) = mask.mask(Datum::Text("123-45-6789".into())).unwrap() else {
            panic!()
        };
        assert_ne!(masked, "123-45-6789");
        assert_eq!(masked.len(), 11);
        assert_eq!(&masked[3..4], "-");
        assert_eq!(&masked[6..7], "-");
        assert!(
            masked
                .chars()
                .filter(|c| *c != '-')
                .all(|c| c.is_ascii_digit())
        );
        // Deterministic.
        assert_eq!(
            mask.mask(Datum::Text("123-45-6789".into())).unwrap(),
            Datum::Text(masked)
        );
        // Too short for FF1.
        assert_eq!(
            mask.mask(Datum::Text("12-3".into())).unwrap(),
            Datum::Text("**-*".into())
        );

        let tweaked = Ff1::new(&options(toml::toml! { tweak = "other" })).unwrap();
        assert_ne!(
            tweaked.mask(Datum::Text("123-45-6789".into())).unwrap(),
            mask.mask(Datum::Text("123-45-6789".into())).unwrap()
        );
        assert!(Ff1::new(&options(toml::toml! { alphabet = "aa" })).is_err());
    }
}
