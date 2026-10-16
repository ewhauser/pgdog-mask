//! Proxy masks: masks computed in code, by the plugin, on the rows Postgres
//! returns.
//!
//! SQL masks are expressions the rewrite puts in the statement, so Postgres
//! computes them. Proxy masks are for values SQL can't or shouldn't compute: a
//! keyed hash whose key must never appear in statement text, format-preserving
//! encryption, tokens from a vault, or anything else written in Rust.
//!
//! A proxy mask only applies where a masked column is a plain output of the
//! top-level `SELECT`. Every other reference to the column, in `WHERE`, joins,
//! `ORDER BY`, subqueries or functions, gets the policy's SQL `fallback` mask,
//! so filtering, ordering and aggregates never run on raw values.
//!
//! # Writing a mask
//!
//! Implement [`ProxyMask`], register a factory for it in a [`Registry`], and
//! build a plugin with [`crate::masking_plugin!`]:
//!
//! ```
//! use pgdog_mask::proxy::{Datum, MaskError, Options, ProxyMask, Registry};
//!
//! /// Adds a fixed offset to integers.
//! struct Offset(i64);
//!
//! impl ProxyMask for Offset {
//!     fn accepts(&self, data_type: &str) -> bool {
//!         data_type == "bigint"
//!     }
//!
//!     fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
//!         match value {
//!             Datum::Bigint(n) => Ok(Datum::Bigint(n + self.0)),
//!             other => Err(MaskError::new(format!("not a bigint: {other:?}"))),
//!         }
//!     }
//! }
//!
//! fn register(registry: &mut Registry) {
//!     registry.register("acme.offset", |options: &Options| {
//!         Ok(Offset(options.integer("offset")?.unwrap_or(1000)))
//!     });
//! }
//! # let mut registry = Registry::default();
//! # register(&mut registry);
//! ```
//!
//! The policy then names it:
//!
//! ```toml
//! [[policies]]
//! name = "balance"
//! data_type = "bigint"
//! mask = "proxy"
//! proxy = "acme.offset"
//! options = { offset = 5000 }
//! fallback = "null"
//! ```
use std::collections::HashMap;
use std::sync::Arc;

pub use pgdog_plugin::MaskError;
pub use pgdog_plugin::types::{DataType, Datum, Format};

mod builtin;
#[cfg(feature = "test-masks")]
pub(crate) mod test_masks;

/// A mask computed in code.
///
/// Masks are shared by every client and called from many threads at once.
pub trait ProxyMask: Send + Sync {
    /// Can this mask apply to a column of this type? `data_type` is the
    /// policy's type, as `information_schema.columns.data_type` spells it
    /// (`text`, `character varying`, `bigint`, ...). Checked when the
    /// configuration loads.
    fn accepts(&self, data_type: &str) -> bool;

    /// The mask may block, e.g. on a network call. PgDog then runs it on a
    /// thread pool for blocking work instead of its async workers.
    fn blocking(&self) -> bool {
        false
    }

    /// Mask one value. It must return a value of the same type, or NULL.
    fn mask(&self, value: Datum) -> Result<Datum, MaskError>;

    /// Mask a batch of values from one column, in row order. NULLs are
    /// [`Datum::Null`]. Override this to batch remote calls; by default, NULLs
    /// stay NULL and every other value goes through [`ProxyMask::mask`].
    fn mask_batch(&self, values: Vec<Datum>) -> Result<Vec<Datum>, MaskError> {
        values
            .into_iter()
            .map(|value| match value {
                Datum::Null => Ok(Datum::Null),
                value => self.mask(value),
            })
            .collect()
    }
}

/// The `options` of a policy or rule using a proxy mask.
#[derive(Debug, Clone, Default)]
pub struct Options(toml::Table);

impl Options {
    pub fn new(table: toml::Table) -> Self {
        Self(table)
    }

    /// A string option.
    pub fn string(&self, name: &str) -> Result<Option<&str>, MaskError> {
        match self.0.get(name) {
            None => Ok(None),
            Some(toml::Value::String(value)) => Ok(Some(value)),
            Some(_) => Err(MaskError::new(format!(
                "option \"{name}\" must be a string"
            ))),
        }
    }

    /// An integer option.
    pub fn integer(&self, name: &str) -> Result<Option<i64>, MaskError> {
        match self.0.get(name) {
            None => Ok(None),
            Some(toml::Value::Integer(value)) => Ok(Some(*value)),
            Some(_) => Err(MaskError::new(format!(
                "option \"{name}\" must be an integer"
            ))),
        }
    }

    /// A secret, from the environment variable named by `key_env` or the file
    /// named by `key_file` (trailing whitespace removed). Secrets never appear
    /// in the configuration file.
    pub fn secret(&self) -> Result<String, MaskError> {
        match (self.string("key_env")?, self.string("key_file")?) {
            (Some(var), None) => std::env::var(var)
                .map_err(|_| MaskError::new(format!("environment variable \"{var}\" is not set"))),
            (None, Some(path)) => std::fs::read_to_string(path)
                .map(|key| key.trim_end().to_owned())
                .map_err(|err| MaskError::new(format!("failed to read \"{path}\": {err}"))),
            (Some(_), Some(_)) => Err(MaskError::new("set key_env or key_file, not both")),
            (None, None) => Err(MaskError::new("the key needs key_env or key_file")),
        }
    }
}

type Factory = dyn Fn(&Options) -> Result<Arc<dyn ProxyMask>, MaskError> + Send + Sync;

/// Proxy masks by name. Policies name a mask, and its factory builds an
/// instance from the policy's options when the configuration loads.
#[derive(Clone)]
pub struct Registry {
    factories: HashMap<String, Arc<Factory>>,
}

impl Default for Registry {
    /// The built-in masks: `hmac_sha256` and `ff1`.
    fn default() -> Self {
        let mut registry = Self {
            factories: HashMap::new(),
        };
        builtin::register(&mut registry);
        registry
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<_> = self.factories.keys().collect();
        names.sort();
        f.debug_tuple("Registry").field(&names).finish()
    }
}

impl Registry {
    /// Register a mask. A later registration with the same name replaces an earlier one.
    pub fn register<M, F>(&mut self, name: &str, factory: F)
    where
        M: ProxyMask + 'static,
        F: Fn(&Options) -> Result<M, MaskError> + Send + Sync + 'static,
    {
        self.factories.insert(
            name.to_owned(),
            Arc::new(move |options: &Options| {
                factory(options).map(|mask| Arc::new(mask) as Arc<dyn ProxyMask>)
            }),
        );
    }

    /// Build a mask for a column of `data_type`.
    pub fn create(
        &self,
        name: &str,
        options: &Options,
        data_type: &str,
    ) -> Result<Arc<dyn ProxyMask>, MaskError> {
        let factory = self
            .factories
            .get(name)
            .ok_or_else(|| MaskError::new(format!("unknown proxy mask \"{name}\"")))?;
        let mask = factory(options)?;
        if !mask.accepts(data_type) {
            return Err(MaskError::new(format!(
                "proxy mask \"{name}\" doesn't support data_type \"{data_type}\""
            )));
        }
        Ok(mask)
    }
}

/// Decode a value of a column of type `type_oid`.
pub(crate) fn decode(
    value: Option<&[u8]>,
    type_oid: u32,
    format: Format,
) -> Result<Datum, MaskError> {
    let Some(value) = value else {
        return Ok(Datum::Null);
    };
    Datum::new(value, data_type(type_oid), format, false)
        .map_err(|err| MaskError::new(format!("failed to decode a value: {err}")))
}

/// Encode a masked value. It must have the column's type.
pub(crate) fn encode(
    value: &Datum,
    type_oid: u32,
    format: Format,
) -> Result<Option<Vec<u8>>, MaskError> {
    if value.is_null() {
        return Ok(None);
    }
    let expected = data_type(type_oid);
    if value.data_type() != expected && !matches!(value, Datum::Unknown(_)) {
        return Err(MaskError::new(format!(
            "mask returned {} for a column of type {expected}",
            value.data_type()
        )));
    }
    value
        .encode(format)
        .map(|bytes| Some(bytes.to_vec()))
        .map_err(|err| MaskError::new(format!("failed to encode a value: {err}")))
}

/// Type of values of a column. Types with the same representation as text
/// decode as text.
fn data_type(type_oid: u32) -> DataType {
    match type_oid {
        // bpchar, name, citext-like domains report their base type.
        1042 | 19 => DataType::Text,
        oid => DataType::from_oid(oid as i32),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct Reverse;

    impl ProxyMask for Reverse {
        fn accepts(&self, data_type: &str) -> bool {
            data_type == "text"
        }

        fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
            match value {
                Datum::Text(text) => Ok(Datum::Text(text.chars().rev().collect())),
                _ => Err(MaskError::new("not text")),
            }
        }
    }

    #[test]
    fn test_registry() {
        let mut registry = Registry::default();
        registry.register("test.reverse", |_: &Options| Ok(Reverse));

        let mask = registry
            .create("test.reverse", &Options::default(), "text")
            .unwrap();
        assert_eq!(
            mask.mask_batch(vec![Datum::Text("abc".into()), Datum::Null])
                .unwrap(),
            [Datum::Text("cba".into()), Datum::Null]
        );

        assert!(
            registry
                .create("test.reverse", &Options::default(), "bigint")
                .is_err()
        );
        assert!(
            registry
                .create("missing", &Options::default(), "text")
                .is_err()
        );
    }

    #[test]
    fn test_codec() {
        for format in [Format::Text, Format::Binary] {
            let encoded = encode(&Datum::Integer(42), 23, format).unwrap().unwrap();
            assert_eq!(
                decode(Some(&encoded), 23, format).unwrap(),
                Datum::Integer(42)
            );
        }
        assert_eq!(decode(None, 23, Format::Text).unwrap(), Datum::Null);
        assert_eq!(encode(&Datum::Null, 23, Format::Text).unwrap(), None);
        // Wrong type.
        assert!(encode(&Datum::Text("x".into()), 23, Format::Text).is_err());
        // bpchar is text.
        assert_eq!(
            decode(Some(b"ab"), 1042, Format::Binary).unwrap(),
            Datum::Text("ab".into())
        );
    }

    #[test]
    fn test_secret() {
        let options = Options::new(toml::toml! { key_env = "PGDOG_MASK_TEST_SECRET_UNSET" });
        assert!(options.secret().is_err());
        assert!(Options::default().secret().is_err());
    }
}
