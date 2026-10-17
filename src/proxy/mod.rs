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
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use pgdog_plugin::{MaskColumn, MaskOutput};

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

    /// Mask one value of a text column, appending the masked text to `out`,
    /// which is empty. Optional, and faster than [`ProxyMask::mask`]: values
    /// aren't copied into [`Datum`]s, and `out` is reused across a batch.
    ///
    /// Return `None`, the default, to mask text columns with
    /// [`ProxyMask::mask_batch`] instead. A mask returning `Some` must return
    /// it for every value, with the text [`ProxyMask::mask`] returns. NULLs
    /// stay NULL and aren't passed in.
    fn mask_text(&self, value: &str, out: &mut String) -> Option<Result<(), MaskError>> {
        let _ = (value, out);
        None
    }

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

/// Mask a column of text values with [`ProxyMask::mask_text`]. Returns
/// false, with nothing written, if the mask doesn't implement it or every
/// value is NULL: the column then goes through [`ProxyMask::mask_batch`].
pub(crate) fn mask_text_column(
    mask: &dyn ProxyMask,
    column: &MaskColumn<'_>,
    out: &mut MaskOutput,
) -> Result<bool, MaskError> {
    if data_type(column.type_oid) != DataType::Text {
        return Ok(false);
    }
    let mut masked = String::new();
    // NULLs before the first value, written once the mask has taken it.
    let mut nulls = 0;
    let mut started = false;
    for value in column.values() {
        let Some(value) = value else {
            match started {
                true => out.push(None),
                false => nulls += 1,
            }
            continue;
        };
        let value = std::str::from_utf8(value)
            .map_err(|err| MaskError::new(format!("failed to decode a value: {err}")))?;
        masked.clear();
        match mask.mask_text(value, &mut masked) {
            Some(result) => result?,
            None if !started => return Ok(false),
            None => {
                return Err(MaskError::new(
                    "mask_text returned None after masking other values",
                ));
            }
        }
        if !started {
            (0..nulls).for_each(|_| out.push(None));
            started = true;
        }
        out.push(Some(masked.as_bytes()));
    }
    Ok(started)
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
) -> Result<Option<Cow<'_, [u8]>>, MaskError> {
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
    match value {
        // Text is its own encoding, in both formats.
        Datum::Text(text) => Ok(Some(Cow::Borrowed(text.as_bytes()))),
        value => value
            .encode(format)
            .map(|bytes| Some(Cow::Owned(bytes.into())))
            .map_err(|err| MaskError::new(format!("failed to encode a value: {err}"))),
    }
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

    /// Reverse, with the text fast path.
    struct FastReverse;

    impl ProxyMask for FastReverse {
        fn accepts(&self, _data_type: &str) -> bool {
            true
        }

        fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
            Reverse.mask(value)
        }

        fn mask_text(&self, value: &str, out: &mut String) -> Option<Result<(), MaskError>> {
            out.extend(value.chars().rev());
            Some(Ok(()))
        }
    }

    #[test]
    fn test_mask_text_column() {
        use pgdog_plugin::{ColumnMask, MaskId, Value};

        let column_of = |type_oid, values| {
            MaskColumn::new(
                &ColumnMask::new(0, MaskId(0), type_oid),
                Format::Text,
                values,
            )
        };
        let masked = |mask: &dyn ProxyMask, column: &MaskColumn<'_>| {
            let mut out = MaskOutput::default();
            let fast = mask_text_column(mask, column, &mut out).unwrap();
            (fast, format!("{out:?}"))
        };
        let values = [
            Value::new(None),
            Value::new(Some(b"abc")),
            Value::new(None),
            Value::new(Some(b"")),
            Value::new(Some("d\u{e9}f".as_bytes())),
        ];

        // Same output as masking through mask_batch.
        let text = column_of(25, &values);
        let mut expected = MaskOutput::default();
        let decoded = text
            .values()
            .map(|value| decode(value, 25, Format::Text).unwrap());
        for value in FastReverse.mask_batch(decoded.collect()).unwrap() {
            expected.push(encode(&value, 25, Format::Text).unwrap().as_deref());
        }
        assert_eq!(masked(&FastReverse, &text), (true, format!("{expected:?}")));
        assert_eq!(
            masked(&FastReverse, &column_of(1043, &values)),
            masked(&FastReverse, &text)
        );

        // Falls back to mask_batch, with nothing written.
        let empty = format!("{:?}", MaskOutput::default());
        assert_eq!(masked(&Reverse, &text), (false, empty.clone()));
        let nulls = [Value::new(None), Value::new(None)];
        assert_eq!(
            masked(&FastReverse, &column_of(25, &nulls)),
            (false, empty.clone())
        );
        assert_eq!(
            masked(&FastReverse, &column_of(23, &values)),
            (false, empty)
        );

        // Not UTF-8.
        let invalid = [Value::new(Some(b"\xff"))];
        let mut out = MaskOutput::default();
        assert!(mask_text_column(&FastReverse, &column_of(25, &invalid), &mut out).is_err());
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
