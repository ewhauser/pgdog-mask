//! Proxy masks registered next to the built-in ones, covering what the
//! built-ins don't: integer types and blocking masks.
use pgdog_mask::proxy::{Datum, MaskError, Options, ProxyMask, Registry};

/// Every proxy mask the fuzzing plugin has.
pub fn register(registry: &mut Registry) {
    registry.register("fuzz.offset", |options: &Options| {
        Ok(Offset(options.integer("offset")?.unwrap_or(1)))
    });
    registry.register("fuzz.blocking", |_: &Options| Ok(Upper));
}

/// Adds an offset to integers.
struct Offset(i64);

impl ProxyMask for Offset {
    fn accepts(&self, data_type: &str) -> bool {
        matches!(data_type, "smallint" | "integer" | "bigint")
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        match value {
            Datum::SmallInt(n) => Ok(Datum::SmallInt(n.wrapping_add(self.0 as i16))),
            Datum::Integer(n) => Ok(Datum::Integer(n.wrapping_add(self.0 as i32))),
            Datum::Bigint(n) => Ok(Datum::Bigint(n.wrapping_add(self.0))),
            other => Err(MaskError::new(format!(
                "expected an integer, got {}",
                other.data_type()
            ))),
        }
    }
}

/// Upper-cases text, declared blocking so PgDog would run it off its workers.
struct Upper;

impl ProxyMask for Upper {
    fn accepts(&self, data_type: &str) -> bool {
        data_type == "text"
    }

    fn blocking(&self) -> bool {
        true
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        match value {
            Datum::Text(text) => Ok(Datum::Text(text.to_uppercase())),
            other => Err(MaskError::new(format!(
                "expected text, got {}",
                other.data_type()
            ))),
        }
    }
}
