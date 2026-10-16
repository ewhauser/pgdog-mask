//! Masks for integration tests, built with the `test-masks` feature.
use super::{Datum, MaskError, Options, ProxyMask, Registry};

pub(crate) fn register(registry: &mut Registry) {
    registry.register("test.increment", |_: &Options| Ok(Increment));
}

/// Adds 1 to integers, so tests can tell masked values from raw ones in any format.
struct Increment;

impl ProxyMask for Increment {
    fn accepts(&self, data_type: &str) -> bool {
        matches!(data_type, "integer" | "bigint")
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        match value {
            Datum::Integer(n) => Ok(Datum::Integer(n + 1)),
            Datum::Bigint(n) => Ok(Datum::Bigint(n + 1)),
            other => Err(MaskError::new(format!(
                "expected an integer, got {}",
                other.data_type()
            ))),
        }
    }
}
