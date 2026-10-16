//! The masking plugin with a custom proxy mask: tokens from a (simulated) vault.
//!
//! Build it with `cargo build` in this directory and load `libacme_mask` in
//! PgDog instead of `libpgdog_mask`. Policies can then use `acme.tokenize`
//! alongside the built-in masks:
//!
//! ```toml
//! [[policies]]
//! name = "account"
//! data_type = "text"
//! mask = "proxy"
//! proxy = "acme.tokenize"
//! options = { prefix = "tok_" }
//! ```
use std::collections::HashMap;

use parking_lot::Mutex;
use pgdog_mask::proxy::{Datum, MaskError, Options, ProxyMask, Registry};

pgdog_mask::masking_plugin!(register);

fn register(registry: &mut Registry) {
    registry.register("acme.tokenize", Tokenize::new);
}

/// Replaces values with tokens from a vault. A real implementation would call
/// the vault's API; this one keeps tokens in memory.
struct Tokenize {
    prefix: String,
    vault: Mutex<HashMap<String, String>>,
}

impl Tokenize {
    fn new(options: &Options) -> Result<Self, MaskError> {
        Ok(Self {
            prefix: options.string("prefix")?.unwrap_or("tok_").to_owned(),
            vault: Mutex::new(HashMap::new()),
        })
    }

    /// One round trip for all the values of a batch.
    fn tokens(&self, values: &[&str]) -> Vec<String> {
        let mut vault = self.vault.lock();
        values
            .iter()
            .map(|value| {
                let next = vault.len();
                vault
                    .entry((*value).to_owned())
                    .or_insert_with(|| format!("{}{next:08}", self.prefix))
                    .clone()
            })
            .collect()
    }
}

impl ProxyMask for Tokenize {
    fn accepts(&self, data_type: &str) -> bool {
        matches!(data_type, "text" | "character varying")
    }

    // Vault calls block: PgDog runs this mask on its blocking thread pool.
    fn blocking(&self) -> bool {
        true
    }

    fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
        Ok(self.mask_batch(vec![value])?.remove(0))
    }

    // Tokenize the whole batch at once instead of value by value.
    fn mask_batch(&self, values: Vec<Datum>) -> Result<Vec<Datum>, MaskError> {
        let texts: Vec<&str> = values
            .iter()
            .filter_map(|value| match value {
                Datum::Text(text) => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let mut tokens = self.tokens(&texts).into_iter();
        values
            .iter()
            .map(|value| match value {
                Datum::Null => Ok(Datum::Null),
                Datum::Text(_) => Ok(Datum::Text(tokens.next().unwrap_or_default())),
                other => Err(MaskError::new(format!(
                    "expected text, got {}",
                    other.data_type()
                ))),
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tokens_are_stable() {
        let mask = Tokenize::new(&Options::default()).unwrap();
        let first = mask
            .mask_batch(vec![
                Datum::Text("a".into()),
                Datum::Null,
                Datum::Text("b".into()),
                Datum::Text("a".into()),
            ])
            .unwrap();
        assert_eq!(first[0], first[3]);
        assert_ne!(first[0], first[2]);
        assert_eq!(first[1], Datum::Null);
        assert_eq!(mask.mask(Datum::Text("b".into())).unwrap(), first[2]);
    }
}
