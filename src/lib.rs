//! Dynamic data masking for PgDog.
//!
//! A masked column has a SQL mask or a proxy mask for each user:
//!
//! - Statements are rewritten so every reference to a SQL-masked column
//!   reads its mask instead, wherever it appears: projections, filters,
//!   joins, grouping, ordering, `RETURNING`, subqueries, CTEs and `COPY`.
//! - References to proxy-masked columns aren't rewritten: conditions run on
//!   real values. PgDog masks the result columns that pass them through with
//!   the proxy mask, and those computed from them are NULL. Statements that
//!   would move their values where PgDog can't mask them are blocked, and
//!   errors of statements computing on them are redacted.
//!
//! See `docs/DESIGN.md`.
pub mod analyzer;
pub mod catalog;
pub mod config;
pub mod engine;
pub mod mask;
pub mod plugin;
pub mod profile;
pub mod proxy;
pub mod tags;

/// The plugin API this crate is built against. Plugins built with
/// [`masking_plugin!`] use it through this re-export, so their version matches.
pub use pgdog_plugin;

/// Version of pgdog-mask.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The plugin itself, with the built-in proxy masks.
#[cfg(feature = "plugin")]
masking_plugin!(register);

#[cfg(feature = "plugin")]
fn register(_registry: &mut proxy::Registry) {
    #[cfg(feature = "test-masks")]
    proxy::test_masks::register(_registry);
}
