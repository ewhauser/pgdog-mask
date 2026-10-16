//! Dynamic data masking for PgDog.
//!
//! Statements from masked users are rewritten so every reference to a masked
//! column reads its mask instead, wherever it appears: projections, filters,
//! joins, grouping, ordering, `RETURNING`, subqueries, CTEs and `COPY`. See
//! `docs/DATA_MASKING.md`.
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
