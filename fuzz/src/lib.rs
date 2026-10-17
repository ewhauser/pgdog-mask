//! Shared harness for the pgdog-mask fuzz targets.
//!
//! This crate is a masking plugin, built with `masking_plugin!` like custom
//! mask plugins are. Targets call it through its vtable, the way PgDog does:
//! hook inputs cross the plugin boundary, and outputs are decoded and freed by
//! `pgdog-plugin`'s host side. Hooks catch panics and fail closed, so a
//! panicking hook comes back as [`HookError::Panicked`]; targets treat every
//! [`HookError`] as a bug. libFuzzer's panic hook also aborts on the panic
//! itself, with its backtrace.
//!
//! [`HookError`]: pgdog_mask::pgdog_plugin::HookError
//! [`HookError::Panicked`]: pgdog_mask::pgdog_plugin::HookError::Panicked
pub mod fixture;
pub mod grammar;
pub mod masks;
pub mod session;

pub use fixture::plugin;

pgdog_mask::masking_plugin!(masks::register);
