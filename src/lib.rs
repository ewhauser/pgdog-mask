//! Dynamic data masking for PgDog.
//!
//! Statements from masked users are rewritten so every reference to a masked
//! column reads its mask instead, wherever it appears: projections, filters,
//! joins, grouping, ordering, `RETURNING`, subqueries, CTEs and `COPY`. See
//! `docs/DATA_MASKING.md`.
use std::path::PathBuf;
use std::sync::LazyLock;

use pgdog_plugin::{
    Access, Capabilities, Catalog, CatalogParts, Config as PluginConfig, ErrorFields, PdStr,
    Plugin, Redaction, Session, Verdict,
};
use tracing::error;

pub mod analyzer;
pub mod catalog;
pub mod config;
pub mod engine;
pub mod mask;
pub mod profile;
pub mod tags;

use engine::Engine;

static ENGINE: LazyLock<Engine> = LazyLock::new(Engine::default);

pgdog_plugin::plugin!(MaskingPlugin);

struct MaskingPlugin;

impl Plugin for MaskingPlugin {
    extern "C-unwind" fn version() -> PdStr<'static> {
        env!("CARGO_PKG_VERSION").into()
    }

    // Configure the plugin with `required = true` in `[[plugins]]`: PgDog must
    // never serve traffic without masking once it's configured.
    fn capabilities() -> Capabilities {
        Capabilities::STATEMENT | Capabilities::ERRORS | Capabilities::CATALOG
    }

    extern "C-unwind" fn config(config: PluginConfig<'_>) -> bool {
        if config.plugin_config.is_empty() {
            error!("[pgdog_mask] no config file; set \"config\" in [[plugins]]");
            return false;
        }
        let path = PathBuf::from(&*config.plugin_config);
        match ENGINE.load(&path) {
            Ok(()) => true,
            Err(err) => {
                error!("[pgdog_mask] failed to load {}: {err}", path.display());
                false
            }
        }
    }

    fn statement(session: &Session<'_>, sql: &str) -> Verdict {
        ENGINE.statement(session, sql)
    }

    fn function_call(session: &Session<'_>, function: u32) -> Access {
        ENGINE.function_call(session, function)
    }

    fn generation() -> u64 {
        ENGINE.generation()
    }

    fn redact_error(session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
        ENGINE.redact_error(session, error)
    }

    fn catalog_parts() -> CatalogParts {
        // Columns hidden from PgDog's role, views and functions are all analyzed.
        CatalogParts::ALL
    }

    fn catalog(database: &str, catalog: &Catalog) {
        ENGINE.catalog(database, catalog);
    }

    fn reload() -> bool {
        ENGINE.reload()
    }
}
