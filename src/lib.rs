//! Dynamic data masking for PgDog.
//!
//! Statements from masked users are rewritten so every reference to a masked
//! column reads its mask instead, wherever it appears: projections, filters,
//! joins, grouping, ordering, `RETURNING`, subqueries, CTEs and `COPY`. See
//! `docs/DATA_MASKING.md`.
use std::path::PathBuf;
use std::sync::LazyLock;

use pgdog_plugin::{
    Capabilities, Config as PluginConfig, PdStr, Plugin, StatementContext, StatementOutput,
};
use tracing::error;

pub mod analyzer;
pub mod catalog;
pub mod config;
pub mod engine;
pub mod mask;
pub mod profile;

use engine::Engine;

static ENGINE: LazyLock<Engine> = LazyLock::new(Engine::default);

pgdog_plugin::plugin!(MaskingPlugin);

struct MaskingPlugin;

impl Plugin for MaskingPlugin {
    extern "C-unwind" fn version() -> PdStr<'static> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn capabilities() -> Capabilities {
        // REQUIRED: PgDog must never serve traffic without masking once it's configured.
        Capabilities::STATEMENT | Capabilities::SCHEMA | Capabilities::REQUIRED
    }

    extern "C-unwind" fn config(config: PluginConfig<'_>) -> bool {
        if config.plugin_config.is_empty() {
            error!("[pgdog_masking] no config file; set \"config\" in [[plugins]]");
            return false;
        }
        let path = PathBuf::from(&*config.plugin_config);
        match ENGINE.load(&path) {
            Ok(()) => true,
            Err(err) => {
                error!("[pgdog_masking] failed to load {}: {err}", path.display());
                false
            }
        }
    }

    fn statement(context: StatementContext<'_>) -> StatementOutput {
        ENGINE.statement(&context)
    }

    fn schema(database: &str, epoch: u64, snapshot: &str) {
        ENGINE.schema(database, epoch, snapshot);
    }

    fn reload() -> bool {
        ENGINE.reload()
    }
}
