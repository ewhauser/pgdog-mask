//! The plugin's hooks, shared by the default plugin and plugins built with
//! [`crate::masking_plugin!`].
use std::path::PathBuf;
use std::sync::{LazyLock, Once};

use pgdog_plugin::{
    Access, Capabilities, Catalog, CatalogParts, Config as PluginConfig, ErrorFields, MaskBatch,
    MaskError, MaskOutput, Redaction, Session, Verdict,
};
use tracing::error;

use crate::engine::Engine;
use crate::proxy::Registry;

static ENGINE: LazyLock<Engine> = LazyLock::new(Engine::default);
static REGISTRY: Once = Once::new();

// Configure the plugin with `required = true` in `[[plugins]]`: PgDog must
// never serve traffic without masking once it's configured.
pub fn capabilities() -> Capabilities {
    Capabilities::STATEMENT | Capabilities::MASK | Capabilities::ERRORS | Capabilities::CATALOG
}

/// Load the configuration file, with the proxy masks `register` adds to the
/// built-in ones.
pub fn config(config: PluginConfig<'_>, register: fn(&mut Registry)) -> bool {
    REGISTRY.call_once(|| {
        let mut registry = Registry::default();
        register(&mut registry);
        ENGINE.set_registry(registry);
    });

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

pub fn statement(session: &Session<'_>, sql: &str) -> Verdict {
    ENGINE.statement(session, sql)
}

pub fn function_call(session: &Session<'_>, function: u32) -> Access {
    ENGINE.function_call(session, function)
}

pub fn generation() -> u64 {
    ENGINE.generation()
}

pub fn mask_rows(batch: &MaskBatch<'_>, out: &mut MaskOutput) -> Result<(), MaskError> {
    ENGINE.mask_rows(batch, out)
}

pub fn redact_error(session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
    ENGINE.redact_error(session, error)
}

/// Columns hidden from PgDog's role, views and functions are all analyzed.
pub fn catalog_parts() -> CatalogParts {
    CatalogParts::ALL
}

pub fn catalog(database: &str, catalog: &Catalog) {
    ENGINE.catalog(database, catalog);
}

pub fn reload() -> bool {
    ENGINE.reload()
}

/// Build the masking plugin with your own proxy masks.
///
/// Depend on `pgdog-mask` with default features off, so its own plugin isn't
/// linked into yours, and build your crate as a `cdylib`:
///
/// ```toml
/// [lib]
/// crate-type = ["cdylib"]
///
/// [dependencies]
/// pgdog-mask = { git = "...", default-features = false }
/// ```
///
/// Then register your masks:
///
/// ```ignore
/// pgdog_mask::masking_plugin!(|registry| {
///     registry.register("acme.offset", |options| Ok(Offset::new(options)?));
/// });
/// ```
///
/// The plugin must be built with the same Rust compiler and `pgdog-plugin`
/// version as PgDog, like any PgDog plugin.
#[macro_export]
macro_rules! masking_plugin {
    ($register:expr) => {
        struct PgdogMaskPlugin;

        impl $crate::pgdog_plugin::Plugin for PgdogMaskPlugin {
            extern "C-unwind" fn version() -> $crate::pgdog_plugin::PdStr<'static> {
                $crate::VERSION.into()
            }

            fn capabilities() -> $crate::pgdog_plugin::Capabilities {
                $crate::plugin::capabilities()
            }

            extern "C-unwind" fn config(config: $crate::pgdog_plugin::Config<'_>) -> bool {
                $crate::plugin::config(config, $register)
            }

            fn statement(
                session: &$crate::pgdog_plugin::Session<'_>,
                sql: &str,
            ) -> $crate::pgdog_plugin::Verdict {
                $crate::plugin::statement(session, sql)
            }

            fn function_call(
                session: &$crate::pgdog_plugin::Session<'_>,
                function: u32,
            ) -> $crate::pgdog_plugin::Access {
                $crate::plugin::function_call(session, function)
            }

            fn generation() -> u64 {
                $crate::plugin::generation()
            }

            fn mask_rows(
                batch: &$crate::pgdog_plugin::MaskBatch<'_>,
                out: &mut $crate::pgdog_plugin::MaskOutput,
            ) -> Result<(), $crate::pgdog_plugin::MaskError> {
                $crate::plugin::mask_rows(batch, out)
            }

            fn redact_error(
                session: &$crate::pgdog_plugin::Session<'_>,
                error: &$crate::pgdog_plugin::ErrorFields<'_>,
            ) -> $crate::pgdog_plugin::Redaction {
                $crate::plugin::redact_error(session, error)
            }

            fn catalog_parts() -> $crate::pgdog_plugin::CatalogParts {
                $crate::plugin::catalog_parts()
            }

            fn catalog(database: &str, catalog: &$crate::pgdog_plugin::Catalog) {
                $crate::plugin::catalog(database, catalog)
            }

            fn reload() -> bool {
                $crate::plugin::reload()
            }
        }

        $crate::pgdog_plugin::plugin!(PgdogMaskPlugin);
    };
}
