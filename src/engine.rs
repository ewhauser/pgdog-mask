//! Plugin state: configuration, schemas, caches, and statement decisions.
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use pgdog_plugin::{StatementContext, StatementKind, StatementOutput};
use tracing::{error, info, warn};

use crate::analyzer::{Context, Outcome, analyze};
use crate::catalog::{Catalog, parse_search_path};
use crate::config::{Config, Error, Mode};
use crate::profile::{Assignments, Policies};

const PERMISSION_DENIED: &str = "42501";
const CANNOT_CONNECT_NOW: &str = "57P03";

/// Loaded configuration.
struct Settings {
    policies: Policies,
    epoch: u64,
}

/// One database's schema, with masked columns resolved for the current settings.
struct Database {
    catalog: Arc<Catalog>,
    schema_epoch: u64,
    assignments: Assignments,
    settings_epoch: u64,
}

/// What to do with a statement, cached by statement and profile.
#[derive(Debug, Clone)]
enum Decision {
    Continue,
    Rewrite { sql: String, variant: u64 },
    Block(String),
}

pub struct Engine {
    path: Mutex<Option<PathBuf>>,
    settings: ArcSwap<Settings>,
    databases: RwLock<HashMap<String, Arc<Database>>>,
    cache: Mutex<LruCache<u64, Decision>>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(Config::default()).expect("default config is valid")
    }
}

impl Engine {
    pub fn new(config: Config) -> Result<Self, Error> {
        let capacity = NonZeroUsize::new(config.general.cache_size).unwrap_or(NonZeroUsize::MIN);
        Ok(Self {
            path: Mutex::new(None),
            settings: ArcSwap::from_pointee(Settings {
                policies: Policies::new(config)?,
                epoch: 1,
            }),
            databases: RwLock::new(HashMap::new()),
            cache: Mutex::new(LruCache::new(capacity)),
        })
    }

    /// Load the configuration file.
    pub fn load(&self, path: &Path) -> Result<(), Error> {
        let config = Config::load(path)?;
        self.apply(config)?;
        *self.path.lock() = Some(path.to_owned());
        Ok(())
    }

    /// Replace the configuration.
    pub fn apply(&self, config: Config) -> Result<(), Error> {
        let capacity = NonZeroUsize::new(config.general.cache_size).unwrap_or(NonZeroUsize::MIN);
        let policies = Policies::new(config)?;
        let epoch = self.settings.load().epoch + 1;
        info!(
            "[pgdog_masking] loaded {} policies, {} masked columns (mode: {:?})",
            policies.config.policies.len(),
            policies.config.masked_columns.len(),
            policies.config.general.mode,
        );
        self.settings.store(Arc::new(Settings { policies, epoch }));
        let mut cache = self.cache.lock();
        cache.clear();
        cache.resize(capacity);
        Ok(())
    }

    /// Reload the configuration file. Keeps the current configuration if the new one is invalid.
    pub fn reload(&self) -> bool {
        let Some(path) = self.path.lock().clone() else {
            return true;
        };
        match self.load(&path) {
            Ok(()) => true,
            Err(err) => {
                error!("[pgdog_masking] failed to reload {}: {err}", path.display());
                false
            }
        }
    }

    /// Store a schema snapshot.
    pub fn schema(&self, database: &str, epoch: u64, snapshot: &str) {
        let catalog = match Catalog::from_json(snapshot) {
            Ok(catalog) => Arc::new(catalog),
            Err(err) => {
                error!("[pgdog_masking] failed to parse schema for \"{database}\": {err}");
                return;
            }
        };
        let settings = self.settings.load();
        let assignments = Assignments::new(&settings.policies, database, &catalog);
        self.databases.write().insert(
            database.to_owned(),
            Arc::new(Database {
                catalog,
                schema_epoch: epoch,
                assignments,
                settings_epoch: settings.epoch,
            }),
        );
    }

    /// A database's schema, with masked columns resolved for the current settings.
    fn database(&self, name: &str, settings: &Settings) -> Option<Arc<Database>> {
        let database = self.databases.read().get(name).cloned()?;
        if database.settings_epoch == settings.epoch {
            return Some(database);
        }

        // Settings changed since the schema arrived.
        let database = Arc::new(Database {
            assignments: Assignments::new(&settings.policies, name, &database.catalog),
            catalog: database.catalog.clone(),
            schema_epoch: database.schema_epoch,
            settings_epoch: settings.epoch,
        });
        self.databases
            .write()
            .insert(name.to_owned(), database.clone());
        Some(database)
    }

    /// Decide what to do with a statement.
    pub fn statement(&self, context: &StatementContext<'_>) -> StatementOutput {
        let settings = self.settings.load();
        let mode = settings.policies.config.general.mode;
        if mode == Mode::Off {
            return StatementOutput::cont();
        }

        let identity = &context.identity;
        let profile = settings
            .policies
            .profile(&identity.user, &identity.database);
        if profile.exempt {
            return StatementOutput::cont();
        }

        let decision = self.decide(context, &settings, &profile);

        match (decision, mode) {
            (Decision::Continue, _) => StatementOutput::cont(),
            (Decision::Rewrite { sql, variant }, Mode::Enforce) => {
                StatementOutput::rewrite(sql, variant)
            }
            (Decision::Block(reason), Mode::Enforce) => {
                let code = if reason.starts_with("masking schema") {
                    CANNOT_CONNECT_NOW
                } else {
                    PERMISSION_DENIED
                };
                StatementOutput::block(code, reason)
            }
            // Shadow mode: decisions are logged when they're made.
            _ => StatementOutput::cont(),
        }
    }

    fn decide(
        &self,
        context: &StatementContext<'_>,
        settings: &Settings,
        profile: &crate::profile::Profile,
    ) -> Decision {
        let identity = &context.identity;
        let shadow = settings.policies.config.general.mode == Mode::Shadow;

        if context.kind == StatementKind::FunctionCall {
            return log_decision(
                &identity.user,
                "fast-path function call",
                Decision::Block("fast-path function calls are not allowed for masked users".into()),
                shadow,
            );
        }

        let Some(database) = self.database(&identity.database, settings) else {
            return Decision::Block(format!(
                "masking schema for database \"{}\" is not loaded yet",
                &*identity.database
            ));
        };

        let search_path = if context.search_path.is_empty() {
            database.catalog.search_path.join(",")
        } else {
            context.search_path.to_string()
        };
        let search_path = parse_search_path(&search_path, &identity.user);

        let key = {
            let mut hasher = DefaultHasher::new();
            (
                &*context.sql,
                profile.hash,
                settings.epoch,
                database.schema_epoch,
                &search_path,
            )
                .hash(&mut hasher);
            hasher.finish()
        };

        if let Some(decision) = self.cache.lock().get(&key) {
            return decision.clone();
        }

        let ctx = Context {
            catalog: &database.catalog,
            assignments: &database.assignments,
            policies: &settings.policies,
            profile,
            search_path,
        };

        let decision = match analyze(&context.sql, &ctx) {
            Outcome::Unchanged { raw } => {
                if !raw.is_empty() {
                    info!(
                        "[pgdog_masking] user \"{}\" searched raw values of {:?}",
                        &*identity.user, raw
                    );
                }
                Decision::Continue
            }
            Outcome::Rewritten { sql, masked, raw } => {
                if !raw.is_empty() {
                    info!(
                        "[pgdog_masking] user \"{}\" searched raw values of {:?}",
                        &*identity.user, raw
                    );
                }
                let variant = {
                    let mut hasher = DefaultHasher::new();
                    sql.hash(&mut hasher);
                    hasher.finish()
                };
                log_decision(
                    &identity.user,
                    &format!("masked {masked:?}"),
                    Decision::Rewrite { sql, variant },
                    shadow,
                )
            }
            Outcome::Blocked { reason } => log_decision(
                &identity.user,
                &context.sql,
                Decision::Block(reason),
                shadow,
            ),
        };

        self.cache.lock().put(key, decision.clone());
        decision
    }
}

fn log_decision(user: &str, what: &str, decision: Decision, shadow: bool) -> Decision {
    let prefix = if shadow {
        "[pgdog_masking] (shadow)"
    } else {
        "[pgdog_masking]"
    };
    match &decision {
        Decision::Rewrite { sql, .. } => {
            info!("{prefix} rewrote statement for user \"{user}\", {what}: {sql}")
        }
        Decision::Block(reason) => {
            warn!("{prefix} blocked statement for user \"{user}\": {reason} [{what}]")
        }
        Decision::Continue => (),
    }
    decision
}

#[cfg(test)]
mod test {
    use pgdog_plugin::Identity;

    use super::*;
    use crate::analyzer::test::{CONFIG, catalog};

    fn context<'a>(user: &'a str, sql: &'a str, kind: StatementKind) -> StatementContext<'a> {
        StatementContext {
            identity: Identity {
                user: user.into(),
                database: "db".into(),
                ..Default::default()
            },
            kind,
            sql: sql.into(),
            statement_name: "".into(),
            search_path: "".into(),
            in_transaction: false,
        }
    }

    fn engine(config: &str) -> Engine {
        let engine = Engine::new(Config::from_toml(config).unwrap()).unwrap();
        let catalog = catalog();
        let settings = engine.settings.load();
        engine.databases.write().insert(
            "db".into(),
            Arc::new(Database {
                assignments: Assignments::new(&settings.policies, "db", &catalog),
                catalog: Arc::new(catalog),
                schema_epoch: 1,
                settings_epoch: settings.epoch,
            }),
        );
        engine
    }

    fn decide(engine: &Engine, user: &str, sql: &str, kind: StatementKind) -> Decision {
        let settings = engine.settings.load();
        let profile = settings.policies.profile(user, "db");
        engine.decide(&context(user, sql, kind), &settings, &profile)
    }

    #[test]
    fn test_decisions() {
        let engine = engine(CONFIG);
        assert!(matches!(
            decide(
                &engine,
                "anonymous",
                "SELECT ssn FROM users",
                StatementKind::Query
            ),
            Decision::Rewrite { .. }
        ));
        assert!(matches!(
            decide(
                &engine,
                "anonymous",
                "SELECT id FROM orders",
                StatementKind::Parse
            ),
            Decision::Continue
        ));
        assert!(matches!(
            decide(&engine, "anonymous", "", StatementKind::FunctionCall),
            Decision::Block(_)
        ));

        // Same rewrite, same variant.
        let Decision::Rewrite { variant: a, .. } = decide(
            &engine,
            "anonymous",
            "SELECT ssn FROM users",
            StatementKind::Bind,
        ) else {
            panic!("rewrite")
        };
        let Decision::Rewrite { variant: b, .. } = decide(
            &engine,
            "anonymous",
            "SELECT ssn FROM users",
            StatementKind::Bind,
        ) else {
            panic!("rewrite")
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_missing_schema_blocks() {
        let engine = Engine::new(Config::from_toml(CONFIG).unwrap()).unwrap();
        let Decision::Block(reason) =
            decide(&engine, "anonymous", "SELECT 1", StatementKind::Query)
        else {
            panic!("blocked");
        };
        assert!(reason.starts_with("masking schema"), "{reason}");
    }

    #[test]
    fn test_modes() {
        let shadow =
            engine(&format!("{CONFIG}\n").replacen("[general]", "[general]\nmode = \"shadow\"", 1));
        let output = shadow.statement(&context(
            "anonymous",
            "SELECT ssn FROM users",
            StatementKind::Query,
        ));
        assert!(format!("{output:?}").contains("action: 0"), "{output:?}");

        let enforce = engine(CONFIG);
        let output = enforce.statement(&context(
            "anonymous",
            "SELECT ssn FROM users",
            StatementKind::Query,
        ));
        assert!(format!("{output:?}").contains("action: 1"), "{output:?}");

        // Exempt users are never analyzed.
        let output = enforce.statement(&context(
            "admin",
            "SELECT * FROM unknown_table",
            StatementKind::Query,
        ));
        assert!(format!("{output:?}").contains("action: 0"), "{output:?}");
    }
}
