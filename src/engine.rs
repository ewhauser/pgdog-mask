//! Plugin state: configuration, schemas, caches, and statement decisions.
use std::collections::HashMap;
use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher, RandomState};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use pgdog_plugin::{
    MessageCodes, StatementContext, StatementKind, StatementOutput, TransformContext,
    TransformOutput,
};
use tracing::{Level, debug, enabled, error, info, warn};

use crate::analyzer::{Context, Outcome, analyze, shape};
use crate::catalog::{Catalog, parse_search_path};
use crate::config::{Config, Error, Mode};
use crate::profile::{Assignments, Policies, Profile};
use crate::scrub::scrub_detail;
use crate::tags;

const PERMISSION_DENIED: &str = "42501";
const CANNOT_CONNECT_NOW: &str = "57P03";

/// Transform handle for removing `DETAIL` from errors and notices. Scrubbing
/// keeps no state, so every statement shares it.
const SCRUB: u64 = 1;

/// Loaded configuration.
struct Settings {
    policies: Policies,
    epoch: u64,
    /// Profiles by user and database. Users and their roles only change
    /// with the configuration, so these live as long as the settings do.
    profiles: ArcSwap<HashMap<String, HashMap<String, Arc<Profile>>>>,
}

impl Settings {
    fn new(policies: Policies, epoch: u64) -> Self {
        Self {
            policies,
            epoch,
            profiles: ArcSwap::default(),
        }
    }

    /// Compute a profile and add it to the snapshot.
    fn add_profile(&self, user: &str, database: &str) -> Arc<Profile> {
        let profile = Arc::new(self.policies.profile(user, database));
        self.profiles.rcu(|profiles| {
            let mut profiles = HashMap::clone(profiles);
            profiles
                .entry(user.to_owned())
                .or_default()
                .insert(database.to_owned(), profile.clone());
            profiles
        });
        profile
    }

    #[cfg(test)]
    fn profile(&self, user: &str, database: &str) -> Arc<Profile> {
        match self.profiles.load().get(user).and_then(|d| d.get(database)) {
            Some(profile) => profile.clone(),
            None => self.add_profile(user, database),
        }
    }
}

/// Everything a cached decision depends on. Stored with the decision and
/// compared on every hit: the hash only picks the slot, so a hash collision
/// (which a client could otherwise engineer) can never return another
/// statement's decision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    sql: Box<str>,
    /// Session search_path as sent; empty means the database default.
    search_path: Box<str>,
    /// Set when the search_path depends on the user (`$user`).
    user: Option<Box<str>>,
    profile: u64,
    settings_epoch: u64,
    schema_epoch: u64,
}

/// A borrowed [`CacheKey`], so lookups don't allocate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKeyRef<'a> {
    sql: &'a str,
    search_path: &'a str,
    user: Option<&'a str>,
    profile: u64,
    settings_epoch: u64,
    schema_epoch: u64,
}

impl CacheKeyRef<'_> {
    fn matches(&self, key: &CacheKey) -> bool {
        self.profile == key.profile
            && self.settings_epoch == key.settings_epoch
            && self.schema_epoch == key.schema_epoch
            && self.sql == &*key.sql
            && self.search_path == &*key.search_path
            && self.user == key.user.as_deref()
    }

    fn to_owned(self) -> CacheKey {
        CacheKey {
            sql: self.sql.into(),
            search_path: self.search_path.into(),
            user: self.user.map(Into::into),
            profile: self.profile,
            settings_epoch: self.settings_epoch,
            schema_epoch: self.schema_epoch,
        }
    }
}

/// Decision cache. Sharded, and lookups only take a read lock, so clients
/// running the same statements don't serialize on the cache. Eviction is
/// arbitrary rather than LRU: keeping recency would make every lookup a write.
struct Cache<T> {
    shards: Vec<RwLock<HashMap<u64, (CacheKey, T)>>>,
    per_shard: usize,
    /// Randomly keyed, so slot hashes can't be predicted by clients.
    hasher: RandomState,
}

const CACHE_SHARDS: usize = 16;

impl<T: Clone> Cache<T> {
    fn new(capacity: usize) -> Self {
        Self {
            shards: (0..CACHE_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            per_shard: capacity.div_ceil(CACHE_SHARDS).max(1),
            hasher: RandomState::new(),
        }
    }

    fn shard(&self, slot: u64) -> &RwLock<HashMap<u64, (CacheKey, T)>> {
        &self.shards[(slot % CACHE_SHARDS as u64) as usize]
    }

    fn get(&self, key: CacheKeyRef<'_>) -> Option<T> {
        let slot = self.hasher.hash_one(key);
        match self.shard(slot).read().get(&slot) {
            Some((stored, decision)) if key.matches(stored) => Some(decision.clone()),
            _ => None,
        }
    }

    fn put(&self, key: CacheKeyRef<'_>, decision: T) {
        let slot = self.hasher.hash_one(key);
        let mut shard = self.shard(slot).write();
        if shard.len() >= self.per_shard
            && !shard.contains_key(&slot)
            && let Some(evict) = shard.keys().next().copied()
        {
            shard.remove(&evict);
        }
        shard.insert(slot, (key.to_owned(), decision));
    }
}

/// One database's schema, with masked columns resolved for the current settings.
struct Database {
    catalog: Arc<Catalog>,
    schema_epoch: u64,
    assignments: Assignments,
    settings_epoch: u64,
}

/// Cached decision for a statement shape.
#[derive(Debug, Clone)]
enum ShapeDecision {
    Continue {
        scrub: bool,
    },
    Rewrite {
        template: Arc<shape::Template>,
        scrub: bool,
    },
    Block(String),
}

impl ShapeDecision {
    /// `None` if the rewrite can't be turned into a template.
    fn new(decision: Decision, literals: usize) -> Option<Self> {
        Some(match decision {
            Decision::Continue { scrub } => Self::Continue { scrub },
            Decision::Block(reason) => Self::Block(reason),
            Decision::Rewrite { sql, scrub, .. } => Self::Rewrite {
                template: Arc::new(shape::Template::new(&sql, literals)?),
                scrub,
            },
        })
    }

    /// The decision for a statement with this shape and these literals.
    fn render(self, literals: &[String]) -> Option<Decision> {
        Some(match self {
            Self::Continue { scrub } => Decision::Continue { scrub },
            Self::Block(reason) => Decision::Block(reason),
            Self::Rewrite { template, scrub } => {
                let sql = template.render(literals)?;
                Decision::Rewrite {
                    variant: variant(&sql),
                    sql,
                    scrub,
                }
            }
        })
    }
}

/// Identifies a rewrite, so PgDog re-prepares statements whose rewrite changed.
fn variant(sql: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    sql.hash(&mut hasher);
    hasher.finish()
}

/// What to do with a statement, cached by statement and profile.
#[derive(Debug, Clone)]
enum Decision {
    /// `scrub`: remove `DETAIL` from errors and notices.
    Continue {
        scrub: bool,
    },
    Rewrite {
        sql: String,
        variant: u64,
        scrub: bool,
    },
    Block(String),
}

pub struct Engine {
    path: Mutex<Option<PathBuf>>,
    settings: ArcSwap<Settings>,
    /// Snapshot of loaded schemas. Lookups don't take locks or touch reference counts.
    databases: ArcSwap<HashMap<String, Arc<Database>>>,
    cache: ArcSwap<Cache<Decision>>,
    /// Decisions for statement shapes, i.e., statements with literals replaced
    /// by placeholders. See [`crate::analyzer::shape`].
    shapes: ArcSwap<Cache<ShapeDecision>>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(Config::default()).expect("default config is valid")
    }
}

impl Engine {
    pub fn new(config: Config) -> Result<Self, Error> {
        let cache = Cache::new(config.general.cache_size);
        Ok(Self {
            path: Mutex::new(None),
            settings: ArcSwap::from_pointee(Settings::new(Policies::new(config)?, 1)),
            databases: ArcSwap::default(),
            shapes: ArcSwap::from_pointee(Cache::new(cache.per_shard * CACHE_SHARDS)),
            cache: ArcSwap::from_pointee(cache),
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
        let cache = Cache::new(config.general.cache_size);
        let policies = Policies::new(config)?;
        let epoch = self.settings.load().epoch + 1;
        info!(
            "[pgdog_masking] loaded {} policies, {} masked columns (mode: {:?})",
            policies.config.policies.len(),
            policies.config.masked_columns.len(),
            policies.config.general.mode,
        );
        self.settings
            .store(Arc::new(Settings::new(policies, epoch)));
        // Keys include the settings epoch, so old entries can't be hit; drop them anyway.
        self.shapes
            .store(Arc::new(Cache::new(cache.per_shard * CACHE_SHARDS)));
        self.cache.store(Arc::new(cache));
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
        if let Some(previous) = self.databases.load().get(database) {
            for ((schema, table, column), tag) in tags::removed(
                &previous.assignments.database_tags,
                &assignments.database_tags,
            ) {
                warn!(
                    "[pgdog_masking] tag \"{tag}\" was removed from column {schema}.{table}.{column} in database \"{database}\"; it's no longer masked by that tag"
                );
            }
        }
        let database_state = Arc::new(Database {
            catalog,
            schema_epoch: epoch,
            assignments,
            settings_epoch: settings.epoch,
        });
        self.databases.rcu(|databases| {
            let mut databases = HashMap::clone(databases);
            databases.insert(database.to_owned(), database_state.clone());
            databases
        });
    }

    /// Resolve masked columns of a database again after the settings changed.
    fn refresh_database(
        &self,
        name: &str,
        database: &Database,
        settings: &Settings,
    ) -> Arc<Database> {
        let database = Arc::new(Database {
            assignments: Assignments::new(&settings.policies, name, &database.catalog),
            catalog: database.catalog.clone(),
            schema_epoch: database.schema_epoch,
            settings_epoch: settings.epoch,
        });
        self.databases.rcu(|databases| {
            let mut databases = HashMap::clone(databases);
            databases.insert(name.to_owned(), database.clone());
            databases
        });
        database
    }

    /// Decide what to do with a statement.
    pub fn statement(&self, context: &StatementContext<'_>) -> StatementOutput {
        let settings = self.settings.load();
        let mode = settings.policies.config.general.mode;
        if mode == Mode::Off {
            return StatementOutput::cont();
        }

        let identity = &context.identity;
        let profiles = settings.profiles.load();
        let added;
        let profile: &Profile = match profiles
            .get(&*identity.user)
            .and_then(|databases| databases.get(&*identity.database))
        {
            Some(profile) => profile,
            None => {
                added = settings.add_profile(&identity.user, &identity.database);
                &added
            }
        };
        if profile.exempt {
            return StatementOutput::cont();
        }

        let decision = self.decide(context, &settings, profile);
        let scrub = |output: StatementOutput, scrub: bool| {
            if scrub && settings.policies.config.general.scrub_error_detail {
                output.with_transform(SCRUB, MessageCodes::none().with('E').with('N'))
            } else {
                output
            }
        };

        match (decision, mode) {
            (Decision::Continue { scrub: touched }, Mode::Enforce) => {
                scrub(StatementOutput::cont(), touched)
            }
            (Decision::Continue { .. }, _) => StatementOutput::cont(),
            (
                Decision::Rewrite {
                    sql,
                    variant,
                    scrub: touched,
                },
                Mode::Enforce,
            ) => scrub(StatementOutput::rewrite(sql, variant), touched),
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
                "",
                "fast-path function call",
                Decision::Block("fast-path function calls are not allowed for masked users".into()),
                shadow,
            );
        }

        let databases = self.databases.load();
        let refreshed;
        let database: &Database = match databases.get(&*identity.database) {
            Some(database) if database.settings_epoch == settings.epoch => database,
            Some(database) => {
                refreshed = self.refresh_database(&identity.database, database, settings);
                &refreshed
            }
            None => {
                return Decision::Block(format!(
                    "masking schema for database \"{}\" is not loaded yet",
                    &*identity.database
                ));
            }
        };

        // Resolution depends on the user only through `$user` in the search_path.
        let user_dependent = if context.search_path.is_empty() {
            database
                .catalog
                .search_path
                .iter()
                .any(|s| s.contains("$user"))
        } else {
            context.search_path.contains("$user")
        };
        let key = CacheKeyRef {
            sql: &context.sql,
            search_path: &context.search_path,
            user: user_dependent.then_some(&*identity.user),
            profile: profile.hash,
            settings_epoch: settings.epoch,
            schema_epoch: database.schema_epoch,
        };

        let cache = self.cache.load();
        if let Some(decision) = cache.get(key) {
            return decision;
        }

        let search_path = if context.search_path.is_empty() {
            database.catalog.search_path.join(",")
        } else {
            context.search_path.to_string()
        };
        let search_path = parse_search_path(&search_path, &identity.user);

        let ctx = Context {
            catalog: &database.catalog,
            assignments: &database.assignments,
            policies: &settings.policies,
            profile,
            search_path,
        };

        // Statements with literals: analyze their shape once, then render.
        // Prepared statements repeat their text on every Bind, so their rendered
        // decision is cached by text too; simple queries rarely do, and caching
        // them would only evict entries that are reused.
        if let Some(literals) = shape::literals(&context.sql) {
            let shape_key = CacheKeyRef {
                sql: &literals.shape,
                ..key
            };
            let shapes = self.shapes.load();
            let shape = match shapes.get(shape_key) {
                Some(shape) => Some(shape),
                None => {
                    let outcome = analyze(&literals.shape, &ctx);
                    let shape = ShapeDecision::new(
                        outcome_decision(outcome, &identity.user, &context.sql, shadow),
                        literals.values.len(),
                    );
                    if let Some(shape) = &shape {
                        shapes.put(shape_key, shape.clone());
                    }
                    shape
                }
            };
            if let Some(decision) = shape.and_then(|shape| shape.render(&literals.values)) {
                if context.kind != StatementKind::Query {
                    cache.put(key, decision.clone());
                }
                return decision;
            }
        }

        let decision = outcome_decision(
            analyze(&context.sql, &ctx),
            &identity.user,
            &context.sql,
            shadow,
        );
        cache.put(key, decision.clone());
        decision
    }
}

/// Decision for an analysis outcome, logged.
fn outcome_decision(outcome: Outcome, user: &str, original: &str, shadow: bool) -> Decision {
    match outcome {
        Outcome::Unchanged {
            raw,
            touches_masked,
        } => {
            if !raw.is_empty() {
                info!(
                    "[pgdog_masking] user \"{}\" searched raw values of {:?}",
                    user, raw
                );
            }
            Decision::Continue {
                scrub: touches_masked,
            }
        }
        Outcome::Rewritten {
            sql,
            masked,
            raw,
            touches_masked,
        } => {
            if !raw.is_empty() {
                info!(
                    "[pgdog_masking] user \"{}\" searched raw values of {:?}",
                    user, raw
                );
            }
            let variant = variant(&sql);
            log_decision(
                user,
                original,
                &format!("masked {masked:?}"),
                Decision::Rewrite {
                    sql,
                    variant,
                    scrub: touches_masked,
                },
                shadow,
            )
        }
        Outcome::Blocked { reason } => {
            log_decision(user, original, "", Decision::Block(reason), shadow)
        }
    }
}

impl Engine {
    /// Remove `DETAIL` from errors and notices of statements that touch masked relations.
    pub fn transform(&self, context: &TransformContext<'_>) -> TransformOutput {
        if context.handle != SCRUB || !matches!(context.code, b'E' | b'N') {
            return TransformOutput::forward();
        }
        match scrub_detail(context.payload.as_slice()) {
            Some(body) => TransformOutput::replace(body),
            None => TransformOutput::forward(),
        }
    }
}

/// Log a decision. Statements are logged normalized, with literals replaced by
/// placeholders, so searched values never end up in logs. Rewrites happen for
/// every statement of masked users and are logged at debug, except in shadow
/// mode, where logging them is the point.
fn log_decision(user: &str, sql: &str, what: &str, decision: Decision, shadow: bool) -> Decision {
    let prefix = if shadow {
        "[pgdog_masking] (shadow)"
    } else {
        "[pgdog_masking]"
    };
    match &decision {
        Decision::Rewrite { .. } => {
            if shadow {
                info!(
                    "{prefix} would rewrite statement for user \"{user}\", {what}: {}",
                    normalized(sql)
                );
            } else if enabled!(Level::DEBUG) {
                debug!(
                    "{prefix} rewrote statement for user \"{user}\", {what}: {}",
                    normalized(sql)
                );
            }
        }
        Decision::Block(reason) => {
            warn!(
                "{prefix} blocked statement for user \"{user}\": {reason} [{what}{}]",
                normalized(sql)
            )
        }
        Decision::Continue { .. } => (),
    }
    decision
}

/// The statement with literals replaced by placeholders.
fn normalized(sql: &str) -> String {
    if sql.is_empty() {
        return String::new();
    }
    match pg_raw_parse::normalize::normalize_str(sql) {
        Ok(normalized) => normalized.as_str().to_owned(),
        Err(_) => "<statement could not be parsed>".to_owned(),
    }
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
        let mut databases = HashMap::new();
        databases.insert(
            "db".to_owned(),
            Arc::new(Database {
                assignments: Assignments::new(&settings.policies, "db", &catalog),
                catalog: Arc::new(catalog),
                schema_epoch: 1,
                settings_epoch: settings.epoch,
            }),
        );
        engine.databases.store(Arc::new(databases));
        engine
    }

    fn decide(engine: &Engine, user: &str, sql: &str, kind: StatementKind) -> Decision {
        let settings = engine.settings.load();
        let profile = settings.profile(user, "db");
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
            Decision::Continue { .. }
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
    fn test_logged_statements_have_no_literals() {
        let logged = normalized("SELECT id FROM users WHERE ssn = '123-45-6789' AND id = 42");
        assert!(!logged.contains("123-45-6789"), "{logged}");
        assert!(!logged.contains("42"), "{logged}");
        assert!(logged.contains("ssn = $1"), "{logged}");
    }

    #[test]
    fn test_profiles_are_cached_per_settings() {
        let engine = engine(CONFIG);
        let settings = engine.settings.load();
        let a = settings.profile("anonymous", "db");
        let b = settings.profile("anonymous", "db");
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &settings.profile("anonymous", "other")));
    }

    #[test]
    fn test_cache_verifies_keys() {
        let cache = Cache::new(16);
        let key = CacheKeyRef {
            sql: "SELECT 1",
            search_path: "",
            user: None,
            profile: 1,
            settings_epoch: 1,
            schema_epoch: 1,
        };
        cache.put(key, Decision::Continue { scrub: false });
        assert!(cache.get(key).is_some());

        // Force a slot collision: same slot, different statement.
        let slot = cache.hasher.hash_one(key);
        let other = CacheKeyRef {
            sql: "SELECT ssn FROM users",
            ..key
        };
        let shard = cache.shard(slot).read();
        let (stored, _) = shard.get(&slot).unwrap();
        assert!(
            !other.matches(stored),
            "a colliding statement must not match"
        );
        drop(shard);

        for changed in [
            CacheKeyRef { profile: 2, ..key },
            CacheKeyRef {
                settings_epoch: 2,
                ..key
            },
            CacheKeyRef {
                schema_epoch: 2,
                ..key
            },
            CacheKeyRef {
                search_path: "other",
                ..key
            },
            CacheKeyRef {
                user: Some("alice"),
                ..key
            },
        ] {
            let shard = cache.shard(slot).read();
            assert!(!changed.matches(&shard.get(&slot).unwrap().0));
        }
    }

    #[test]
    fn test_shapes() {
        let engine = engine(CONFIG);
        let first = decide(
            &engine,
            "anonymous",
            "SELECT ssn FROM users WHERE id = 1 AND name = 'a'",
            StatementKind::Query,
        );
        let second = decide(
            &engine,
            "anonymous",
            "SELECT ssn FROM users WHERE id = 2 AND name = 'it''s'",
            StatementKind::Query,
        );
        let (
            Decision::Rewrite {
                sql: a,
                variant: va,
                ..
            },
            Decision::Rewrite {
                sql: b,
                variant: vb,
                ..
            },
        ) = (first, second)
        else {
            panic!("rewrites");
        };
        assert!(a.ends_with("WHERE id = 1 AND name = 'a'"), "{a}");
        assert!(b.ends_with("WHERE id = 2 AND name = 'it''s'"), "{b}");
        assert_ne!(va, vb, "different statements, different variants");

        // One shape analyzed; rendered statements aren't cached by text.
        let shapes = engine.shapes.load();
        let entries: usize = shapes.shards.iter().map(|s| s.read().len()).sum();
        assert_eq!(entries, 1);
        let cache = engine.cache.load();
        let entries: usize = cache.shards.iter().map(|s| s.read().len()).sum();
        assert_eq!(entries, 0, "simple queries aren't cached by text");

        // Prepared statements are.
        decide(
            &engine,
            "anonymous",
            "SELECT ssn FROM users LIMIT 10",
            StatementKind::Bind,
        );
        let entries: usize = cache.shards.iter().map(|s| s.read().len()).sum();
        assert_eq!(entries, 1);

        // Blocks apply to every statement of the shape.
        for id in [1, 2] {
            assert!(matches!(
                decide(
                    &engine,
                    "anonymous",
                    &format!("SELECT my_func({id}) FROM users"),
                    StatementKind::Query
                ),
                Decision::Block(_)
            ));
        }
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

    #[test]
    fn test_scrub_transform() {
        let enforce = engine(CONFIG);
        let output = |user, sql| {
            format!(
                "{:?}",
                enforce.statement(&context(user, sql, StatementKind::Query))
            )
        };

        // Statements touching masked relations get the transform, others don't.
        assert!(
            output("anonymous", "UPDATE users SET name = $1 WHERE id = $2")
                .contains("transform: 1")
        );
        assert!(output("anonymous", "SELECT ssn FROM users").contains("transform: 1"));
        assert!(output("anonymous", "SELECT id FROM orders").contains("transform: 0"));
        assert!(output("admin", "UPDATE users SET name = $1").contains("transform: 0"));

        let disabled =
            engine(&CONFIG.replacen("[general]", "[general]\nscrub_error_detail = false", 1));
        let output = format!(
            "{:?}",
            disabled.statement(&context(
                "anonymous",
                "SELECT ssn FROM users",
                StatementKind::Query
            ))
        );
        assert!(output.contains("transform: 0"), "{output}");

        let body = b"SERROR\0C23514\0Mcheck\0DFailing row contains (1, secret).\0\0";
        let replaced = enforce.transform(&TransformContext {
            handle: SCRUB,
            code: b'E',
            payload: body.as_slice().into(),
            result_formats: Default::default(),
        });
        let replaced = format!("{replaced:?}");
        assert!(replaced.contains("action: 1"), "{replaced}");
        let forwarded = enforce.transform(&TransformContext {
            handle: SCRUB,
            code: b'D',
            payload: body.as_slice().into(),
            result_formats: Default::default(),
        });
        assert!(format!("{forwarded:?}").contains("action: 0"));
    }
}
