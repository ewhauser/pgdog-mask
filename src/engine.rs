//! Plugin state: configuration, schemas, caches, and statement decisions.
use std::collections::{BTreeSet, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use pgdog_plugin::{
    Access, ColumnTransform, Deny, ErrorFields, Redaction, Session, SqlState, TransformBatch,
    TransformId, TransformOutput, Verdict, redact::field::DETAIL,
};
use tracing::{Level, debug, enabled, error, info, warn};

use crate::analyzer::{self, Context, Outcome, ResultMask, analyze, deparsable, shape};
use crate::catalog::{Catalog, parse_search_path};
use crate::config::{Config, Error, Mode};
use crate::profile::{Assignments, Policies, Profile, ProxyInstance};
use crate::proxy::{self, MaskError, Registry};
use crate::tags;

/// `cannot_connect_now`: the schema of the database isn't loaded yet.
const CANNOT_CONNECT_NOW: &str = "57P03";

/// Loaded configuration.
struct Settings {
    policies: Policies,
    epoch: u64,
    /// Mask ID of the first of `policies.proxies` (see [`Engine::proxies`]).
    proxy_base: u64,
    /// Profiles by user and database. Users and their roles only change
    /// with the configuration, so these live as long as the settings do.
    profiles: ArcSwap<HashMap<String, HashMap<String, Arc<Profile>>>>,
}

impl Settings {
    fn new(policies: Policies, epoch: u64, proxy_base: u64) -> Self {
        Self {
            policies,
            epoch,
            proxy_base,
            profiles: ArcSwap::default(),
        }
    }

    /// How PgDog masks a statement's results.
    fn results(&self, results: &analyzer::Results) -> Results {
        let columns = results
            .columns
            .iter()
            .map(|column| match column.mask {
                ResultMask::Null => ColumnTransform::null(column.column).in_result(column.result),
                ResultMask::Proxy { proxy, type_oid } => {
                    let mask = ColumnTransform::new(
                        column.column,
                        TransformId(self.proxy_base + proxy as u64),
                        type_oid,
                    )
                    .in_result(column.result);
                    if self.policies.proxies[proxy].mask.blocking() {
                        mask.blocking()
                    } else {
                        mask
                    }
                }
            })
            .collect();
        Results {
            columns,
            redact_errors: results.redact_errors,
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

/// How PgDog masks a statement's results.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Results {
    columns: Arc<[ColumnTransform]>,
    /// Errors may quote values of proxy-masked columns.
    redact_errors: bool,
}

impl Results {
    fn is_empty(&self) -> bool {
        self.columns.is_empty() && !self.redact_errors
    }

    /// For logs: `N proxy, M NULL, errors redacted: yes|no`.
    fn summary(&self) -> String {
        let nulls = self.columns.iter().filter(|mask| mask.is_null()).count();
        format!(
            "{} proxy, {nulls} NULL, errors redacted: {}",
            self.columns.len() - nulls,
            if self.redact_errors { "yes" } else { "no" }
        )
    }
}

/// Cached decision for a statement shape.
#[derive(Debug, Clone)]
enum ShapeDecision {
    Continue(Results),
    Rewrite(Arc<shape::Template>, Results),
    Block(String),
}

impl ShapeDecision {
    /// `None` if the rewrite can't be turned into a template.
    fn new(decision: Decision, literals: usize) -> Option<Self> {
        Some(match decision {
            Decision::Continue(results) => Self::Continue(results),
            Decision::Block(reason) => Self::Block(reason),
            Decision::Rewrite(sql, results) => {
                Self::Rewrite(Arc::new(shape::Template::new(&sql, literals)?), results)
            }
        })
    }

    /// The decision for a statement with this shape and these literals.
    fn render(self, literals: &[String]) -> Option<Decision> {
        Some(match self {
            Self::Continue(results) => Decision::Continue(results),
            Self::Block(reason) => Decision::Block(reason),
            Self::Rewrite(template, results) => {
                Decision::Rewrite(template.render(literals)?, results)
            }
        })
    }
}

/// What to do with a statement, cached by statement and profile.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// Send it as is, masking its results as said.
    Continue(Results),
    /// Send this SQL instead, masking its results as said.
    Rewrite(String, Results),
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
    /// Changes whenever decisions may change: new settings or a new catalog.
    generation: AtomicU64,
    /// Numbers catalogs as they arrive.
    catalog_epoch: AtomicU64,
    /// Every proxy mask any settings have used, by mask ID. Never shrinks:
    /// statements prepared before a reload keep their mask IDs until PgDog
    /// checks them again.
    proxies: ArcSwap<Vec<ProxyInstance>>,
    /// Proxy masks policies can name.
    registry: Mutex<Arc<Registry>>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(Config::default()).expect("default config is valid")
    }
}

impl Engine {
    /// An engine with the built-in proxy masks.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_registry(config, Registry::default())
    }

    /// An engine with the proxy masks of `registry`.
    pub fn with_registry(config: Config, registry: Registry) -> Result<Self, Error> {
        let cache = Cache::new(config.general.cache_size);
        let policies = Policies::with_registry(config, &registry)?;
        let proxies = policies.proxies.clone();
        Ok(Self {
            path: Mutex::new(None),
            settings: ArcSwap::from_pointee(Settings::new(policies, 1, 0)),
            databases: ArcSwap::default(),
            shapes: ArcSwap::from_pointee(Cache::new(cache.per_shard * CACHE_SHARDS)),
            cache: ArcSwap::from_pointee(cache),
            generation: AtomicU64::new(1),
            catalog_epoch: AtomicU64::new(0),
            proxies: ArcSwap::from_pointee(proxies),
            registry: Mutex::new(Arc::new(registry)),
        })
    }

    /// Use the proxy masks of `registry` from the next configuration on.
    pub fn set_registry(&self, registry: Registry) {
        *self.registry.lock() = Arc::new(registry);
    }

    /// Generation of the plugin's decisions, see [`pgdog_plugin::Plugin::generation`].
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Decisions made so far may no longer hold.
    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
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
        let registry = self.registry.lock().clone();
        let policies = Policies::with_registry(config, &registry)?;
        let epoch = self.settings.load().epoch + 1;
        let mut proxy_base = 0;
        self.proxies.rcu(|proxies| {
            proxy_base = proxies.len() as u64;
            let mut proxies = Vec::clone(proxies);
            proxies.extend(policies.proxies.iter().cloned());
            proxies
        });
        info!(
            "[pgdog_mask] loaded {} policies, {} masked columns (mode: {:?})",
            policies.config.policies.len(),
            policies.config.masked_columns.len(),
            policies.config.general.mode,
        );
        self.settings
            .store(Arc::new(Settings::new(policies, epoch, proxy_base)));
        // Keys include the settings epoch, so old entries can't be hit; drop them anyway.
        self.shapes
            .store(Arc::new(Cache::new(cache.per_shard * CACHE_SHARDS)));
        self.cache.store(Arc::new(cache));
        self.invalidate();
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
                error!("[pgdog_mask] failed to reload {}: {err}", path.display());
                false
            }
        }
    }

    /// Store a database's catalog.
    pub fn catalog(&self, database: &str, catalog: &pgdog_plugin::Catalog) {
        let catalog = Arc::new(Catalog::from_plugin(catalog));
        let epoch = self.catalog_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        let settings = self.settings.load();
        let assignments = Assignments::new(&settings.policies, database, &catalog);
        if let Some(previous) = self.databases.load().get(database) {
            for ((schema, table, column), tag) in tags::removed(
                &previous.assignments.database_tags,
                &assignments.database_tags,
            ) {
                warn!(
                    "[pgdog_mask] tag \"{tag}\" was removed from column {schema}.{table}.{column} in database \"{database}\"; it's no longer masked by that tag"
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
        self.invalidate();
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

    /// Run `f` with the profile of a user, computing it on first use.
    fn with_profile<R>(
        settings: &Settings,
        session: &Session<'_>,
        f: impl FnOnce(&Profile) -> R,
    ) -> R {
        let profiles = settings.profiles.load();
        match profiles
            .get(&*session.user)
            .and_then(|databases| databases.get(&*session.database))
        {
            Some(profile) => f(profile),
            None => f(&settings.add_profile(&session.user, &session.database)),
        }
    }

    /// Decide what to do with a statement.
    pub fn statement(&self, session: &Session<'_>, sql: &str) -> Verdict {
        let settings = self.settings.load();
        let mode = settings.policies.config.general.mode;
        if mode == Mode::Off {
            return Verdict::Allow;
        }

        Self::with_profile(&settings, session, |profile| {
            if profile.exempt {
                return Verdict::Allow;
            }

            match (self.decide(session, sql, &settings, profile), mode) {
                (Decision::Continue(results), Mode::Enforce) if !results.is_empty() => {
                    Verdict::transform(sql, results.columns.to_vec())
                        .redact_errors(results.redact_errors)
                }
                (Decision::Rewrite(sql, results), Mode::Enforce) => {
                    Verdict::transform(sql, results.columns.to_vec())
                        .redact_errors(results.redact_errors)
                }
                (Decision::Block(reason), Mode::Enforce) => Verdict::Deny(denied(reason)),
                // Shadow mode: decisions are logged when they're made.
                _ => Verdict::Allow,
            }
        })
    }

    /// Fast-path function calls can't be analyzed: masked users can't make them.
    pub fn function_call(&self, session: &Session<'_>, function: u32) -> Access {
        let settings = self.settings.load();
        let mode = settings.policies.config.general.mode;
        if mode == Mode::Off {
            return Access::Allow;
        }

        Self::with_profile(&settings, session, |profile| {
            if profile.exempt {
                return Access::Allow;
            }
            let decision = log_decision(
                &session.user,
                "",
                &format!("fast-path call of function {function}"),
                Decision::Block("fast-path function calls are not allowed for masked users".into()),
                mode == Mode::Shadow,
            );
            match (decision, mode) {
                (Decision::Block(reason), Mode::Enforce) => Access::Deny(denied(reason)),
                _ => Access::Allow,
            }
        })
    }

    /// Mask a batch of result rows with proxy masks. See [`crate::proxy`].
    pub fn mask_rows(
        &self,
        batch: &TransformBatch<'_>,
        out: &mut TransformOutput,
    ) -> Result<(), MaskError> {
        let proxies = self.proxies.load();
        for column in batch.columns() {
            // PgDog applies NULL masks itself; never mask with whatever has
            // that ID if one arrives anyway.
            if column.transform == TransformId::NULL {
                for _ in column.values() {
                    out.push(None);
                }
                continue;
            }
            let instance = proxies
                .get(column.transform.0 as usize)
                .ok_or_else(|| MaskError::new(format!("unknown mask ID {}", column.transform.0)))?;
            let failed = |err: MaskError| MaskError::new(format!("{}: {}", instance.name, err.0));
            if proxy::mask_text_column(instance.mask.as_ref(), column, out).map_err(failed)? {
                continue;
            }

            let values = column
                .values()
                .map(|value| proxy::decode(value, column.type_oid, column.format))
                .collect::<Result<Vec<_>, _>>()
                .map_err(failed)?;
            let count = values.len();
            let masked = instance.mask.mask_batch(values).map_err(failed)?;
            if masked.len() != count {
                return Err(failed(MaskError::new(format!(
                    "returned {} values for {count}",
                    masked.len()
                ))));
            }
            for value in &masked {
                let encoded =
                    proxy::encode(value, column.type_oid, column.format).map_err(failed)?;
                out.push(encoded.as_deref());
            }
        }
        Ok(())
    }

    /// Remove `DETAIL` from the errors and notices masked users get: it can
    /// hold the values of masked columns, e.g. a `CHECK` violation's
    /// `Failing row contains (1, 123-45-6789, ...)`. Users with proxy masks
    /// always lose it, whatever `scrub_error_detail` says: their statements
    /// read the real values of proxy-masked columns.
    pub fn redact_error(&self, session: &Session<'_>, error: &ErrorFields<'_>) -> Redaction {
        let settings = self.settings.load();
        let general = &settings.policies.config.general;
        if general.mode != Mode::Enforce || error.get(DETAIL).is_none() {
            return Redaction::Keep;
        }
        let scrub = general.scrub_error_detail;

        Self::with_profile(&settings, session, |profile| {
            if profile.exempt || !(scrub || profile.proxies) {
                Redaction::Keep
            } else {
                Redaction::Replace(error.without(&[DETAIL]))
            }
        })
    }

    fn decide(
        &self,
        session: &Session<'_>,
        sql: &str,
        settings: &Settings,
        profile: &Profile,
    ) -> Decision {
        let shadow = settings.policies.config.general.mode == Mode::Shadow;

        let databases = self.databases.load();
        let refreshed;
        let database: &Database = match databases.get(&*session.database) {
            Some(database) if database.settings_epoch == settings.epoch => database,
            Some(database) => {
                refreshed = self.refresh_database(&session.database, database, settings);
                &refreshed
            }
            None => {
                return Decision::Block(format!(
                    "masking schema for database \"{}\" is not loaded yet",
                    &*session.database
                ));
            }
        };

        // Resolution depends on the user only through `$user` in the search_path.
        let user_dependent = if session.search_path.is_empty() {
            database
                .catalog
                .search_path
                .iter()
                .any(|s| s.contains("$user"))
        } else {
            session.search_path.contains("$user")
        };
        let key = CacheKeyRef {
            sql,
            search_path: &session.search_path,
            user: user_dependent.then_some(&*session.user),
            profile: profile.hash,
            settings_epoch: settings.epoch,
            schema_epoch: database.schema_epoch,
        };

        let cache = self.cache.load();
        if let Some(decision) = cache.get(key) {
            return decision;
        }

        let search_path = if session.search_path.is_empty() {
            database.catalog.search_path.join(",")
        } else {
            session.search_path.to_string()
        };
        let search_path = parse_search_path(&search_path, &session.user);

        let ctx = Context {
            catalog: &database.catalog,
            assignments: &database.assignments,
            policies: &settings.policies,
            profile,
            search_path,
        };

        // Statements with literals: analyze their shape once, then render.
        // Rendered decisions aren't cached by text: statements with literals
        // rarely repeat, and PgDog only asks again for a prepared statement
        // when the generation changes.
        if let Some(literals) = shape::literals(sql) {
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
                        outcome_decision(outcome, settings, &session.user, sql, shadow),
                        literals.values.len(),
                    );
                    if let Some(shape) = &shape {
                        shapes.put(shape_key, shape.clone());
                    }
                    shape
                }
            };
            if let Some(decision) = shape.and_then(|shape| shape.render(&literals.values)) {
                return decision;
            }
        }

        let decision = outcome_decision(analyze(sql, &ctx), settings, &session.user, sql, shadow);
        cache.put(key, decision.clone());
        decision
    }
}

/// Decision for an analysis outcome, logged.
fn outcome_decision(
    outcome: Outcome,
    settings: &Settings,
    user: &str,
    original: &str,
    shadow: bool,
) -> Decision {
    match outcome {
        Outcome::Unchanged { raw, results, .. } => {
            if !raw.is_empty() {
                info!(
                    "[pgdog_mask] user \"{}\" searched raw values of {:?}",
                    user, raw
                );
            }
            log_decision(
                user,
                original,
                "",
                Decision::Continue(settings.results(&results)),
                shadow,
            )
        }
        Outcome::Rewritten {
            sql,
            masked,
            raw,
            results,
            ..
        } => {
            if !raw.is_empty() {
                info!(
                    "[pgdog_mask] user \"{}\" searched raw values of {:?}",
                    user, raw
                );
            }
            log_decision(
                user,
                original,
                &rewrite_what(&masked),
                Decision::Rewrite(sql, settings.results(&results)),
                shadow,
            )
        }
        Outcome::Blocked { reason } => {
            log_decision(user, original, "", Decision::Block(reason), shadow)
        }
    }
}

/// Deny a statement. Until a database's schema is loaded, masked users get a
/// retryable error.
fn denied(reason: String) -> Deny {
    if reason.starts_with("masking schema") {
        Deny::new(
            SqlState::new(CANNOT_CONNECT_NOW).expect("valid SQLSTATE"),
            reason,
        )
    } else {
        Deny::insufficient_privilege(reason)
    }
}

/// What a rewrite masked, for its log message.
fn rewrite_what(masked: &BTreeSet<String>) -> String {
    format!("masked {masked:?}")
}

/// Log a decision. Statements are logged normalized, with literals replaced by
/// placeholders, so searched values never end up in logs. Rewrites and result
/// masks apply to every statement of masked users and are logged at debug,
/// except in shadow mode, where logging them is the point.
fn log_decision(user: &str, sql: &str, what: &str, decision: Decision, shadow: bool) -> Decision {
    let Some(level) = log_level(&decision, shadow) else {
        return decision;
    };
    if level == Level::DEBUG && !enabled!(Level::DEBUG) {
        return decision;
    }
    let message = decision_message(user, sql, what, &decision, shadow);
    match level {
        Level::WARN => warn!("{message}"),
        Level::INFO => info!("{message}"),
        _ => debug!("{message}"),
    }
    decision
}

/// The level a decision is logged at, `None` if it isn't logged.
fn log_level(decision: &Decision, shadow: bool) -> Option<Level> {
    match decision {
        Decision::Continue(results) if results.is_empty() => None,
        Decision::Block(_) => Some(Level::WARN),
        _ if shadow => Some(Level::INFO),
        _ => Some(Level::DEBUG),
    }
}

/// What [`log_decision`] logs.
fn decision_message(
    user: &str,
    sql: &str,
    what: &str,
    decision: &Decision,
    shadow: bool,
) -> String {
    let prefix = if shadow {
        "[pgdog_mask] (shadow)"
    } else {
        "[pgdog_mask]"
    };
    match decision {
        Decision::Continue(results) => {
            let verb = if shadow { "would mask" } else { "masked" };
            format!(
                "{prefix} {verb} results for user \"{user}\": {}: {}",
                results.summary(),
                normalized(sql)
            )
        }
        Decision::Rewrite(_, results) => {
            let verb = if shadow { "would rewrite" } else { "rewrote" };
            let results = if results.is_empty() {
                String::new()
            } else {
                format!(", results: {}", results.summary())
            };
            format!(
                "{prefix} {verb} statement for user \"{user}\", {what}{results}: {}",
                normalized(sql)
            )
        }
        Decision::Block(reason) => format!(
            "{prefix} blocked statement for user \"{user}\": {reason} [{what}{}]",
            normalized(sql)
        ),
    }
}

/// The statement with literals replaced by placeholders.
fn normalized(sql: &str) -> String {
    if sql.is_empty() {
        return String::new();
    }
    // Normalizing deparses the statement, which some invalid ones crash.
    match pg_raw_parse::parse(sql) {
        Ok(parsed) if parsed.iter().all(|stmt| deparsable(stmt.stmt())) => (),
        Ok(_) => return "<statement with invalid COPY options>".to_owned(),
        Err(_) => return "<statement could not be parsed>".to_owned(),
    }
    match pg_raw_parse::normalize::normalize_str(sql) {
        Ok(normalized) => normalized.as_str().to_owned(),
        Err(_) => "<statement could not be parsed>".to_owned(),
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use pgdog_plugin::{ErrorField, TransformColumn, Value, redact::field, types::Format};

    use super::*;
    use crate::analyzer::test::proxy::{PROXY_CONFIG, proxy_registry, rows};
    use crate::analyzer::test::{CONFIG, catalog};
    use crate::catalog::Catalog;
    use crate::proxy::{Datum, Options, ProxyMask};

    fn session(user: &str) -> Session<'_> {
        Session::new(user.into(), "db".into())
    }

    fn engine(config: &str) -> Engine {
        engine_with(config, Registry::default(), catalog())
    }

    /// An engine with this configuration and these proxy masks, and the
    /// catalog of database "db" loaded.
    fn engine_with(config: &str, registry: Registry, catalog: Catalog) -> Engine {
        let engine = Engine::with_registry(Config::from_toml(config).unwrap(), registry).unwrap();
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

    fn decide(engine: &Engine, user: &str, sql: &str) -> Decision {
        let settings = engine.settings.load();
        let profile = settings.profile(user, "db");
        engine.decide(&session(user), sql, &settings, &profile)
    }

    #[test]
    fn test_decisions() {
        let engine = engine(CONFIG);
        assert!(matches!(
            decide(&engine, "anonymous", "SELECT ssn FROM users"),
            Decision::Rewrite(..)
        ));
        assert!(matches!(
            decide(&engine, "anonymous", "SELECT id FROM orders"),
            Decision::Continue(results) if results.is_empty()
        ));

        // Deterministic: PgDog relies on it for prepared statements.
        assert_eq!(
            decide(&engine, "anonymous", "SELECT ssn FROM users"),
            decide(&engine, "anonymous", "SELECT ssn FROM users"),
        );
    }

    #[test]
    fn test_function_calls() {
        let engine = engine(CONFIG);
        assert!(matches!(
            engine.function_call(&session("anonymous"), 1234),
            Access::Deny(_)
        ));
        assert_eq!(engine.function_call(&session("admin"), 1234), Access::Allow);
    }

    #[test]
    fn test_generation() {
        let engine = engine(CONFIG);
        let first = engine.generation();
        engine.apply(Config::from_toml(CONFIG).unwrap()).unwrap();
        let second = engine.generation();
        assert_ne!(first, second, "new settings");
        engine.catalog("db", &pgdog_plugin::Catalog::default());
        assert_ne!(second, engine.generation(), "new catalog");
    }

    #[test]
    fn test_logged_statements_have_no_literals() {
        let logged = normalized("SELECT id FROM users WHERE ssn = '123-45-6789' AND id = 42");
        assert!(!logged.contains("123-45-6789"), "{logged}");
        assert!(!logged.contains("42"), "{logged}");
        assert!(logged.contains("ssn = $1"), "{logged}");
    }

    /// Decisions are logged with the statement normalized, which deparses
    /// it: COPY options the deparser can't print would crash the process.
    #[test]
    fn test_invalid_copy_options_never_deparsed() {
        let statements = [
            "COPY users TO STDOUT WITH (delimiter)",
            "COPY orders FROM STDIN WITH (delimiter)",
            "COPY orders TO '/tmp/x' WITH (format)",
            "SELECT ssn FROM users; COPY orders TO STDOUT WITH (null)",
        ];
        for sql in statements {
            assert_eq!(normalized(sql), "<statement with invalid COPY options>");
        }

        let shadow = CONFIG.replacen("[general]", "[general]\nmode = \"shadow\"", 1);
        let proxy = || engine_with(PROXY_CONFIG, proxy_registry(), catalog());
        for (engine, user, denied) in [
            (engine(CONFIG), "anonymous", true),
            (engine(CONFIG), "bob", true),
            (engine(&shadow), "anonymous", false),
            (proxy(), "engineer", true),
        ] {
            for sql in statements {
                let verdict = engine.statement(&session(user), sql);
                assert_eq!(matches!(verdict, Verdict::Deny(_)), denied, "{user}: {sql}");
            }
        }
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
        cache.put(key, Decision::Continue(Results::default()));
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
        );
        let second = decide(
            &engine,
            "anonymous",
            "SELECT ssn FROM users WHERE id = 2 AND name = 'it''s'",
        );
        let (Decision::Rewrite(a, _), Decision::Rewrite(b, _)) = (first, second) else {
            panic!("rewrites");
        };
        assert!(a.ends_with("WHERE id = 1 AND name = 'a'"), "{a}");
        assert!(b.ends_with("WHERE id = 2 AND name = 'it''s'"), "{b}");

        // One shape analyzed; rendered statements aren't cached by text.
        let shapes = engine.shapes.load();
        let entries: usize = shapes.shards.iter().map(|s| s.read().len()).sum();
        assert_eq!(entries, 1);
        let cache = engine.cache.load();
        let entries: usize = cache.shards.iter().map(|s| s.read().len()).sum();
        assert_eq!(entries, 0, "statements with literals aren't cached by text");

        // Statements without literals are.
        decide(&engine, "anonymous", "SELECT ssn FROM users WHERE id = $1");
        let entries: usize = cache.shards.iter().map(|s| s.read().len()).sum();
        assert_eq!(entries, 1);

        // Blocks apply to every statement of the shape.
        for id in [1, 2] {
            assert!(matches!(
                decide(
                    &engine,
                    "anonymous",
                    &format!("SELECT my_func({id}) FROM users")
                ),
                Decision::Block(_)
            ));
        }
    }

    #[test]
    fn test_missing_schema_blocks() {
        let engine = Engine::new(Config::from_toml(CONFIG).unwrap()).unwrap();
        let Decision::Block(reason) = decide(&engine, "anonymous", "SELECT 1") else {
            panic!("blocked");
        };
        assert!(reason.starts_with("masking schema"), "{reason}");
        let Verdict::Deny(deny) = engine.statement(&session("anonymous"), "SELECT 1") else {
            panic!("denied");
        };
        assert_eq!(deny.sqlstate.as_str(), CANNOT_CONNECT_NOW);
    }

    #[test]
    fn test_modes() {
        let shadow =
            engine(&format!("{CONFIG}\n").replacen("[general]", "[general]\nmode = \"shadow\"", 1));
        assert_eq!(
            shadow.statement(&session("anonymous"), "SELECT ssn FROM users"),
            Verdict::Allow
        );

        let enforce = engine(CONFIG);
        assert!(matches!(
            enforce.statement(&session("anonymous"), "SELECT ssn FROM users"),
            Verdict::Rewrite { .. }
        ));

        // Exempt users are never analyzed.
        assert_eq!(
            enforce.statement(&session("admin"), "SELECT * FROM unknown_table"),
            Verdict::Allow
        );
    }

    #[test]
    fn test_redact_error() {
        let fields = [
            ErrorField::new(field::SQLSTATE, "23514".into()),
            ErrorField::new(field::MESSAGE, "check".into()),
            ErrorField::new(field::DETAIL, "Failing row contains (1, secret).".into()),
        ];
        let error = ErrorFields::new(false, &fields);

        let enforce = engine(CONFIG);
        assert_eq!(
            enforce.redact_error(&session("anonymous"), &error),
            Redaction::Replace(vec![
                (field::SQLSTATE, "23514".into()),
                (field::MESSAGE, "check".into())
            ])
        );
        // Exempt users keep DETAIL.
        assert_eq!(
            enforce.redact_error(&session("admin"), &error),
            Redaction::Keep
        );
        // Nothing to remove.
        let error = ErrorFields::new(false, &fields[..2]);
        assert_eq!(
            enforce.redact_error(&session("anonymous"), &error),
            Redaction::Keep
        );

        let disabled =
            engine(&CONFIG.replacen("[general]", "[general]\nscrub_error_detail = false", 1));
        let error = ErrorFields::new(false, &fields);
        assert_eq!(
            disabled.redact_error(&session("anonymous"), &error),
            Redaction::Keep
        );
    }

    /// Upper-cases text.
    struct Upper;

    impl ProxyMask for Upper {
        fn accepts(&self, _data_type: &str) -> bool {
            true
        }

        fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
            match value {
                Datum::Text(text) => Ok(Datum::Text(text.to_uppercase())),
                _ => Err(MaskError::new("not text")),
            }
        }
    }

    /// Returns values unchanged, and may block.
    struct Blocking;

    impl ProxyMask for Blocking {
        fn accepts(&self, _data_type: &str) -> bool {
            true
        }

        fn blocking(&self) -> bool {
            true
        }

        fn mask(&self, value: Datum) -> Result<Datum, MaskError> {
            Ok(value)
        }
    }

    /// Mask `values` with each of `masks`, as PgDog batches them.
    fn mask_rows(
        engine: &Engine,
        masks: &[ColumnTransform],
        format: Format,
        values: &[Value<'_>],
    ) -> Result<TransformOutput, MaskError> {
        let columns: Vec<_> = masks
            .iter()
            .map(|mask| TransformColumn::new(mask, format, values))
            .collect();
        let batch = TransformBatch::new(values.len() as u32, &columns);
        let mut out = TransformOutput::default();
        engine.mask_rows(&batch, &mut out).map(|_| out)
    }

    #[test]
    fn test_proxy_masks() {
        const CONFIG: &str = r#"
[[policies]]
name = "ssn"
data_type = "character varying"
mask = "proxy"
proxy = "test.upper"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"
"#;
        let mut registry = Registry::default();
        registry.register("test.upper", |_: &Options| Ok(Upper));
        let engine = engine_with(CONFIG, registry, catalog());

        let Verdict::Rewrite { sql, columns, .. } =
            engine.statement(&session("anonymous"), "SELECT id, ssn FROM users")
        else {
            panic!("rewrite");
        };
        assert_eq!(sql, "SELECT id, ssn FROM users");
        assert_eq!(columns.len(), 1);
        let mask = columns[0];
        assert_eq!((mask.column, mask.type_oid), (1, 1043));

        let values = [Value::new(Some(b"abc")), Value::new(None)];
        for format in [Format::Text, Format::Binary] {
            let out = mask_rows(&engine, &[mask], format, &values).unwrap();
            assert_eq!(out.len(), 2);
            assert!(format!("{out:?}").contains("[65, 66, 67]"), "{out:?}");
        }

        // A reload doesn't invalidate mask IDs already handed out: statements
        // prepared before it keep masking with them.
        engine.apply(Config::from_toml(CONFIG).unwrap()).unwrap();
        let out = mask_rows(&engine, &[mask], Format::Text, &values).unwrap();
        assert!(format!("{out:?}").contains("[65, 66, 67]"), "{out:?}");
        let Verdict::Rewrite { columns, .. } =
            engine.statement(&session("anonymous"), "SELECT ssn FROM users")
        else {
            panic!("rewrite");
        };
        assert_ne!(
            columns[0].transform, mask.transform,
            "new settings, new mask IDs"
        );
        assert!(mask_rows(&engine, &columns, Format::Text, &values).is_ok());
    }

    /// Engine verdicts for proxy-masked results (X2, X7, X9).
    #[test]
    fn test_proxy_results_verdicts() {
        let engine = engine_with(PROXY_CONFIG, proxy_registry(), catalog());
        let engineer = session("engineer");

        // Nothing to mask or redact.
        assert_eq!(
            engine.statement(&engineer, "SELECT id FROM orders"),
            Verdict::Allow
        );

        // A1: the original SQL, with a proxy mask.
        assert_eq!(
            engine.statement(&engineer, "SELECT ssn FROM users"),
            Verdict::transform(
                "SELECT ssn FROM users",
                vec![ColumnTransform::new(0, TransformId(0), 1043)]
            )
        );

        // S4: each statement's masks in its own result.
        let sql =
            "UPDATE users SET name = 'x' WHERE id = 1 RETURNING ssn; SELECT upper(ssn) FROM users";
        let verdict = engine.statement(&engineer, sql);
        assert_eq!(
            verdict,
            Verdict::transform(
                sql,
                vec![
                    ColumnTransform::new(0, TransformId(0), 1043),
                    ColumnTransform::null(0).in_result(1)
                ]
            )
            .redact_errors(true)
        );
        let Verdict::Rewrite { columns, .. } = verdict else {
            panic!("rewrite");
        };
        let null = columns[1];
        assert!(null.is_null());
        assert_eq!((null.transform, null.type_oid), (TransformId::NULL, 0));
        let pairs: HashSet<_> = columns.iter().map(|m| (m.result, m.column)).collect();
        assert_eq!(pairs.len(), columns.len(), "one mask per result column");

        // Masks that may block say so; NULL masks never do: PgDog applies them.
        let mut registry = proxy_registry();
        registry.register("test.hmac", |_: &Options| Ok(Blocking));
        let blocking = engine_with(PROXY_CONFIG, registry, catalog());
        assert_eq!(
            blocking.statement(&engineer, "SELECT ssn, upper(ssn) FROM users"),
            Verdict::transform(
                "SELECT ssn, upper(ssn) FROM users",
                vec![
                    ColumnTransform::new(0, TransformId(0), 1043).blocking(),
                    ColumnTransform::null(1)
                ]
            )
            .redact_errors(true)
        );
        assert_eq!(
            blocking.statement(&engineer, "SELECT mrn FROM patients"),
            Verdict::transform(
                "SELECT mrn FROM patients",
                vec![ColumnTransform::new(0, TransformId(1), 25)]
            )
        );
    }

    /// X1: a statement that only computes on proxy-masked columns is sent as
    /// is, with its errors redacted. So is one reading a view queried like a
    /// table whose definition computes on masked columns, whatever the user's
    /// masks: PgDog redacts without result masks too.
    #[test]
    fn test_redaction_only_rewrite() {
        let engine = engine_with(PROXY_CONFIG, proxy_registry(), catalog());
        let sql = "SELECT id FROM users WHERE ssn = $1";
        assert_eq!(
            engine.statement(&session("engineer"), sql),
            Verdict::transform(sql, vec![]).redact_errors(true)
        );
        let sql = "SELECT id FROM err_sb";
        assert_eq!(
            engine.statement(&session("analyst"), sql),
            Verdict::transform(sql, vec![]).redact_errors(true)
        );
    }

    /// X3: result masks are logged at info in shadow mode, at debug otherwise.
    #[test]
    fn test_proxy_decision_logs() {
        let shadow = engine_with(
            &PROXY_CONFIG.replacen("[general]", "[general]\nmode = \"shadow\"", 1),
            proxy_registry(),
            catalog(),
        );
        let log = |sql: &str, shadow_mode: bool| {
            let decision = decide(&shadow, "engineer", sql);
            log_level(&decision, shadow_mode).map(|level| {
                let message = decision_message("engineer", sql, "", &decision, shadow_mode);
                (level, message)
            })
        };

        let computed = "SELECT upper(ssn) FROM users";
        assert_eq!(
            log(computed, true),
            Some((
                Level::INFO,
                "[pgdog_mask] (shadow) would mask results for user \"engineer\": 0 proxy, 1 NULL, errors redacted: yes: SELECT upper(ssn) FROM users".into()
            ))
        );
        assert_eq!(
            log(computed, false),
            Some((
                Level::DEBUG,
                "[pgdog_mask] masked results for user \"engineer\": 0 proxy, 1 NULL, errors redacted: yes: SELECT upper(ssn) FROM users".into()
            ))
        );
        assert_eq!(
            log("SELECT ssn FROM users", true),
            Some((
                Level::INFO,
                "[pgdog_mask] (shadow) would mask results for user \"engineer\": 1 proxy, 0 NULL, errors redacted: no: SELECT ssn FROM users".into()
            ))
        );
        assert_eq!(log("SELECT id FROM orders", true), None);
        assert_eq!(log("SELECT id FROM orders", false), None);

        // Rewrites say which SQL-masked columns they rewrote (proxy-masked
        // ones aren't), and how their results are masked; literals never show.
        let sql = "SELECT * FROM users WHERE ssn = '123-45-6789'";
        let decision = decide(&shadow, "engineer", sql);
        let settings = shadow.settings.load();
        let profile = settings.profile("engineer", "db");
        let databases = shadow.databases.load();
        let database = &databases["db"];
        let ctx = Context {
            catalog: &database.catalog,
            assignments: &database.assignments,
            policies: &settings.policies,
            profile: &profile,
            search_path: vec!["public".into()],
        };
        let Some(Outcome::Rewritten { masked, .. }) = analyzer::analyze_shape(sql, &ctx) else {
            panic!("a rewrite");
        };
        assert_eq!(log_level(&decision, true), Some(Level::INFO));
        assert_eq!(
            decision_message("engineer", sql, &rewrite_what(&masked), &decision, true),
            "[pgdog_mask] (shadow) would rewrite statement for user \"engineer\", masked {\"public.users.email\"}, results: 1 proxy, 0 NULL, errors redacted: yes: SELECT * FROM users WHERE ssn = $1"
        );
        let (level, message) = log("UPDATE users SET name = ssn WHERE id = 7", false).unwrap();
        assert_eq!(level, Level::WARN);
        assert!(
            message.contains("blocked statement for user \"engineer\""),
            "{message}"
        );
        assert!(!message.contains(" 7"), "{message}");
    }

    /// Shadow mode never changes what runs.
    #[test]
    fn test_shadow_mode_allows() {
        let shadow = engine_with(
            &PROXY_CONFIG.replacen("[general]", "[general]\nmode = \"shadow\"", 1),
            proxy_registry(),
            catalog(),
        );
        for sql in [
            "SELECT upper(ssn) FROM users",
            "SELECT ssn FROM users",
            "UPDATE users SET name = ssn WHERE id = 1",
        ] {
            assert_eq!(
                shadow.statement(&session("engineer"), sql),
                Verdict::Allow,
                "{sql}"
            );
        }
    }

    /// PgDog applies NULL masks itself; one passed to `mask_rows` anyway
    /// still comes out NULL.
    #[test]
    fn test_mask_rows_null_defensive() {
        let engine = engine_with(PROXY_CONFIG, proxy_registry(), catalog());
        let values = [
            Value::new(Some(b"123-45-6789")),
            Value::new(None),
            Value::new(Some(b"x")),
        ];
        let masks = [
            ColumnTransform::null(0),
            ColumnTransform::new(1, TransformId(0), 1043),
        ];
        let out = mask_rows(&engine, &masks, Format::Text, &values).unwrap();
        assert_eq!(out.len(), 6);
        let debug = format!("{out:?}");
        assert!(
            debug.contains("lengths: [-1, -1, -1, 11, -1, 1]"),
            "{debug}"
        );
    }

    /// X13: users with proxy masks lose DETAIL even when the scrub is off.
    #[test]
    fn test_detail_scrub_forced_for_proxy_users() {
        let engine = engine_with(
            &PROXY_CONFIG.replacen("[general]", "[general]\nscrub_error_detail = false", 1),
            proxy_registry(),
            catalog(),
        );
        let fields = [
            ErrorField::new(field::SQLSTATE, "23514".into()),
            ErrorField::new(field::MESSAGE, "check".into()),
            ErrorField::new(field::DETAIL, "Failing row contains (1, secret).".into()),
        ];
        let error = ErrorFields::new(false, &fields);
        assert_eq!(
            engine.redact_error(&session("engineer"), &error),
            Redaction::Replace(vec![
                (field::SQLSTATE, "23514".into()),
                (field::MESSAGE, "check".into())
            ])
        );
        // SQL masks only: the setting applies.
        assert_eq!(
            engine.redact_error(&session("analyst"), &error),
            Redaction::Keep
        );
        assert_eq!(
            engine.redact_error(&session("admin"), &error),
            Redaction::Keep
        );
    }

    /// X10: decisions depend only on the session and the SQL, so PgDog can
    /// ask again at any time: every corpus row decided twice, by a fresh
    /// engine, and with other literals, gets the same decision.
    #[test]
    fn test_proxy_determinism() {
        // The decision with literals as placeholders, comparable across literals.
        let shaped = |decision: Decision| match decision {
            Decision::Rewrite(sql, results) => Decision::Rewrite(normalized(&sql), results),
            other => other,
        };

        let mut failures = vec![];
        let mut changed = 0;
        for row in rows() {
            let engine = || engine_with(&row.config, proxy_registry(), (row.catalog)());
            let first = engine();
            let decision = decide(&first, row.user, row.sql);
            let again = decide(&first, row.user, row.sql);
            let fresh = decide(&engine(), row.user, row.sql);
            if decision != again || decision != fresh {
                failures.push(format!(
                    "{} {:?}\n    {decision:?}\n    {again:?}\n    {fresh:?}",
                    row.id, row.sql
                ));
                continue;
            }

            let Some(literals) = shape::literals(row.sql) else {
                continue;
            };
            let values: Vec<String> = literals.values.iter().map(|v| other_literal(v)).collect();
            let other = shape::Template::new(&literals.shape, values.len())
                .and_then(|template| template.render(&values))
                .expect("render the shape with other literals");
            changed += 1;
            let decided = decide(&engine(), row.user, &other);
            if shaped(decided.clone()) != shaped(decision.clone()) {
                failures.push(format!(
                    "{} {:?} with other literals: {other:?}\n    {decision:?}\n    {decided:?}",
                    row.id, row.sql
                ));
            }
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
        assert!(changed > 90, "most of the corpus has literals: {changed}");
    }

    /// Another literal of the same kind, as the deparser writes literals.
    fn other_literal(value: &str) -> String {
        if let Some(text) = value.strip_prefix('\'') {
            return format!("'z{text}");
        }
        match value {
            "true" => "false".into(),
            "false" => "true".into(),
            _ => match value.parse::<i64>() {
                // Same sign: rendering parenthesizes negative literals.
                Ok(n) if n < 0 => (n - 1).to_string(),
                Ok(n) => (n + 1).to_string(),
                Err(_) => value.into(),
            },
        }
    }
}
