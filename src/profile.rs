//! Masking profiles: which mask each policy applies for a given user.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use parking_lot::RwLock;
use pg_raw_parse::{Owned, StmtList};
use regex::Regex;
use std::sync::Arc;
use tracing::error;

use crate::analyzer::lineage::{Lineage, view_lineage, view_relations};
use crate::catalog::{Catalog, Relation, RelationKind};
use crate::config::{Config, Error, General, MaskKind, Policy};
use crate::mask::{Mask, compile};
use crate::proxy::{Options, ProxyMask, Registry};
use crate::tags::{self, DatabaseTags};

/// A policy with its masks compiled.
#[derive(Debug)]
pub struct CompiledPolicy {
    pub policy: Policy,
    default: Mask,
    rules: Vec<(HashSet<String>, Mask)>,
}

/// A proxy mask built for a policy or rule.
#[derive(Clone)]
pub struct ProxyInstance {
    /// Name it's registered under.
    pub name: String,
    pub mask: Arc<dyn ProxyMask>,
}

impl std::fmt::Debug for ProxyInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyInstance({})", self.name)
    }
}

/// Name of the policy for columns whose tags can't be resolved to one policy.
pub const UNRESOLVED_TAGS: &str = "pgdog_mask.unresolved_tags";

/// Configuration with compiled policies.
#[derive(Debug)]
pub struct Policies {
    pub config: Config,
    /// The config's policies, in order, then the policy for unresolved tags.
    pub policies: Vec<CompiledPolicy>,
    /// Index of the policy for columns whose database tags have no `[[tags]]`
    /// entry, or map to several policies: they read as NULL for every user
    /// who isn't exempt.
    pub unresolved: usize,
    /// Proxy masks, referenced by index from compiled masks.
    pub proxies: Vec<ProxyInstance>,
    templates: Templates,
}

/// Mask expressions parsed once and copied into each statement that uses them.
#[derive(Default)]
struct Templates(RwLock<HashMap<String, Arc<Owned<StmtList>>>>);

impl std::fmt::Debug for Templates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Templates({})", self.0.read().len())
    }
}

/// Entries kept before the template cache is cleared. Templates are one per
/// (mask, column type), so this only matters for pathological configs.
const MAX_TEMPLATES: usize = 4096;

impl Policies {
    /// Compile policies, with the built-in proxy masks.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_registry(config, &Registry::default())
    }

    /// Compile policies, building proxy masks from `registry`.
    pub fn with_registry(config: Config, registry: &Registry) -> Result<Self, Error> {
        let mut proxies = vec![];
        let mut compile_spec = |policy: &Policy, spec: &crate::config::MaskSpec| {
            let mut mask = compile(policy, spec)?;
            if spec.kind == Some(MaskKind::Proxy) {
                let name = spec.proxy.as_deref().unwrap_or_default();
                let options = Options::new(spec.options.clone().unwrap_or_default());
                let instance =
                    registry
                        .create(name, &options, &policy.data_type)
                        .map_err(|err| {
                            Error::Invalid(format!("policy \"{}\": {}", policy.name, err.0))
                        })?;
                proxies.push(ProxyInstance {
                    name: name.to_owned(),
                    mask: instance,
                });
                if let Mask::Masked { proxy, .. } = &mut mask {
                    *proxy = Some(proxies.len() - 1);
                }
            }
            Ok::<_, Error>(mask)
        };

        let mut policies = vec![];
        for policy in &config.policies {
            let default = compile_spec(policy, &policy.mask_spec())?;
            let mut rules = vec![];
            for rule in &policy.rules {
                rules.push((
                    rule.roles.iter().cloned().collect(),
                    compile_spec(policy, &rule.mask_spec())?,
                ));
            }
            policies.push(CompiledPolicy {
                default,
                rules,
                policy: policy.clone(),
            });
        }

        // Fail closed on tags that can't be resolved: NULL for everyone but
        // exempt users, who see every column.
        let unresolved = policies.len();
        let policy: Policy = toml::from_str(&format!(
            "name = \"{UNRESOLVED_TAGS}\"\ndata_type = \"text\"\nmask = \"null\""
        ))
        .expect("valid policy");
        policies.push(CompiledPolicy {
            default: compile(&policy, &policy.mask_spec())?,
            rules: vec![],
            policy,
        });

        Ok(Self {
            config,
            policies,
            unresolved,
            proxies,
            templates: Templates::default(),
        })
    }

    /// `SELECT <expr>`, parsed. Mask expressions are the same for every statement,
    /// so they're parsed once and copied into statements.
    pub fn template(&self, expr: &str) -> Result<Arc<Owned<StmtList>>, pg_raw_parse::Error> {
        if let Some(parsed) = self.templates.0.read().get(expr) {
            return Ok(parsed.clone());
        }
        let parsed = Arc::new(pg_raw_parse::parse(&format!("SELECT {expr}"))?.into_inner());
        let mut templates = self.templates.0.write();
        if templates.len() >= MAX_TEMPLATES {
            templates.clear();
        }
        templates.insert(expr.to_owned(), parsed.clone());
        Ok(parsed)
    }

    /// Masking roles of a PgDog user.
    pub fn roles(&self, user: &str, database: &str) -> HashSet<&str> {
        self.config
            .users
            .iter()
            .filter(|u| u.name == user && u.database.as_deref().is_none_or(|db| db == database))
            .flat_map(|u| u.roles.iter().map(String::as_str))
            .collect()
    }

    /// Masks that apply to a user.
    pub fn profile(&self, user: &str, database: &str) -> Profile {
        let roles = self.roles(user, database);
        let mut hasher = DefaultHasher::new();

        let masks: Vec<Mask> = self
            .policies
            .iter()
            .map(|policy| {
                let selected = policy.rules.iter().position(|(rule_roles, _)| {
                    rule_roles.iter().any(|r| roles.contains(r.as_str()))
                });
                selected.hash(&mut hasher);
                match selected {
                    Some(index) => policy.rules[index].1.clone(),
                    None => policy.default.clone(),
                }
            })
            .collect();

        Profile {
            // The policy for unresolved tags masks everyone; users that no
            // configured policy masks are still exempt.
            exempt: !masks[..self.unresolved].iter().any(Mask::is_masked),
            hash: hasher.finish(),
            masks,
        }
    }
}

/// The mask of every policy for one user.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Mask per policy, in config order.
    pub masks: Vec<Mask>,
    /// Identifies the set of masks.
    pub hash: u64,
    /// No policy masks anything for this user.
    pub exempt: bool,
}

/// A masked column's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// Index into the config's policies.
    pub policy: usize,
    /// Columns bound to the policy's arguments.
    pub arguments: Vec<String>,
}

/// Masked columns of one database, by relation.
#[derive(Debug, Default)]
pub struct Assignments {
    relations: HashMap<(String, String), HashMap<String, Assignment>>,
    /// Columns of table-like views computed from masked columns. They can't be
    /// masked, so statements reading them are blocked for users who'd see any of
    /// these policies masked.
    derived: HashMap<(String, String), HashMap<String, BTreeSet<usize>>>,
    /// Views that are queried like tables instead of being inlined.
    table_like: HashSet<(String, String)>,
    /// Tags read from the database.
    pub database_tags: DatabaseTags,
}

/// Passes over table-like views, so views over materialized views see their masks.
const VIEW_PASSES: usize = 8;

impl Assignments {
    /// Resolve masked columns against a database's schema, from (in order of
    /// precedence) `[[masked_columns]]`, database tags and `[[classifiers]]`.
    /// Partitions inherit their parent's masked columns, and table-like views
    /// the masks of the columns they pass through.
    pub fn new(policies: &Policies, database: &str, catalog: &Catalog) -> Self {
        let mut this = Self::default();
        let config = &policies.config;
        let policy_index = |name: &str| config.policies.iter().position(|p| p.name == name);

        for column in &config.masked_columns {
            if column.database.as_deref().is_some_and(|db| db != database) {
                continue;
            }
            let Some(policy) = config
                .column_policy(column)
                .and_then(|policy| policy_index(&policy.name))
            else {
                continue;
            };

            for relation in catalog.relations() {
                let schema_matches = column
                    .schema
                    .as_deref()
                    .is_none_or(|s| s == relation.schema);
                let name_matches = column.name.as_deref().is_none_or(|n| n == relation.name);
                if schema_matches && name_matches && relation.column(&column.column).is_some() {
                    this.relations
                        .entry((relation.schema.clone(), relation.name.clone()))
                        .or_default()
                        .insert(
                            column.column.clone(),
                            Assignment {
                                policy,
                                arguments: column.arguments.clone(),
                            },
                        );
                }
            }
        }

        // Database tags add masks to columns the config doesn't mention.
        // A tag without a [[tags]] entry, or tags for several policies, fail
        // closed: the column reads as NULL.
        let database_tags = tags::database_tags(&config.general, catalog);
        for ((schema, table, column), tags) in &database_tags {
            if this.is_assigned(schema, table, column) {
                continue;
            }
            let unknown: Vec<_> = tags
                .iter()
                .filter(|tag| config.tag_policy(tag).is_none())
                .collect();
            let resolved: BTreeSet<usize> = tags
                .iter()
                .filter_map(|tag| config.tag_policy(tag).and_then(|p| policy_index(&p.name)))
                .collect();
            let policy = if !unknown.is_empty() {
                error!(
                    "[pgdog_mask] column {schema}.{table}.{column} has tags {unknown:?} with no [[tags]] entry; it reads as NULL for masked users"
                );
                policies.unresolved
            } else if resolved.len() > 1 {
                error!(
                    "[pgdog_mask] column {schema}.{table}.{column} has tags {tags:?} for different policies; it reads as NULL for masked users"
                );
                policies.unresolved
            } else {
                match resolved.first() {
                    Some(policy) => *policy,
                    None => continue,
                }
            };
            this.assign_missing(schema, table, column, policy);
        }

        let mut classified: BTreeMap<tags::ColumnKey, BTreeSet<usize>> = BTreeMap::new();
        for classifier in &config.classifiers {
            if classifier
                .database
                .as_deref()
                .is_some_and(|db| db != database)
            {
                continue;
            }
            let (Ok(regex), Some(policy)) = (
                Regex::new(&format!("^(?:{})$", classifier.column_regex)),
                config
                    .tag_policy(&classifier.tag)
                    .and_then(|p| policy_index(&p.name)),
            ) else {
                continue;
            };
            for relation in catalog.relations().filter(|r| {
                matches!(r.kind, RelationKind::Table | RelationKind::MaterializedView)
                    && classifier.schema.as_deref().is_none_or(|s| s == r.schema)
                    && classifier.name.as_deref().is_none_or(|n| n == r.name)
            }) {
                for column in relation.columns.iter().filter(|c| regex.is_match(&c.name)) {
                    classified
                        .entry((
                            relation.schema.clone(),
                            relation.name.clone(),
                            column.name.clone(),
                        ))
                        .or_default()
                        .insert(policy);
                }
            }
        }

        // Classifiers that match the same column with different policies fail
        // closed, like conflicting database tags.
        for ((schema, table, column), policies_matched) in &classified {
            if this.is_assigned(schema, table, column) {
                continue;
            }
            let policy = match policies_matched.iter().collect::<Vec<_>>().as_slice() {
                [policy] => **policy,
                _ => {
                    error!(
                        "[pgdog_mask] column {schema}.{table}.{column} matches classifiers for different policies; it reads as NULL for masked users"
                    );
                    policies.unresolved
                }
            };
            this.assign_missing(schema, table, column, policy);
        }

        this.database_tags = database_tags;
        this.inherit_partitions(catalog);
        this.views(&config.general, catalog);
        this
    }

    fn is_assigned(&self, schema: &str, table: &str, column: &str) -> bool {
        self.relations
            .get(&(schema.to_owned(), table.to_owned()))
            .is_some_and(|columns| columns.contains_key(column))
    }

    fn assign_missing(&mut self, schema: &str, table: &str, column: &str, policy: usize) {
        self.relations
            .entry((schema.to_owned(), table.to_owned()))
            .or_default()
            .entry(column.to_owned())
            .or_insert(Assignment {
                policy,
                arguments: vec![],
            });
    }

    /// Partitions inherit their ancestors' masked columns.
    fn inherit_partitions(&mut self, catalog: &Catalog) {
        for relation in catalog.relations() {
            let mut parent = relation.parent.clone();
            let mut depth = 0;
            while let Some(key) = parent
                && depth < 32
            {
                if let Some(inherited) = self.relations.get(&key).cloned() {
                    let entry = self
                        .relations
                        .entry((relation.schema.clone(), relation.name.clone()))
                        .or_default();
                    for (column, assignment) in inherited {
                        entry.entry(column).or_insert(assignment);
                    }
                }
                parent = catalog.get(&key.0, &key.1).and_then(|p| p.parent.clone());
                depth += 1;
            }
        }
    }

    /// Decide which views are queried like tables, and mask their columns by lineage.
    ///
    /// Materialized views hold their own copy of the data. `security_barrier` and
    /// `security_invoker` views would change meaning if inlined. Views with masked
    /// columns of their own keep them. With `inline_views` off, every view is
    /// treated like a table.
    fn views(&mut self, general: &General, catalog: &Catalog) {
        let explicit = self.relations.clone();
        let table_like: Vec<&Relation> = catalog
            .relations()
            .filter(|relation| match relation.kind {
                RelationKind::MaterializedView => true,
                RelationKind::View => {
                    !general.inline_views
                        || relation.option("security_barrier")
                        || relation.option("security_invoker")
                        || explicit.contains_key(&(relation.schema.clone(), relation.name.clone()))
                }
                _ => false,
            })
            .collect();
        self.table_like = table_like
            .iter()
            .map(|relation| (relation.schema.clone(), relation.name.clone()))
            .collect();

        let lineage: Vec<_> = table_like
            .iter()
            .map(|relation| view_lineage(catalog, relation))
            .collect();

        for _ in 0..VIEW_PASSES {
            let mut changed = false;
            for (relation, lineage) in table_like.iter().zip(&lineage) {
                let key = (relation.schema.clone(), relation.name.clone());
                let own = explicit.get(&key);
                let (assigned, derived) =
                    self.view_columns(catalog, relation, lineage.as_deref(), own);
                let same_assigned = self
                    .relations
                    .get(&key)
                    .map_or(assigned.is_empty(), |current| *current == assigned);
                let same_derived = self
                    .derived
                    .get(&key)
                    .map_or(derived.is_empty(), |current| *current == derived);
                if !same_assigned || !same_derived {
                    changed = true;
                    self.relations.insert(key.clone(), assigned);
                    self.derived.insert(key, derived);
                }
            }
            if !changed {
                break;
            }
        }

        self.relations.retain(|_, columns| !columns.is_empty());
        self.derived.retain(|_, columns| !columns.is_empty());
    }

    /// Masks of a table-like view's columns, from what they're computed from.
    fn view_columns(
        &self,
        catalog: &Catalog,
        relation: &Relation,
        lineage: Option<&[Lineage]>,
        own: Option<&HashMap<String, Assignment>>,
    ) -> (
        HashMap<String, Assignment>,
        HashMap<String, BTreeSet<usize>>,
    ) {
        let mut assigned = own.cloned().unwrap_or_default();
        let mut derived = HashMap::new();
        let unknown: BTreeSet<usize> = view_relations(catalog, relation)
            .iter()
            .filter_map(|(schema, name)| self.relation(schema, name))
            .flat_map(|columns| columns.values().map(|a| a.policy))
            .collect();

        for (i, column) in relation.columns.iter().enumerate() {
            if assigned.contains_key(&column.name) {
                continue;
            }
            match lineage.and_then(|lineage| lineage.get(i)) {
                Some(Lineage::Column((schema, table, base))) => {
                    let Some(assignment) = self.column(schema, table, base) else {
                        continue;
                    };
                    // Conditional masks need their argument columns in the view too.
                    let arguments: Option<Vec<String>> = assignment
                        .arguments
                        .iter()
                        .map(|argument| {
                            let source =
                                Lineage::Column((schema.clone(), table.clone(), argument.clone()));
                            lineage?
                                .iter()
                                .position(|l| *l == source)
                                .map(|j| relation.columns[j].name.clone())
                        })
                        .collect();
                    match arguments {
                        Some(arguments) => {
                            assigned.insert(
                                column.name.clone(),
                                Assignment {
                                    policy: assignment.policy,
                                    arguments,
                                },
                            );
                        }
                        None => {
                            derived
                                .insert(column.name.clone(), BTreeSet::from([assignment.policy]));
                        }
                    }
                }
                Some(Lineage::Derived(inputs)) => {
                    let policies: BTreeSet<usize> = inputs
                        .iter()
                        .filter_map(|(schema, table, base)| self.column(schema, table, base))
                        .map(|assignment| assignment.policy)
                        .collect();
                    if !policies.is_empty() {
                        derived.insert(column.name.clone(), policies);
                    }
                }
                Some(Lineage::Unknown) | None => {
                    if !unknown.is_empty() {
                        derived.insert(column.name.clone(), unknown.clone());
                    }
                }
            }
        }

        (assigned, derived)
    }

    /// Masked columns of a relation.
    pub fn relation(&self, schema: &str, name: &str) -> Option<&HashMap<String, Assignment>> {
        self.relations.get(&(schema.to_owned(), name.to_owned()))
    }

    pub fn column(&self, schema: &str, name: &str, column: &str) -> Option<&Assignment> {
        self.relation(schema, name)
            .and_then(|columns| columns.get(column))
    }

    /// Policies a table-like view column is computed from, if it can't be masked.
    pub fn derived(&self, schema: &str, name: &str, column: &str) -> Option<&BTreeSet<usize>> {
        self.derived
            .get(&(schema.to_owned(), name.to_owned()))
            .and_then(|columns| columns.get(column))
    }

    /// Policies of every masked or derived column of a relation.
    pub fn relation_policies(&self, schema: &str, name: &str) -> impl Iterator<Item = usize> {
        let key = (schema.to_owned(), name.to_owned());
        let assigned = self
            .relations
            .get(&key)
            .into_iter()
            .flat_map(|columns| columns.values().map(|a| a.policy));
        let derived = self
            .derived
            .get(&key)
            .into_iter()
            .flat_map(|columns| columns.values().flatten().copied());
        assigned.chain(derived).collect::<Vec<_>>().into_iter()
    }

    /// Is this view queried like a table?
    pub fn is_table_like(&self, schema: &str, name: &str) -> bool {
        self.table_like
            .contains(&(schema.to_owned(), name.to_owned()))
    }

    /// Relation names with masked columns, for temp table shadowing checks.
    pub fn relation_names(&self) -> impl Iterator<Item = &str> {
        self.relations.keys().map(|(_, name)| name.as_str())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const CONFIG: &str = r#"
[[users]]
name = "support"
roles = ["support"]

[[users]]
name = "admin"
roles = ["pii_admin"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "null"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies.rules]]
roles = ["support"]
mask = "partial"
keep_suffix = 4
"#;

    #[test]
    fn test_profiles() {
        let policies = Policies::new(Config::from_toml(CONFIG).unwrap()).unwrap();

        let admin = policies.profile("admin", "db");
        assert!(admin.exempt);

        let support = policies.profile("support", "db");
        assert!(!support.exempt);
        let anonymous = policies.profile("someone", "db");
        assert!(!anonymous.exempt);

        assert_ne!(support.hash, anonymous.hash);
        assert_ne!(support.masks, anonymous.masks);
        assert_eq!(policies.profile("support", "db").hash, support.hash);
    }

    const TAGS: &str = r#"
[general]
tag_source = "comment"

[[policies]]
name = "ssn"
data_type = "text"
mask = "null"

[[policies]]
name = "email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val END"

[[policies]]
name = "secret"
data_type = "text"
mask = "default"

[[tags]]
name = "pii.email"
policy = "email"

[[tags]]
name = "secret"
policy = "secret"

[[tags]]
name = "pii.ssn"
policy = "ssn"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"

[[masked_columns]]
name = "users"
column = "email"
policy = "email"
arguments = ["opted_in"]

[[classifiers]]
column_regex = "e_?mail_address|secret_.*"
tag = "secret"

# Conflicts with the classifier above on secret_key.
[[classifiers]]
column_regex = "secret_key"
tag = "pii.ssn"
"#;

    fn tagged_catalog() -> Catalog {
        use crate::catalog::Column;

        let mut ssn = Column::new("ssn", "text");
        // The config binding wins over the database tag.
        ssn.comment = Some("pgdog:tag=secret".into());
        let mut name = Column::new("name", "text");
        name.comment = Some("Full name. pgdog:tag=secret".into());
        let mut nickname = Column::new("nickname", "text");
        nickname.comment = Some("pgdog:tag=unknown".into());
        // Tags for two policies.
        let mut alias = Column::new("alias", "text");
        alias.comment = Some("pgdog:tag=secret,pii.ssn".into());
        let mut handle = Column::new("handle", "text");
        handle.comment = Some("pgdog:tag=pii.ssn pgdog:tag=pii.ssn".into());
        let users = Relation::new(
            "public",
            "users",
            RelationKind::Table,
            vec![
                Column::new("id", "bigint"),
                ssn,
                Column::new("email", "text"),
                Column::new("opted_in", "boolean"),
                name,
                nickname,
                alias,
                handle,
                Column::new("email_address", "text"),
                Column::new("secret_key", "text"),
                Column::new("emails", "text"),
            ],
        );

        let mut barrier = Relation::new(
            "public",
            "contacts",
            RelationKind::View,
            ["id", "mail", "opted", "ssn", "both"]
                .iter()
                .map(|c| Column::new(c, "text"))
                .collect(),
        );
        barrier.definition = Some(
            " SELECT users.id, users.email AS mail, users.opted_in AS opted, users.ssn, users.ssn || users.name AS both FROM public.users;".into(),
        );
        barrier.options = vec!["security_invoker=true".into()];

        // Conditional mask without its argument column.
        let mut emails = Relation::new(
            "public",
            "emails",
            RelationKind::MaterializedView,
            vec![Column::new("email", "text")],
        );
        emails.definition = Some(" SELECT users.email FROM public.users;".into());

        let mut inlined = Relation::new(
            "public",
            "ssns",
            RelationKind::View,
            vec![Column::new("ssn", "text")],
        );
        inlined.definition = Some(" SELECT users.ssn FROM public.users;".into());

        Catalog::new(vec![], vec![users, barrier, emails, inlined])
    }

    #[test]
    fn test_assignment_sources() {
        let policies = Policies::new(Config::from_toml(TAGS).unwrap()).unwrap();
        let assignments = Assignments::new(&policies, "db", &tagged_catalog());
        let policy = |table: &str, column: &str| {
            assignments
                .column("public", table, column)
                .map(|a| policies.policies[a.policy].policy.name.as_str())
        };

        assert_eq!(policy("users", "ssn"), Some("ssn"));
        assert_eq!(policy("users", "name"), Some("secret"));
        assert_eq!(policy("users", "email_address"), Some("secret"));
        assert_eq!(policy("users", "handle"), Some("ssn"), "the same tag twice");
        // Fail closed: an unknown tag, tags for different policies, and
        // classifiers for different policies.
        assert_eq!(policy("users", "nickname"), Some(UNRESOLVED_TAGS));
        assert_eq!(policy("users", "alias"), Some(UNRESOLVED_TAGS));
        assert_eq!(policy("users", "secret_key"), Some(UNRESOLVED_TAGS));
        // Classifiers match the whole name.
        assert_eq!(policy("users", "emails"), None);
        assert_eq!(policy("users", "id"), None);
        assert_eq!(
            assignments
                .database_tags
                .keys()
                .map(|(_, _, c)| c.as_str())
                .collect::<Vec<_>>(),
            ["alias", "handle", "name", "nickname", "ssn"]
        );

        // Unresolved tags read as NULL for masked users, and don't stop
        // exempt users from being exempt.
        let profile = policies.profile("anyone", "db");
        assert!(!profile.exempt);
        assert_eq!(
            profile.masks[policies.unresolved],
            crate::mask::Mask::Masked {
                template: "NULL".into(),
                raw_search: Default::default(),
                proxy: None,
            }
        );
        let none = Policies::new(
            Config::from_toml(
                r#"
[[users]]
name = "admin"
roles = ["admin"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "null"

[[policies.rules]]
roles = ["admin"]
mask = "none"
"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(none.profile("admin", "db").exempt);
        assert!(!none.profile("other", "db").exempt);

        // Without tag_source, comments are ignored.
        let config = TAGS.replace("tag_source = \"comment\"", "");
        let policies = Policies::new(Config::from_toml(&config).unwrap()).unwrap();
        let assignments = Assignments::new(&policies, "db", &tagged_catalog());
        assert!(assignments.column("public", "users", "name").is_none());
        assert!(assignments.database_tags.is_empty());
    }

    #[test]
    fn test_table_like_views() {
        let policies = Policies::new(Config::from_toml(TAGS).unwrap()).unwrap();
        let assignments = Assignments::new(&policies, "db", &tagged_catalog());

        assert!(assignments.is_table_like("public", "contacts"));
        assert!(assignments.is_table_like("public", "emails"));
        assert!(!assignments.is_table_like("public", "ssns"));

        // Passed-through columns inherit masks, with arguments renamed.
        let mail = assignments.column("public", "contacts", "mail").unwrap();
        assert_eq!(policies.config.policies[mail.policy].name, "email");
        assert_eq!(mail.arguments, ["opted"]);
        assert!(assignments.column("public", "contacts", "ssn").is_some());
        // Derived columns can't be masked.
        let both = assignments.derived("public", "contacts", "both").unwrap();
        assert_eq!(both.len(), 2);
        assert!(assignments.column("public", "contacts", "id").is_none());
        assert!(assignments.derived("public", "contacts", "id").is_none());

        // A conditional mask whose argument isn't in the view can't be applied.
        assert!(assignments.column("public", "emails", "email").is_none());
        assert!(assignments.derived("public", "emails", "email").is_some());

        // Inlined views have no masks of their own.
        assert!(assignments.relation("public", "ssns").is_none());
    }
}
