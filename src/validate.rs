//! Checks of a configuration against a database, for `pgdog-mask validate`.
//!
//! The plugin checks a configuration when it loads it, without a database:
//! the file's schema, policy/type compatibility, and that every template
//! parses and references only `val` and the policy's arguments. These checks
//! add what needs the database's catalog:
//!
//! - every SQL mask, prepared as `SELECT (<template>)::T FROM (SELECT NULL::T
//!   AS val) s LIMIT 0` for each type it's applied to, so type errors show up
//!   before a statement uses the mask ([`Validation::probes`], run by the
//!   caller);
//! - `[[masked_columns]]` and `[[classifiers]]` that match no column, and
//!   arguments that aren't bound to columns of the table;
//! - raw searches that make values easy to recover: range and pattern
//!   operators, and low-entropy types (`date`, `boolean`, enums).
use std::collections::HashMap;

use indexmap::IndexMap;
use regex::Regex;

use crate::catalog::{Catalog, Column, Relation, RelationKind};
use crate::config::{Config, MaskKind, MaskSpec, Policy};
use crate::mask::{Mask, SearchOp, TypeFamily, VALUE, castable, check_proxy, compile};
use crate::profile::{Assignments, Policies};
use crate::proxy::{Datum, MaskError, Options as ProxyOptions, ProxyMask, Registry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The plugin would refuse the configuration, or a mask fails when used.
    Error,
    /// Probably a mistake, or a deliberate risk worth reviewing.
    Warning,
    /// Something that wasn't checked.
    Note,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    pub fn note(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Note,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.severity, self.message)
    }
}

/// A SQL mask to prepare against the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The mask, e.g. `policy "ssn", rule 1 (roles support)`.
    pub mask: String,
    /// `SELECT (<template>)::T FROM (SELECT NULL::T AS val, ...) s LIMIT 0`.
    pub sql: String,
    /// What it's applied to: columns, or the policy's `data_type`.
    pub targets: Vec<String>,
}

impl Probe {
    /// The finding for a probe that failed to prepare.
    pub fn failed(&self, error: &str) -> Finding {
        let mut targets = self.targets.iter().take(3).cloned().collect::<Vec<_>>();
        if self.targets.len() > 3 {
            targets.push(format!("{} more", self.targets.len() - 3));
        }
        Finding::error(format!(
            "{} on {}: {error} (in {})",
            self.mask,
            targets.join(", "),
            self.sql
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Build proxy masks from their options, as the plugin does. Their keys
    /// must then be available, e.g. in `key_env` variables.
    pub proxy_masks: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { proxy_masks: true }
    }
}

#[derive(Debug, Default)]
pub struct Validation {
    pub findings: Vec<Finding>,
    /// SQL masks to prepare; each one that fails is a [`Probe::failed`] error.
    pub probes: Vec<Probe>,
}

impl Validation {
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }
}

/// A policy's masks: its default, then its rules.
fn masks(policy: &Policy) -> Vec<(String, MaskSpec)> {
    let mut masks = vec![(
        format!("policy \"{}\", default mask", policy.name),
        policy.mask_spec(),
    )];
    for (i, rule) in policy.rules.iter().enumerate() {
        masks.push((
            format!(
                "policy \"{}\", rule {} (roles {})",
                policy.name,
                i + 1,
                rule.roles.join(", ")
            ),
            rule.mask_spec(),
        ));
    }
    masks
}

/// Raw searches that make values easy to recover, for a mask on `data_type`.
fn raw_search_risks(mask: &str, data_type: &str, raw_search: &SqlSearch) -> Vec<String> {
    let mut risks = vec![];
    if raw_search.contains(&SearchOp::Range) {
        risks.push(format!(
            "{mask}: search = \"raw\" with range operators (<, >, BETWEEN) lets these users recover a value by binary search, in a few dozen statements"
        ));
    }
    if raw_search.contains(&SearchOp::Like) {
        risks.push(format!(
            "{mask}: search = \"raw\" with pattern operators (LIKE, ILIKE) lets these users recover a value one character at a time"
        ));
    }
    if !raw_search.is_empty() && low_entropy(data_type) {
        risks.push(format!(
            "{mask}: search = \"raw\" on {data_type} values lets these users find any value by trying each possible one with ="
        ));
    }
    risks
}

type SqlSearch = std::collections::HashSet<SearchOp>;

/// Types with few enough values to try them all.
fn low_entropy(data_type: &str) -> bool {
    matches!(
        TypeFamily::of(data_type),
        TypeFamily::Date | TypeFamily::Boolean
    )
}

/// Warnings that need only the configuration, logged by the plugin when it
/// loads one: raw searches with range or pattern operators, or on a policy
/// whose `data_type` is low-entropy.
pub fn config_warnings(config: &Config) -> Vec<String> {
    let mut warnings = vec![];
    for policy in &config.policies {
        for (mask, spec) in masks(policy) {
            if let Ok(Mask::Sql { raw_search, .. }) = compile(policy, &spec) {
                warnings.extend(raw_search_risks(&mask, &policy.data_type, &raw_search));
            }
        }
    }
    warnings
}

/// A SQL mask of a policy.
struct SqlMask {
    policy: usize,
    mask: String,
    template: String,
    raw_search: SqlSearch,
}

/// Stands in for proxy masks that aren't built, so the policies can be
/// resolved against the catalog. Never applied.
struct Unchecked;

impl ProxyMask for Unchecked {
    fn accepts(&self, _data_type: &str) -> bool {
        true
    }

    fn mask(&self, _value: Datum) -> Result<Datum, MaskError> {
        Err(MaskError::new("not built"))
    }
}

/// Check a configuration against a database's catalog. `database` is the
/// PgDog database name `[[masked_columns]]` and `[[classifiers]]` are matched
/// against, and `enums` the number of labels of each enum type, by OID.
pub fn validate(
    config: &Config,
    registry: &Registry,
    options: &Options,
    database: &str,
    catalog: &Catalog,
    enums: &HashMap<u32, usize>,
) -> Validation {
    let mut validation = Validation::default();
    let findings = &mut validation.findings;

    // Compile every mask, as the plugin does, but report every error.
    let mut sql_masks = vec![];
    let mut unbuilt = vec![];
    for (index, policy) in config.policies.iter().enumerate() {
        for (mask, spec) in masks(policy) {
            if spec.kind == Some(MaskKind::Proxy) {
                let name = match check_proxy(policy, &spec) {
                    Ok(name) => name,
                    Err(err) => {
                        findings.push(Finding::error(err.to_string()));
                        continue;
                    }
                };
                if !registry.contains(name) {
                    findings.push(Finding::note(format!(
                        "{mask}: proxy mask \"{name}\" isn't built in, so its options aren't checked"
                    )));
                    unbuilt.push(name.to_owned());
                } else if !options.proxy_masks {
                    unbuilt.push(name.to_owned());
                } else {
                    let proxy_options = ProxyOptions::new(spec.options.clone().unwrap_or_default());
                    if let Err(err) = registry.create(name, &proxy_options, &policy.data_type) {
                        findings.push(Finding::error(format!("{mask}: {}", err.0)));
                    }
                }
                continue;
            }
            match compile(policy, &spec) {
                Ok(Mask::Sql {
                    template,
                    raw_search,
                }) => {
                    for risk in raw_search_risks(&mask, &policy.data_type, &raw_search) {
                        findings.push(Finding::warning(risk));
                    }
                    sql_masks.push(SqlMask {
                        policy: index,
                        mask,
                        template,
                        raw_search,
                    });
                }
                Ok(_) => (),
                Err(err) => findings.push(Finding::error(err.to_string())),
            }
        }
    }

    check_masked_columns(config, database, catalog, findings);
    check_classifiers(config, database, catalog, findings);

    if validation.count(Severity::Error) > 0 {
        return validation;
    }

    // Resolve masked columns the way the plugin does, with tags and
    // classifiers, to prepare each mask for the types it's applied to.
    let mut registry = registry.clone();
    for name in unbuilt {
        registry.register(&name, |_: &ProxyOptions| Ok(Unchecked));
    }
    let policies = match Policies::with_registry(config.clone(), &registry) {
        Ok(policies) => policies,
        Err(err) => {
            validation.findings.push(Finding::error(err.to_string()));
            return validation;
        }
    };
    let assignments = Assignments::new(&policies, database, catalog);

    let mut probes: IndexMap<(String, String), Probe> = IndexMap::new();
    let mut probe = |mask: &SqlMask, sql: String, target: String| {
        probes
            .entry((mask.mask.clone(), sql.clone()))
            .or_insert_with(|| Probe {
                mask: mask.mask.clone(),
                sql,
                targets: vec![],
            })
            .targets
            .push(target);
    };

    // Each policy for its own data_type.
    for mask in &sql_masks {
        let policy = &config.policies[mask.policy];
        if policy.arguments.is_empty() {
            let sql = probe_sql(&mask.template, &policy.data_type, &policy.data_type, &[]);
            probe(mask, sql, format!("data_type {}", policy.data_type));
        }
    }

    // And for each column it masks. Partitions inherit their parent's masks
    // and views the masks of the columns they pass through, so they're left out.
    let mut relations: Vec<&Relation> = catalog
        .relations()
        .filter(|r| r.parent.is_none() && r.kind != RelationKind::View)
        .collect();
    relations.sort_by(|a, b| (&a.schema, &a.name).cmp(&(&b.schema, &b.name)));
    let mut bound = vec![false; config.policies.len()];
    for relation in relations {
        for column in &relation.columns {
            let Some(assignment) =
                assignments.column(&relation.schema, &relation.name, &column.name)
            else {
                continue;
            };
            let target = format!("{}.{}", relation.qualified_name(), column.name);
            if assignment.policy == policies.unresolved {
                let key = (
                    relation.schema.clone(),
                    relation.name.clone(),
                    column.name.clone(),
                );
                let reason = match assignments.database_tags.get(&key) {
                    Some(tags) => {
                        let tags: Vec<_> = tags.iter().map(|tag| format!("\"{tag}\"")).collect();
                        format!(
                            "its tags {} have no [[tags]] entry, or map to different policies",
                            tags.join(", ")
                        )
                    }
                    None => "[[classifiers]] for different policies match it".into(),
                };
                validation.findings.push(Finding::warning(format!(
                    "column {target}: {reason}, so it reads as NULL for every masked user"
                )));
                continue;
            }
            let policy = &config.policies[assignment.policy];
            let Some(arguments) = bind_arguments(
                policy,
                &assignment.arguments,
                relation,
                &target,
                &mut validation.findings,
            ) else {
                continue;
            };
            bound[assignment.policy] = true;

            let val_type = column_type(column, policy);
            let cast = if castable(&column.data_type) {
                column.data_type.as_str()
            } else {
                policy.data_type.as_str()
            };
            for mask in sql_masks.iter().filter(|m| m.policy == assignment.policy) {
                probe(
                    mask,
                    probe_sql(&mask.template, &val_type, cast, &arguments),
                    target.clone(),
                );
                if mask.raw_search.is_empty() {
                    continue;
                }
                if low_entropy(&column.data_type) && !low_entropy(&policy.data_type) {
                    validation.findings.push(Finding::warning(format!(
                        "{} on {target}: search = \"raw\" on {} values lets these users find any value by trying each possible one with =",
                        mask.mask, column.data_type
                    )));
                }
                if let Some(labels) = enums.get(&column.type_oid) {
                    validation.findings.push(Finding::warning(format!(
                        "{} on {target}: search = \"raw\" on enum {} lets these users find any value by trying each of its {labels} labels with =",
                        mask.mask, column.type_name
                    )));
                }
            }
        }
    }

    for mask in &sql_masks {
        let policy = &config.policies[mask.policy];
        if !policy.arguments.is_empty() && !bound[mask.policy] {
            validation.findings.push(Finding::note(format!(
                "{}: not prepared, since no column binds its arguments",
                mask.mask
            )));
        }
    }

    validation.probes = probes.into_values().collect();
    validation
}

/// Types of the columns bound to a policy's arguments, by argument name.
fn bind_arguments(
    policy: &Policy,
    bound: &[String],
    relation: &Relation,
    target: &str,
    findings: &mut Vec<Finding>,
) -> Option<Vec<(String, String)>> {
    if bound.len() < policy.arguments.len() {
        findings.push(Finding::error(format!(
            "column {target}: policy \"{}\" takes arguments ({}), but {} bound: bind them with \"arguments\" in its [[masked_columns]] entry",
            policy.name,
            policy.arguments.join(", "),
            match bound.len() {
                0 => "none are".to_owned(),
                1 => "1 is".to_owned(),
                n => format!("{n} are"),
            }
        )));
        return None;
    }
    if bound.len() > policy.arguments.len() {
        findings.push(Finding::warning(format!(
            "column {target}: policy \"{}\" takes {} arguments, so columns ({}) are ignored",
            policy.name,
            policy.arguments.len(),
            bound[policy.arguments.len()..].join(", ")
        )));
    }

    let mut arguments = vec![];
    for (name, column) in policy.arguments.iter().zip(bound) {
        match relation.column(column) {
            Some(column) => arguments.push((name.clone(), column_type(column, policy))),
            None => {
                findings.push(Finding::error(format!(
                    "column {target}: argument \"{name}\" of policy \"{}\" is bound to column \"{column}\", which {} doesn't have",
                    policy.name,
                    relation.qualified_name()
                )));
                return None;
            }
        }
    }
    Some(arguments)
}

/// A column's type, as SQL. The catalog qualifies types outside `pg_catalog`.
fn column_type(column: &Column, policy: &Policy) -> String {
    if !column.type_name.is_empty() {
        column.type_name.clone()
    } else if castable(&column.data_type) {
        column.data_type.clone()
    } else {
        policy.data_type.clone()
    }
}

/// The statement that prepares a mask: `val` and the arguments are typed NULLs,
/// and the mask is cast to the column's type, as in rewritten statements.
pub fn probe_sql(
    template: &str,
    val_type: &str,
    cast: &str,
    arguments: &[(String, String)],
) -> String {
    let mut columns = format!("NULL::{val_type} AS {VALUE}");
    for (name, data_type) in arguments {
        columns.push_str(&format!(", NULL::{data_type} AS {}", identifier(name)));
    }
    format!("SELECT ({template})::{cast} FROM (SELECT {columns}) s LIMIT 0")
}

/// Quote an identifier, so it matches the name exactly.
fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// `[[masked_columns]]` entries that match no column of the database.
fn check_masked_columns(
    config: &Config,
    database: &str,
    catalog: &Catalog,
    findings: &mut Vec<Finding>,
) {
    for column in &config.masked_columns {
        if column.database.as_deref().is_some_and(|db| db != database) {
            continue;
        }
        let in_schema = |relation: &&Relation| {
            column
                .schema
                .as_deref()
                .is_none_or(|schema| schema == relation.schema)
        };
        let target = [
            column.schema.as_deref(),
            column.name.as_deref().or(Some("*")),
        ]
        .into_iter()
        .flatten()
        .chain([column.column.as_str()])
        .collect::<Vec<_>>()
        .join(".");
        let entry = format!("[[masked_columns]] {target}");
        let has_column = |relation: &&Relation| relation.column(&column.column).is_some();

        let message = match &column.name {
            Some(name) => {
                let tables: Vec<&Relation> = catalog
                    .relations_named(name)
                    .iter()
                    .filter(in_schema)
                    .collect();
                if tables.is_empty() {
                    let table = [column.schema.as_deref(), Some(name.as_str())]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(".");
                    Some(format!("table {table} doesn't exist"))
                } else if !tables.iter().any(has_column) {
                    Some(format!(
                        "{} has no column \"{}\"",
                        tables[0].qualified_name(),
                        column.column
                    ))
                } else {
                    None
                }
            }
            None => {
                let tables: Vec<&Relation> = catalog.relations().filter(in_schema).collect();
                match &column.schema {
                    Some(schema) if tables.is_empty() => {
                        Some(format!("schema {schema} has no tables"))
                    }
                    _ if !tables.iter().any(has_column) => Some(format!(
                        "no table{} has a column \"{}\"",
                        column
                            .schema
                            .as_deref()
                            .map(|schema| format!(" in schema {schema}"))
                            .unwrap_or_default(),
                        column.column
                    )),
                    _ => None,
                }
            }
        };
        if let Some(message) = message {
            findings.push(Finding::warning(format!(
                "{entry}: {message} in database \"{database}\", so it masks nothing"
            )));
        }
    }
}

/// `[[classifiers]]` that match no column of the database.
fn check_classifiers(
    config: &Config,
    database: &str,
    catalog: &Catalog,
    findings: &mut Vec<Finding>,
) {
    for classifier in &config.classifiers {
        if classifier
            .database
            .as_deref()
            .is_some_and(|db| db != database)
        {
            continue;
        }
        let Ok(regex) = Regex::new(&format!("^(?:{})$", classifier.column_regex)) else {
            continue;
        };
        let matched = catalog
            .relations()
            .filter(|r| {
                matches!(r.kind, RelationKind::Table | RelationKind::MaterializedView)
                    && classifier.schema.as_deref().is_none_or(|s| s == r.schema)
                    && classifier.name.as_deref().is_none_or(|n| n == r.name)
            })
            .any(|r| r.columns.iter().any(|c| regex.is_match(&c.name)));
        if !matched {
            findings.push(Finding::warning(format!(
                "[[classifiers]] \"{}\" matches no column in database \"{database}\"",
                classifier.column_regex
            )));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn column(name: &str, data_type: &str, type_name: &str, type_oid: u32) -> Column {
        Column {
            type_name: type_name.into(),
            type_oid,
            ..Column::new(name, data_type)
        }
    }

    fn catalog() -> Catalog {
        Catalog::new(
            vec!["public".into()],
            vec![
                Relation::new(
                    "public",
                    "users",
                    RelationKind::Table,
                    vec![
                        column("id", "bigint", "bigint", 20),
                        column("ssn", "text", "text", 25),
                        column("dob", "date", "date", 1082),
                        column("mood", "USER-DEFINED", "public.mood", 16400),
                        column("opted_in", "boolean", "boolean", 16),
                        column("card", "character varying", "character varying", 1043),
                    ],
                ),
                Relation::new(
                    "public",
                    "user_ssns",
                    RelationKind::View,
                    vec![column("ssn", "text", "text", 25)],
                ),
            ],
        )
    }

    fn run(toml: &str) -> Validation {
        run_with(toml, &Options::default())
    }

    fn run_with(toml: &str, options: &Options) -> Validation {
        let config = Config::from_toml(toml).unwrap();
        let enums = [(16400, 3)].into();
        validate(
            &config,
            &Registry::default(),
            options,
            "pgdog",
            &catalog(),
            &enums,
        )
    }

    fn messages(validation: &Validation, severity: Severity) -> Vec<&str> {
        validation
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .map(|f| f.message.as_str())
            .collect()
    }

    #[test]
    fn test_probe_sql() {
        assert_eq!(
            probe_sql("left(val, 2)", "text", "text", &[]),
            "SELECT (left(val, 2))::text FROM (SELECT NULL::text AS val) s LIMIT 0"
        );
        assert_eq!(
            probe_sql(
                "CASE WHEN opted_in THEN val END",
                "text",
                "text",
                &[("opted_in".into(), "boolean".into())]
            ),
            "SELECT (CASE WHEN opted_in THEN val END)::text FROM (SELECT NULL::text AS val, NULL::boolean AS \"opted_in\") s LIMIT 0"
        );
    }

    #[test]
    fn test_probes() {
        let validation = run(r#"
[[policies]]
name = "ssn"
data_type = "text"
mask = "partial"
keep_suffix = 4

[[policies.rules]]
roles = ["admin"]
mask = "none"

[[policies.rules]]
roles = ["support"]
mask = "sql"
expression = "'***' || right(val, 4)"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"
"#);
        assert!(validation.findings.is_empty(), "{:?}", validation.findings);
        // Each SQL mask once for the policy's data_type, which is the column's
        // type too; `none` isn't prepared.
        let probes: Vec<_> = validation
            .probes
            .iter()
            .map(|p| (p.mask.as_str(), p.targets.clone()))
            .collect();
        assert_eq!(
            probes,
            [
                (
                    "policy \"ssn\", default mask",
                    vec!["data_type text".to_owned(), "public.users.ssn".to_owned()]
                ),
                (
                    "policy \"ssn\", rule 2 (roles support)",
                    vec!["data_type text".to_owned(), "public.users.ssn".to_owned()]
                ),
            ]
        );
        assert!(
            validation.probes[1]
                .sql
                .starts_with("SELECT ('***' || right(val, 4))::text FROM"),
            "{}",
            validation.probes[1].sql
        );
        let failed = validation.probes[0].failed("function left(integer) does not exist");
        assert_eq!(failed.severity, Severity::Error);
        assert!(
            failed.message.starts_with(
                "policy \"ssn\", default mask on data_type text, public.users.ssn: function left(integer) does not exist (in SELECT"
            ),
            "{failed}"
        );
    }

    #[test]
    fn test_probe_column_types() {
        // The column's type, not the policy's, as the rewriter casts to it.
        let validation = run(r#"
[[policies]]
name = "card"
data_type = "text"
mask = "default"

[[masked_columns]]
name = "users"
column = "card"
policy = "card"
"#);
        let sqls: Vec<_> = validation.probes.iter().map(|p| p.sql.as_str()).collect();
        assert_eq!(
            sqls,
            [
                "SELECT ('****')::text FROM (SELECT NULL::text AS val) s LIMIT 0",
                "SELECT ('****')::character varying FROM (SELECT NULL::character varying AS val) s LIMIT 0",
            ]
        );
    }

    #[test]
    fn test_arguments() {
        let policy = r#"
[[policies]]
name = "ssn"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val END"
"#;
        let validation = run(&format!(
            "{policy}
[[masked_columns]]
name = \"users\"
column = \"ssn\"
policy = \"ssn\"
arguments = [\"opted_in\"]
"
        ));
        assert!(validation.findings.is_empty(), "{:?}", validation.findings);
        // Arguments are typed by their columns, so only the column is prepared.
        assert_eq!(validation.probes.len(), 1);
        assert_eq!(
            validation.probes[0].sql,
            "SELECT (CASE WHEN opted_in THEN val END)::text FROM (SELECT NULL::text AS val, NULL::boolean AS \"opted_in\") s LIMIT 0"
        );

        // Not bound.
        let validation = run(&format!(
            "{policy}
[[masked_columns]]
name = \"users\"
column = \"ssn\"
policy = \"ssn\"
"
        ));
        let errors = messages(&validation, Severity::Error);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with(
                "column public.users.ssn: policy \"ssn\" takes arguments (opted_in), but none are bound"
            ),
            "{errors:?}"
        );
        assert!(validation.probes.is_empty());
        assert_eq!(
            messages(&validation, Severity::Note),
            ["policy \"ssn\", default mask: not prepared, since no column binds its arguments"]
        );

        // Bound to a column the table doesn't have, and an extra one.
        let validation = run(&format!(
            "{policy}
[[masked_columns]]
name = \"users\"
column = \"ssn\"
policy = \"ssn\"
arguments = [\"consent\", \"id\"]
"
        ));
        assert_eq!(
            messages(&validation, Severity::Warning),
            [
                "column public.users.ssn: policy \"ssn\" takes 1 arguments, so columns (id) are ignored"
            ]
        );
        assert_eq!(
            messages(&validation, Severity::Error),
            [
                "column public.users.ssn: argument \"opted_in\" of policy \"ssn\" is bound to column \"consent\", which public.users doesn't have"
            ]
        );
    }

    #[test]
    fn test_missing_columns() {
        let validation = run(r#"
[[policies]]
name = "null"
data_type = "text"
mask = "null"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "null"

[[masked_columns]]
name = "users"
column = "nope"
policy = "null"

[[masked_columns]]
schema = "other"
name = "users"
column = "ssn"
policy = "null"

[[masked_columns]]
column = "missing"
policy = "null"

[[masked_columns]]
schema = "empty"
column = "ssn"
policy = "null"

# Another database's columns aren't checked.
[[masked_columns]]
database = "other"
name = "accounts"
column = "ssn"
policy = "null"

[[tags]]
name = "pii"
policy = "null"

[[classifiers]]
column_regex = "ss.*"
tag = "pii"

[[classifiers]]
column_regex = "secret_.*"
tag = "pii"
"#);
        assert_eq!(
            messages(&validation, Severity::Warning),
            [
                "[[masked_columns]] users.nope: public.users has no column \"nope\" in database \"pgdog\", so it masks nothing",
                "[[masked_columns]] other.users.ssn: table other.users doesn't exist in database \"pgdog\", so it masks nothing",
                "[[masked_columns]] *.missing: no table has a column \"missing\" in database \"pgdog\", so it masks nothing",
                "[[masked_columns]] empty.*.ssn: schema empty has no tables in database \"pgdog\", so it masks nothing",
                "[[classifiers]] \"secret_.*\" matches no column in database \"pgdog\"",
            ]
        );
    }

    #[test]
    fn test_raw_search_warnings() {
        let validation = run(r#"
[[policies]]
name = "dob"
data_type = "date"
mask = "truncate"

[[policies.rules]]
roles = ["support"]
mask = "null"
search = "raw"
search_operators = ["=", "between", "like"]

[[policies]]
name = "status"
data_type = "text"
mask = "null"
search = "raw"

[[policies]]
name = "ssn"
data_type = "text"
mask = "null"
search = "raw"

[[masked_columns]]
name = "users"
column = "dob"
policy = "dob"

[[masked_columns]]
name = "users"
column = "mood"
policy = "status"

[[masked_columns]]
name = "users"
column = "opted_in"
policy = "status"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"
"#);
        let warnings = messages(&validation, Severity::Warning);
        let rule = "policy \"dob\", rule 1 (roles support)";
        assert_eq!(
            warnings,
            [
                format!(
                    "{rule}: search = \"raw\" with range operators (<, >, BETWEEN) lets these users recover a value by binary search, in a few dozen statements"
                ),
                format!(
                    "{rule}: search = \"raw\" with pattern operators (LIKE, ILIKE) lets these users recover a value one character at a time"
                ),
                format!(
                    "{rule}: search = \"raw\" on date values lets these users find any value by trying each possible one with ="
                ),
                "policy \"status\", default mask on public.users.mood: search = \"raw\" on enum public.mood lets these users find any value by trying each of its 3 labels with =".into(),
                "policy \"status\", default mask on public.users.opted_in: search = \"raw\" on boolean values lets these users find any value by trying each possible one with =".into(),
            ]
        );
        assert!(messages(&validation, Severity::Error).is_empty());

        // The plugin logs those it can tell from the configuration alone.
        let config = Config::from_toml(
            "[[policies]]\nname = \"dob\"\ndata_type = \"date\"\nmask = \"null\"\nsearch = \"raw\"\n",
        )
        .unwrap();
        assert_eq!(
            config_warnings(&config),
            [
                "policy \"dob\", default mask: search = \"raw\" on date values lets these users find any value by trying each possible one with ="
            ]
        );
    }

    #[test]
    fn test_mask_errors() {
        // Every error, not just the first.
        let validation = run(r#"
[[policies]]
name = "salary"
data_type = "integer"
mask = "email"

[[policies]]
name = "ssn"
data_type = "text"
mask = "partial"

[[policies.rules]]
roles = ["support"]
mask = "sql"
expression = "other_column"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"
"#);
        let errors = messages(&validation, Severity::Error);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].starts_with("policy \"salary\": "), "{errors:?}");
        assert!(errors[1].contains("not other_column"), "{errors:?}");
        assert!(validation.probes.is_empty());
    }

    #[test]
    fn test_proxy_masks() {
        let config = r#"
[[policies]]
name = "card"
data_type = "character varying"
mask = "proxy"
proxy = "ff1"
options = { key_env = "PGDOG_MASK_VALIDATE_TEST_UNSET_KEY" }

[[policies]]
name = "token"
data_type = "text"
mask = "proxy"
proxy = "vault.token"

[[policies.rules]]
roles = ["support"]
mask = "null"

[[masked_columns]]
name = "users"
column = "card"
policy = "card"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "token"
"#;
        // Built as the plugin builds them: the key is missing.
        let validation = run(config);
        let errors = messages(&validation, Severity::Error);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].starts_with("policy \"card\", default mask: "),
            "{errors:?}"
        );
        assert!(
            errors[0].contains("PGDOG_MASK_VALIDATE_TEST_UNSET_KEY"),
            "{errors:?}"
        );
        assert_eq!(
            messages(&validation, Severity::Note),
            [
                "policy \"token\", default mask: proxy mask \"vault.token\" isn't built in, so its options aren't checked"
            ]
        );

        // Without building them, the rest is still checked.
        let validation = run_with(config, &Options { proxy_masks: false });
        assert!(messages(&validation, Severity::Error).is_empty());
        let targets: Vec<_> = validation
            .probes
            .iter()
            .flat_map(|p| p.targets.iter().map(String::as_str))
            .collect();
        assert_eq!(targets, ["data_type text", "public.users.ssn"]);
    }

    #[test]
    fn test_unresolved_tags() {
        let mut catalog = catalog();
        let mut users = catalog.get("public", "users").unwrap().clone();
        users.columns[1].comment = Some("pgdog:tag=pii.unknown".into());
        catalog = Catalog::new(vec!["public".into()], vec![users]);
        let config = Config::from_toml("[general]\ntag_source = \"comment\"\n").unwrap();
        let validation = validate(
            &config,
            &Registry::default(),
            &Options::default(),
            "pgdog",
            &catalog,
            &HashMap::new(),
        );
        assert_eq!(
            messages(&validation, Severity::Warning),
            [
                "column public.users.ssn: its tags \"pii.unknown\" have no [[tags]] entry, or map to different policies, so it reads as NULL for every masked user"
            ]
        );

        // Classifiers for different policies.
        let config = Config::from_toml(
            r#"
[[policies]]
name = "a"
data_type = "text"
mask = "null"

[[policies]]
name = "b"
data_type = "text"
mask = "default"

[[tags]]
name = "a"
policy = "a"

[[tags]]
name = "b"
policy = "b"

[[classifiers]]
column_regex = "ssn"
tag = "a"

[[classifiers]]
column_regex = "s.n"
tag = "b"
"#,
        )
        .unwrap();
        let validation = validate(
            &config,
            &Registry::default(),
            &Options::default(),
            "pgdog",
            &catalog,
            &HashMap::new(),
        );
        assert_eq!(
            messages(&validation, Severity::Warning),
            [
                "column public.users.ssn: [[classifiers]] for different policies match it, so it reads as NULL for every masked user"
            ]
        );
    }
}
