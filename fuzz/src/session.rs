//! Fuzzed sessions and the checks every hook result must pass.
use std::collections::HashSet;

use arbitrary::Arbitrary;
use pgdog_mask::pgdog_plugin::{Session, Verdict};

use crate::fixture::{DATABASE, EXEMPT_USER, FUZZED_DATABASE, UNLOADED_DATABASE, USERS};

/// `cannot_connect_now`: masked users get it until the schema is loaded.
const CANNOT_CONNECT_NOW: &str = "57P03";

/// A client session, mostly of known users and databases.
#[derive(Debug, Arbitrary)]
pub struct SessionInput {
    user: Name,
    database: Database,
    search_path: SearchPath,
}

/// Users and databases come from PgDog's configuration, so there are few of
/// them; the plugin keeps a profile for each pair it sees.
#[derive(Debug, Arbitrary)]
enum Name {
    Known(u8),
    Other(u8),
}

/// Users the configuration doesn't name.
const OTHER_USERS: &[&str] = &[
    "bob",
    "",
    "ADMIN",
    "admin ",
    "$user",
    "pii_admin",
    "ünïcödé",
];

#[derive(Debug, Arbitrary)]
enum Database {
    Loaded,
    Unloaded,
    Other(u8),
}

/// Databases the configuration doesn't name.
const OTHER_DATABASES: &[&str] = &["", "DB", "db ", "postgres", FUZZED_DATABASE];

#[derive(Debug, Arbitrary)]
enum SearchPath {
    /// The database default.
    Default,
    Public,
    User,
    Other(String),
}

/// Owned session fields, borrowed by [`Session`].
#[derive(Debug, Clone)]
pub struct Owned {
    pub user: String,
    pub database: String,
    pub search_path: String,
}

impl Owned {
    pub fn new(user: &str, database: &str, search_path: &str) -> Self {
        Self {
            user: user.into(),
            database: database.into(),
            search_path: search_path.into(),
        }
    }

    pub fn session(&self) -> Session<'_> {
        Session::new(self.user.as_str().into(), self.database.as_str().into())
            .with_search_path(self.search_path.as_str().into())
    }

    pub fn exempt(&self) -> bool {
        self.user == EXEMPT_USER
    }

    /// The database's catalog was never loaded.
    pub fn unloaded(&self) -> bool {
        self.database != DATABASE && self.database != FUZZED_DATABASE
    }
}

impl SessionInput {
    pub fn owned(&self) -> Owned {
        let user = match &self.user {
            Name::Known(i) => USERS[*i as usize % USERS.len()].to_owned(),
            Name::Other(i) => OTHER_USERS[*i as usize % OTHER_USERS.len()].to_owned(),
        };
        let database = match &self.database {
            Database::Loaded => DATABASE.to_owned(),
            Database::Unloaded => UNLOADED_DATABASE.to_owned(),
            Database::Other(i) => OTHER_DATABASES[*i as usize % OTHER_DATABASES.len()].to_owned(),
        };
        let search_path = match &self.search_path {
            SearchPath::Default => String::new(),
            SearchPath::Public => "public".to_owned(),
            SearchPath::User => "\"$user\", public".to_owned(),
            SearchPath::Other(path) => path.clone(),
        };
        Owned {
            user,
            database,
            search_path,
        }
    }
}

/// Checks that hold for the verdict of any statement in any session.
pub fn check_verdict(owned: &Owned, sql: &str, verdict: &Verdict) {
    if owned.exempt() {
        assert_eq!(*verdict, Verdict::Allow, "exempt users are never analyzed");
        return;
    }
    if owned.unloaded() {
        // Masked users fail closed, with an error clients can retry.
        match verdict {
            Verdict::Deny(deny) => assert_eq!(deny.sqlstate.as_str(), CANNOT_CONNECT_NOW),
            other => panic!("statement allowed without a schema: {other:?}"),
        }
        return;
    }
    check_rewrite(sql, verdict);
}

/// Rewrites are deparsed from a parse tree, so they must parse again, and
/// their result masks must be ones PgDog can apply.
pub fn check_rewrite(sql: &str, verdict: &Verdict) {
    check_masks(sql, verdict);
    if let Verdict::Rewrite { sql: rewritten, .. } = verdict
        && rewritten != sql
        && !has_param_zero(sql)
        && !has_empty_typmod(rewritten)
        && !has_empty_returning(rewritten)
        && let Err(err) = pg_raw_parse::parse(rewritten)
    {
        panic!("rewrite doesn't parse: {err}\n  statement: {sql}\n  rewrite: {rewritten}");
    }
}

/// One mask per result column; proxy masks carry the column's type, which
/// PgDog checks; NULL masks are applied by PgDog, so they never block.
fn check_masks(sql: &str, verdict: &Verdict) {
    let Verdict::Rewrite { columns, .. } = verdict else {
        return;
    };
    let mut seen = HashSet::new();
    for mask in columns {
        assert!(
            seen.insert((mask.result, mask.column)),
            "two masks for result {} column {}\n  statement: {sql}\n  masks: {columns:?}",
            mask.result,
            mask.column
        );
        if mask.is_null() {
            assert!(
                !mask.blocking,
                "NULL mask marked blocking\n  statement: {sql}\n  masks: {columns:?}"
            );
        } else {
            assert_ne!(
                mask.type_oid, 0,
                "proxy mask without a type\n  statement: {sql}\n  masks: {columns:?}"
            );
        }
    }
}

// Known issues, skipped so they don't hide new findings. All fail closed:
// Postgres rejects the original statements too.

/// Parameter `$0` deparses as `?` (pg_raw_parse).
fn has_param_zero(sql: &str) -> bool {
    sql.match_indices('$').any(|(i, _)| {
        let digits: String = sql[i + 1..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        !digits.is_empty() && digits.bytes().all(|b| b == b'0')
    })
}

/// Masked columns in a type's modifiers (`to_jsonb(u.*) ''`, `foo('c', ssn)
/// ''`) are masked like any other reference, and masked modifiers deparse
/// as nothing: `''::to_jsonb()`, `''::foo('c', )`.
fn has_empty_typmod(rewritten: &str) -> bool {
    rewritten.match_indices("::").any(|(i, _)| {
        let rest = skip_type_name(&rewritten[i + 2..]);
        let Some(modifiers) = rest.strip_prefix('(') else {
            return false;
        };
        let end = modifiers.find(')').unwrap_or(modifiers.len());
        modifiers[..end].split(',').any(|m| m.trim().is_empty())
    })
}

/// What follows a type name: identifiers, quoted or not, joined by dots.
fn skip_type_name(mut rest: &str) -> &str {
    loop {
        if let Some(quoted) = rest.strip_prefix('"') {
            // `""` is a quote inside a quoted identifier.
            let bytes = quoted.as_bytes();
            let mut end = 0;
            while end < bytes.len() {
                if bytes[end] == b'"' {
                    if bytes.get(end + 1) != Some(&b'"') {
                        break;
                    }
                    end += 1;
                }
                end += 1;
            }
            rest = quoted.get(end + 1..).unwrap_or("");
        } else {
            let name = rest
                .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '$')))
                .unwrap_or(rest.len());
            if name == 0 {
                return rest;
            }
            rest = &rest[name..];
        }
        match rest.strip_prefix('.') {
            Some(next) => rest = next,
            None => return rest,
        }
    }
}

/// `RETURNING *` of a relation with no columns expands to nothing.
fn has_empty_returning(rewritten: &str) -> bool {
    rewritten.match_indices("RETURNING").any(|(i, keyword)| {
        let rest = rewritten[i + keyword.len()..].trim_start();
        rest.is_empty() || rest.starts_with([';', ')'])
    })
}

/// All the sessions every statement runs in: each user with the database
/// default and an explicit `search_path`, and a database with no schema.
pub fn standard_sessions() -> Vec<Owned> {
    USERS
        .iter()
        .flat_map(|user| {
            [
                Owned::new(user, DATABASE, ""),
                Owned::new(user, DATABASE, "public"),
            ]
        })
        .chain([Owned::new("anonymous", UNLOADED_DATABASE, "")])
        .collect()
}
