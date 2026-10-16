//! Masking configuration, loaded from the plugin's TOML file.
//!
//! The format follows PgDog's own config files: top-level `[[array_tables]]`,
//! flat keys, and the same `database` / `schema` / `name` / `column` keys as
//! `[[sharded_tables]]`.
use std::{collections::HashSet, fs, path::Path};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read {path}: {err}")]
    Read { path: String, err: std::io::Error },

    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("{0}")]
    Invalid(String),
}

/// What the plugin does with its decisions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Rewrite and block statements.
    #[default]
    Enforce,
    /// Analyze statements and log what would happen, without changing them.
    Shadow,
    /// Do nothing.
    Off,
}

/// What to do with statements the analyzer can't prove safe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnUnresolved {
    #[default]
    Block,
    Allow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    #[serde(default)]
    pub mode: Mode,
    /// Statements referencing relations missing from the schema snapshot.
    #[serde(default)]
    pub on_unresolved: OnUnresolved,
    /// User-defined functions masked users may call, e.g. `public.normalize_phone`.
    #[serde(default)]
    pub udf_allowlist: Vec<String>,
    /// Views masked users may query even though their definitions aren't analyzed.
    #[serde(default)]
    pub view_allowlist: Vec<String>,
    /// Number of analyzed statements to cache.
    #[serde(default = "General::cache_size")]
    pub cache_size: usize,
}

impl General {
    fn cache_size() -> usize {
        100_000
    }
}

impl Default for General {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            on_unresolved: OnUnresolved::default(),
            udf_allowlist: vec![],
            view_allowlist: vec![],
            cache_size: Self::cache_size(),
        }
    }
}

/// Masking roles granted to a PgDog user.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// PgDog user name, as in `users.toml`.
    pub name: String,
    /// PgDog database. Applies to all databases if omitted.
    pub database: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Masking functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskKind {
    /// Not masked.
    None,
    Null,
    Constant,
    Default,
    Partial,
    Email,
    Hash,
    Round,
    Truncate,
    Sql,
}

/// Whether masked users can search on the raw value of the column.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Search {
    #[default]
    Masked,
    Raw,
}

/// Mask settings, shared by policy defaults and rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaskSpec {
    pub kind: Option<MaskKind>,
    pub value: Option<String>,
    pub keep_prefix: Option<usize>,
    pub keep_suffix: Option<usize>,
    pub fill: Option<String>,
    pub digits: Option<i32>,
    pub unit: Option<String>,
    pub expression: Option<String>,
    pub search: Search,
    pub search_operators: Option<Vec<String>>,
}

/// Declares the flat mask keys on a config struct, so policies and rules
/// share them without `#[serde(flatten)]`, which doesn't support `deny_unknown_fields`.
macro_rules! mask_fields {
    ($(#[$meta:meta])* pub struct $name:ident { $($(#[$fmeta:meta])* pub $field:ident: $ty:ty,)* }) => {
        $(#[$meta])*
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
            pub mask: Option<MaskKind>,
            pub value: Option<String>,
            pub keep_prefix: Option<usize>,
            pub keep_suffix: Option<usize>,
            pub fill: Option<String>,
            pub digits: Option<i32>,
            pub unit: Option<String>,
            pub expression: Option<String>,
            #[serde(default)]
            pub search: Search,
            pub search_operators: Option<Vec<String>>,
        }

        impl $name {
            pub fn mask_spec(&self) -> MaskSpec {
                MaskSpec {
                    kind: self.mask,
                    value: self.value.clone(),
                    keep_prefix: self.keep_prefix,
                    keep_suffix: self.keep_suffix,
                    fill: self.fill.clone(),
                    digits: self.digits,
                    unit: self.unit.clone(),
                    expression: self.expression.clone(),
                    search: self.search,
                    search_operators: self.search_operators.clone(),
                }
            }
        }
    };
}

mask_fields! {
    /// A role-specific mask, evaluated in order. The first rule whose roles
    /// intersect the user's roles wins.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Rule {
        pub roles: Vec<String>,
    }
}

mask_fields! {
    /// A masking policy. Its top-level mask is the default for users no rule matches.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Policy {
        pub name: String,
        /// Type the policy applies to, e.g. `text`, `numeric`, `date`.
        pub data_type: String,
        /// Extra inputs for conditional masking, bound per column.
        #[serde(default)]
        pub arguments: Vec<String>,
        #[serde(default)]
        pub rules: Vec<Rule>,
    }
}

/// Column assignment.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskedColumn {
    pub database: Option<String>,
    pub schema: Option<String>,
    /// Table name. If omitted, every table with the column is masked.
    pub name: Option<String>,
    pub column: String,
    pub policy: Option<String>,
    pub tag: Option<String>,
    /// Columns of the same table bound, by position, to the policy's `arguments`.
    #[serde(default)]
    pub arguments: Vec<String>,
}

/// Tag to policy mapping.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tag {
    pub name: String,
    pub policy: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub masked_columns: Vec<MaskedColumn>,
    #[serde(default)]
    pub tags: Vec<Tag>,
}

impl Config {
    /// Load and validate the config file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(path).map_err(|err| Error::Read {
            path: path.display().to_string(),
            err,
        })?;
        Self::from_toml(&contents)
    }

    pub fn from_toml(contents: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(contents)?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), Error> {
        let mut names = HashSet::new();
        for policy in &self.policies {
            if !names.insert(policy.name.as_str()) {
                return Err(Error::Invalid(format!(
                    "policy \"{}\" is defined more than once",
                    policy.name
                )));
            }
        }

        let tags: HashSet<_> = self.tags.iter().map(|tag| tag.name.as_str()).collect();
        for tag in &self.tags {
            if !names.contains(tag.policy.as_str()) {
                return Err(Error::Invalid(format!(
                    "tag \"{}\" references unknown policy \"{}\"",
                    tag.name, tag.policy
                )));
            }
        }

        for column in &self.masked_columns {
            let target = format!(
                "{}.{}",
                column.name.as_deref().unwrap_or("*"),
                column.column
            );
            match (&column.policy, &column.tag) {
                (Some(policy), None) if !names.contains(policy.as_str()) => {
                    return Err(Error::Invalid(format!(
                        "masked column {target} references unknown policy \"{policy}\""
                    )));
                }
                (None, Some(tag)) if !tags.contains(tag.as_str()) => {
                    return Err(Error::Invalid(format!(
                        "masked column {target} references unknown tag \"{tag}\""
                    )));
                }
                (Some(_), Some(_)) | (None, None) => {
                    return Err(Error::Invalid(format!(
                        "masked column {target} needs exactly one of \"policy\" or \"tag\""
                    )));
                }
                _ => (),
            }
        }

        Ok(())
    }

    /// Policy assigned to a masked column, directly or through its tag.
    pub fn column_policy(&self, column: &MaskedColumn) -> Option<&Policy> {
        let name = match (&column.policy, &column.tag) {
            (Some(policy), _) => policy.as_str(),
            (None, Some(tag)) => self
                .tags
                .iter()
                .find(|t| &t.name == tag)
                .map(|t| t.policy.as_str())?,
            (None, None) => return None,
        };
        self.policies.iter().find(|policy| policy.name == name)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config = Config::from_toml(
            r#"
[general]
mode = "shadow"

[[users]]
name = "support"
roles = ["support"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "sql"
expression = "'XXX-XX-' || right(val, 4)"

[[policies.rules]]
roles = ["support"]
mask = "partial"
keep_suffix = 4
search = "raw"

[[tags]]
name = "pii.ssn"
policy = "ssn"

[[masked_columns]]
database = "pgdog"
name = "users"
column = "ssn"
tag = "pii.ssn"
"#,
        )
        .unwrap();

        assert_eq!(config.general.mode, Mode::Shadow);
        let policy = config.column_policy(&config.masked_columns[0]).unwrap();
        assert_eq!(policy.name, "ssn");
        assert_eq!(policy.mask_spec().kind, Some(MaskKind::Sql));
        let rule = &policy.rules[0].mask_spec();
        assert_eq!(rule.kind, Some(MaskKind::Partial));
        assert_eq!(rule.search, Search::Raw);
    }

    #[test]
    fn test_unknown_policy() {
        let err = Config::from_toml(
            r#"
[[masked_columns]]
name = "users"
column = "ssn"
policy = "nope"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown policy"), "{err}");
    }

    #[test]
    fn test_unknown_field() {
        assert!(Config::from_toml("[general]\nbogus = 1\n").is_err());
    }
}
