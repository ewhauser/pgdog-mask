//! Masking profiles: which mask each policy applies for a given user.
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::catalog::Catalog;
use crate::config::{Config, Error, Policy};
use crate::mask::{Mask, compile};

/// A policy with its masks compiled.
#[derive(Debug)]
pub struct CompiledPolicy {
    pub policy: Policy,
    default: Mask,
    rules: Vec<(HashSet<String>, Mask)>,
}

/// Configuration with compiled policies.
#[derive(Debug)]
pub struct Policies {
    pub config: Config,
    pub policies: Vec<CompiledPolicy>,
}

impl Policies {
    pub fn new(config: Config) -> Result<Self, Error> {
        let policies = config
            .policies
            .iter()
            .map(|policy| {
                Ok(CompiledPolicy {
                    default: compile(policy, &policy.mask_spec())?,
                    rules: policy
                        .rules
                        .iter()
                        .map(|rule| {
                            Ok((
                                rule.roles.iter().cloned().collect(),
                                compile(policy, &rule.mask_spec())?,
                            ))
                        })
                        .collect::<Result<_, Error>>()?,
                    policy: policy.clone(),
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(Self { config, policies })
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
            exempt: !masks.iter().any(Mask::is_masked),
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
}

impl Assignments {
    /// Resolve `[[masked_columns]]` against a database's schema. Partitions
    /// inherit their parent's masked columns.
    pub fn new(policies: &Policies, database: &str, catalog: &Catalog) -> Self {
        let mut relations: HashMap<(String, String), HashMap<String, Assignment>> = HashMap::new();
        let config = &policies.config;

        for column in &config.masked_columns {
            if column.database.as_deref().is_some_and(|db| db != database) {
                continue;
            }
            let Some(policy) = config
                .column_policy(column)
                .and_then(|policy| config.policies.iter().position(|p| p.name == policy.name))
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
                    relations
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

        // Partitions inherit their ancestors' masked columns.
        for relation in catalog.relations() {
            let mut parent = relation.parent.clone();
            let mut depth = 0;
            while let Some(key) = parent
                && depth < 32
            {
                if let Some(inherited) = relations.get(&key).cloned() {
                    let entry = relations
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

        Self { relations }
    }

    /// Masked columns of a relation.
    pub fn relation(&self, schema: &str, name: &str) -> Option<&HashMap<String, Assignment>> {
        self.relations.get(&(schema.to_owned(), name.to_owned()))
    }

    pub fn column(&self, schema: &str, name: &str, column: &str) -> Option<&Assignment> {
        self.relation(schema, name)
            .and_then(|columns| columns.get(column))
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
}
