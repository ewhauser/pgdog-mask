//! Column tags read from the database: column comments or security labels.
//!
//! Database tags only add masking. They never replace or remove a binding
//! from the config file, and tags that disappear between catalogs are
//! logged, since removing one unmasks a column.
use std::collections::{BTreeMap, BTreeSet};

use crate::catalog::{Catalog, RelationKind};
use crate::config::{General, TagSource};

/// Prefix of a tag in a column comment: `pgdog:tag=pii.ssn`.
pub const COMMENT_PREFIX: &str = "pgdog:tag=";

/// `(schema, table, column)`.
pub type ColumnKey = (String, String, String);

/// Tags read from the database, by column.
pub type DatabaseTags = BTreeMap<ColumnKey, BTreeSet<String>>;

/// Read column tags from the catalog, as configured by `tag_source`.
pub fn database_tags(general: &General, catalog: &Catalog) -> DatabaseTags {
    let mut tags = DatabaseTags::new();
    if general.tag_source == TagSource::Config {
        return tags;
    }

    for relation in catalog.relations() {
        if relation.kind == RelationKind::Other {
            continue;
        }
        for column in &relation.columns {
            let found: BTreeSet<String> = match general.tag_source {
                TagSource::Config => BTreeSet::new(),
                TagSource::Comment => column
                    .comment
                    .as_deref()
                    .map(comment_tags)
                    .unwrap_or_default(),
                TagSource::SecurityLabel => column
                    .security_labels
                    .iter()
                    .filter(|(provider, _)| *provider == general.security_label_provider)
                    .flat_map(|(_, label)| split_tags(label))
                    .collect(),
            };
            if !found.is_empty() {
                tags.insert(
                    (
                        relation.schema.clone(),
                        relation.name.clone(),
                        column.name.clone(),
                    ),
                    found,
                );
            }
        }
    }

    tags
}

/// Tags in a comment, e.g. `Social security number. pgdog:tag=pii.ssn`.
/// Several can be given, separated by commas or repeated.
pub fn comment_tags(comment: &str) -> BTreeSet<String> {
    comment
        .match_indices(COMMENT_PREFIX)
        .flat_map(|(start, _)| {
            let rest = &comment[start + COMMENT_PREFIX.len()..];
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '-' | ':' | ',')))
                .unwrap_or(rest.len());
            split_tags(rest[..end].trim_end_matches(['.', ',']))
        })
        .collect()
}

fn split_tags(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
}

/// Tags present in `previous` but not in `current`.
pub fn removed(previous: &DatabaseTags, current: &DatabaseTags) -> Vec<(ColumnKey, String)> {
    previous
        .iter()
        .flat_map(|(column, tags)| {
            tags.iter()
                .filter(move |tag| current.get(column).is_none_or(|now| !now.contains(*tag)))
                .map(move |tag| (column.clone(), tag.clone()))
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::catalog::{Column, Relation};

    #[test]
    fn test_comment_tags() {
        assert_eq!(
            comment_tags("Social security number. pgdog:tag=pii.ssn"),
            BTreeSet::from(["pii.ssn".into()])
        );
        assert_eq!(
            comment_tags("pgdog:tag=pii.email,pii.contact and pgdog:tag=gdpr."),
            BTreeSet::from(["pii.email".into(), "pii.contact".into(), "gdpr".into()])
        );
        assert!(comment_tags("no tags here, pgdog: tag=x").is_empty());
    }

    fn catalog() -> Catalog {
        let mut ssn = Column::new("ssn", "text");
        ssn.comment = Some("SSN pgdog:tag=pii.ssn".into());
        ssn.security_labels = vec![
            ("pgdog".into(), "pii.ssn, pii.id".into()),
            ("other".into(), "secret".into()),
        ];
        Catalog::new(
            vec![],
            vec![Relation::new(
                "public",
                "users",
                RelationKind::Table,
                vec![Column::new("id", "bigint"), ssn],
            )],
        )
    }

    #[test]
    fn test_database_tags() {
        let key = ("public".into(), "users".into(), "ssn".into());
        let mut general = General::default();
        assert!(database_tags(&general, &catalog()).is_empty());

        general.tag_source = TagSource::Comment;
        assert_eq!(
            database_tags(&general, &catalog())[&key],
            BTreeSet::from(["pii.ssn".into()])
        );

        general.tag_source = TagSource::SecurityLabel;
        assert_eq!(
            database_tags(&general, &catalog())[&key],
            BTreeSet::from(["pii.ssn".into(), "pii.id".into()])
        );
    }

    #[test]
    fn test_removed() {
        let key: ColumnKey = ("public".into(), "users".into(), "ssn".into());
        let before = DatabaseTags::from([(key.clone(), BTreeSet::from(["a".into(), "b".into()]))]);
        let after = DatabaseTags::from([(key.clone(), BTreeSet::from(["a".into()]))]);
        assert_eq!(removed(&before, &after), [(key.clone(), "b".into())]);
        assert!(removed(&after, &before).is_empty());
        assert_eq!(removed(&after, &DatabaseTags::new()), [(key, "a".into())]);
    }
}
