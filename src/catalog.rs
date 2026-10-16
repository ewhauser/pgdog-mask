//! Database schema, from the snapshots PgDog sends to the plugin.
use std::collections::HashMap;

use indexmap::IndexMap;
use serde::Deserialize;

/// Kind of relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationKind {
    Table,
    View,
    MaterializedView,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub schema: String,
    pub name: String,
    pub kind: RelationKind,
    /// Columns in ordinal order.
    pub columns: Vec<Column>,
    /// Parent table, for partitions.
    pub parent: Option<(String, String)>,
}

impl Relation {
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|column| column.name == name)
    }
}

/// Relations of one database.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Server default `search_path`.
    pub search_path: Vec<String>,
    relations: HashMap<(String, String), Relation>,
}

#[derive(Deserialize)]
struct Snapshot {
    inner: SnapshotInner,
}

#[derive(Deserialize)]
struct SnapshotInner {
    #[serde(default)]
    search_path: Vec<String>,
    #[serde(default)]
    relations: HashMap<String, HashMap<String, SnapshotRelation>>,
}

#[derive(Deserialize)]
struct SnapshotRelation {
    schema: String,
    name: String,
    type_: String,
    parent_table_schema: Option<String>,
    parent_table_name: Option<String>,
    #[serde(default)]
    columns: IndexMap<String, SnapshotColumn>,
}

#[derive(Deserialize)]
struct SnapshotColumn {
    column_name: String,
    data_type: String,
    ordinal_position: i32,
}

impl Catalog {
    /// Parse a schema snapshot sent by PgDog.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let snapshot: Snapshot = serde_json::from_str(json)?;
        let relations = snapshot
            .inner
            .relations
            .into_values()
            .flat_map(|tables| tables.into_values())
            .map(|relation| {
                let mut columns: Vec<_> = relation.columns.into_values().collect();
                columns.sort_by_key(|column| column.ordinal_position);
                let relation = Relation {
                    kind: match relation.type_.as_str() {
                        "table" | "partitioned table" | "foreign table" => RelationKind::Table,
                        "view" => RelationKind::View,
                        "materialized view" => RelationKind::MaterializedView,
                        _ => RelationKind::Other,
                    },
                    columns: columns
                        .into_iter()
                        .map(|column| Column {
                            name: column.column_name,
                            data_type: column.data_type,
                        })
                        .collect(),
                    parent: relation.parent_table_schema.zip(relation.parent_table_name),
                    schema: relation.schema,
                    name: relation.name,
                };
                ((relation.schema.clone(), relation.name.clone()), relation)
            })
            .collect();

        Ok(Self {
            search_path: snapshot.inner.search_path,
            relations,
        })
    }

    /// Build a catalog from relations. Used in tests.
    pub fn new(search_path: Vec<String>, relations: Vec<Relation>) -> Self {
        Self {
            search_path,
            relations: relations
                .into_iter()
                .map(|relation| ((relation.schema.clone(), relation.name.clone()), relation))
                .collect(),
        }
    }

    pub fn get(&self, schema: &str, name: &str) -> Option<&Relation> {
        self.relations.get(&(schema.to_owned(), name.to_owned()))
    }

    pub fn relations(&self) -> impl Iterator<Item = &Relation> {
        self.relations.values()
    }

    /// Find a relation the way Postgres would, using the `search_path` for
    /// unqualified names.
    pub fn resolve(
        &self,
        schema: Option<&str>,
        name: &str,
        search_path: &[String],
    ) -> Option<&Relation> {
        match schema {
            Some(schema) => self.get(schema, name),
            None => search_path.iter().find_map(|schema| self.get(schema, name)),
        }
    }
}

/// Parse a `search_path` setting, e.g. `"$user", public`.
pub fn parse_search_path(value: &str, user: &str) -> Vec<String> {
    value
        .split(',')
        .map(|schema| schema.trim().trim_matches('"'))
        .filter(|schema| !schema.is_empty())
        .map(|schema| {
            if schema == "$user" {
                user.to_owned()
            } else {
                schema.to_owned()
            }
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_search_path() {
        assert_eq!(
            parse_search_path(r#""$user", public"#, "alice"),
            vec!["alice".to_owned(), "public".to_owned()]
        );
        assert!(parse_search_path("", "alice").is_empty());
    }

    #[test]
    fn test_from_json() {
        let json = r#"{"inner":{"search_path":["$user","public"],"relations":{"public":{"users":{
            "schema":"public","name":"users","type_":"table","owner":"pgdog","persistence":"permanent",
            "access_method":"heap","description":"","oid":1,"parent_table_schema":null,"parent_table_name":null,
            "columns":{
              "ssn":{"table_catalog":"pgdog","table_schema":"public","table_name":"users","column_name":"ssn","column_default":"","is_nullable":true,"data_type":"text","ordinal_position":2,"is_primary_key":false,"foreign_keys":[]},
              "id":{"table_catalog":"pgdog","table_schema":"public","table_name":"users","column_name":"id","column_default":"","is_nullable":false,"data_type":"bigint","ordinal_position":1,"is_primary_key":true,"foreign_keys":[]}
            }}}},"aggregate_functions":[]}}"#;
        let catalog = Catalog::from_json(json).unwrap();
        let users = catalog.resolve(None, "users", &["public".into()]).unwrap();
        assert_eq!(users.kind, RelationKind::Table);
        let names: Vec<_> = users.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["id", "ssn"]);
    }
}
