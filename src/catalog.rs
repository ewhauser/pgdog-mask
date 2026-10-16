//! Database schema, from the snapshots PgDog sends to the plugin.
use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    /// As in `information_schema.columns.data_type`.
    pub data_type: String,
    /// From `format_type`, e.g. `public.mood` or `text[]`. Empty if unknown.
    pub type_name: String,
    pub comment: Option<String>,
    /// `(provider, label)` pairs.
    pub security_labels: Vec<(String, String)>,
}

impl Column {
    pub fn new(name: &str, data_type: &str) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            ..Default::default()
        }
    }
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
    /// Query of a view or materialized view, with schema-qualified names.
    pub definition: Option<String>,
    /// `reloptions`, e.g. `security_barrier=true`.
    pub options: Vec<String>,
}

impl Relation {
    pub fn new(schema: &str, name: &str, kind: RelationKind, columns: Vec<Column>) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
            kind,
            columns,
            parent: None,
            definition: None,
            options: vec![],
        }
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|column| column.name == name)
    }

    /// Is a boolean `reloption` set, e.g. `security_barrier`?
    pub fn option(&self, name: &str) -> bool {
        self.options.iter().any(|option| {
            option
                .split_once('=')
                .is_some_and(|(key, value)| key == name && matches!(value, "true" | "on" | "1"))
                || option == name
        })
    }

    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

/// A function from `pg_proc`, outside `pg_catalog`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Function {
    pub oid: i64,
    pub schema: String,
    pub name: String,
    /// `function`, `procedure`, `aggregate` or `window`.
    pub kind: String,
    pub argument_types: Vec<String>,
    pub argument_names: Vec<String>,
    pub argument_defaults: i32,
    pub variadic: bool,
    pub return_type: String,
    pub returns_set: bool,
    /// `OUT`, `INOUT` and `TABLE` columns.
    pub output_names: Vec<String>,
    pub output_types: Vec<String>,
    pub language: String,
    pub source: String,
    /// `BEGIN ATOMIC` / `RETURN` body, with schema-qualified names.
    pub sql_body: Option<String>,
    pub volatility: String,
    pub security_definer: bool,
    pub strict: bool,
    /// `SET` clauses, e.g. `search_path=public`.
    pub config: Vec<String>,
    pub extension: Option<String>,
}

impl Function {
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }

    /// Can a call with `count` positional arguments resolve to this function?
    pub fn accepts(&self, count: usize) -> bool {
        let max = self.argument_types.len();
        let min = max.saturating_sub(self.argument_defaults.max(0) as usize);
        (min..=max).contains(&count) || (self.variadic && count + 1 >= max)
    }

    /// `search_path` set with `SET search_path` on the function, if any.
    pub fn search_path(&self) -> Option<&str> {
        self.config
            .iter()
            .find_map(|setting| setting.strip_prefix("search_path="))
    }
}

/// An operator from `pg_operator`, outside `pg_catalog`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Operator {
    pub schema: String,
    pub name: String,
    pub left_type: Option<String>,
    pub right_type: Option<String>,
    pub function_oid: i64,
    pub function_schema: String,
    pub function_name: String,
}

/// Relations and functions of one database.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Server default `search_path`.
    pub search_path: Vec<String>,
    relations: HashMap<(String, String), Relation>,
    /// User-defined functions by name.
    functions: HashMap<String, Vec<Function>>,
    /// User-defined operators by name.
    operators: HashMap<String, Vec<Operator>>,
    /// Names of the functions in `pg_catalog`.
    system_functions: HashSet<String>,
    /// The snapshot has view definitions and functions. Without them, views and
    /// functions can't be analyzed.
    pub full: bool,
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
    #[serde(default)]
    full_catalog: bool,
    #[serde(default)]
    functions: Vec<Function>,
    #[serde(default)]
    operators: Vec<Operator>,
    #[serde(default)]
    system_functions: Vec<String>,
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
    #[serde(default)]
    definition: Option<String>,
    #[serde(default)]
    options: Vec<String>,
}

#[derive(Deserialize)]
struct SnapshotColumn {
    column_name: String,
    data_type: String,
    ordinal_position: i32,
    #[serde(default)]
    type_name: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    security_labels: Vec<SnapshotLabel>,
}

#[derive(Deserialize)]
struct SnapshotLabel {
    provider: String,
    label: String,
}

impl Catalog {
    /// Parse a schema snapshot sent by PgDog.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let snapshot: Snapshot = serde_json::from_str(json)?;
        let inner = snapshot.inner;
        let relations = inner
            .relations
            .into_values()
            .flat_map(|tables| tables.into_values())
            .map(|relation| {
                let mut columns: Vec<_> = relation.columns.into_values().collect();
                columns.sort_by_key(|column| column.ordinal_position);
                let kind = match relation.type_.as_str() {
                    "table" | "partitioned table" | "foreign table" => RelationKind::Table,
                    "view" => RelationKind::View,
                    "materialized view" => RelationKind::MaterializedView,
                    _ => RelationKind::Other,
                };
                let columns = columns
                    .into_iter()
                    .map(|column| Column {
                        name: column.column_name,
                        data_type: column.data_type,
                        type_name: column.type_name,
                        comment: column.comment,
                        security_labels: column
                            .security_labels
                            .into_iter()
                            .map(|label| (label.provider, label.label))
                            .collect(),
                    })
                    .collect();
                let mut built = Relation::new(&relation.schema, &relation.name, kind, columns);
                built.parent = relation.parent_table_schema.zip(relation.parent_table_name);
                built.definition = relation.definition;
                built.options = relation.options;
                built
            })
            .collect();

        let mut catalog = Self::new(inner.search_path, relations);
        catalog.full = inner.full_catalog;
        catalog.add_functions(inner.functions);
        catalog.add_operators(inner.operators);
        catalog.system_functions = inner.system_functions.into_iter().collect();
        Ok(catalog)
    }

    /// Build a catalog from relations.
    pub fn new(search_path: Vec<String>, relations: Vec<Relation>) -> Self {
        Self {
            search_path,
            relations: relations
                .into_iter()
                .map(|relation| ((relation.schema.clone(), relation.name.clone()), relation))
                .collect(),
            ..Default::default()
        }
    }

    pub fn add_functions(&mut self, functions: Vec<Function>) {
        for function in functions {
            self.functions
                .entry(function.name.clone())
                .or_default()
                .push(function);
        }
    }

    pub fn add_operators(&mut self, operators: Vec<Operator>) {
        for operator in operators {
            self.operators
                .entry(operator.name.clone())
                .or_default()
                .push(operator);
        }
    }

    pub fn set_system_functions<'a>(&mut self, names: impl IntoIterator<Item = &'a str>) {
        self.system_functions = names.into_iter().map(str::to_owned).collect();
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

    /// Is there a function with this name in `pg_catalog`?
    pub fn is_system_function(&self, name: &str) -> bool {
        self.system_functions.contains(name)
    }

    /// User-defined functions a call could resolve to: by name, in the given
    /// schema or the `search_path`.
    pub fn functions(
        &self,
        schema: Option<&str>,
        name: &str,
        search_path: &[String],
    ) -> Vec<&Function> {
        self.functions
            .get(name)
            .into_iter()
            .flatten()
            .filter(|function| match schema {
                Some(schema) => function.schema == schema,
                None => search_path.contains(&function.schema),
            })
            .collect()
    }

    /// A function by OID.
    pub fn function(&self, oid: i64) -> Option<&Function> {
        self.functions
            .values()
            .flatten()
            .find(|function| function.oid == oid)
    }

    /// User-defined operators an expression could resolve to.
    pub fn operators(
        &self,
        schema: Option<&str>,
        name: &str,
        search_path: &[String],
    ) -> Vec<&Operator> {
        self.operators
            .get(name)
            .into_iter()
            .flatten()
            .filter(|operator| match schema {
                Some(schema) => operator.schema == schema,
                None => search_path.contains(&operator.schema),
            })
            .collect()
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
              "ssn":{"table_catalog":"pgdog","table_schema":"public","table_name":"users","column_name":"ssn","column_default":"","is_nullable":true,"data_type":"text","ordinal_position":2,"is_primary_key":false,"foreign_keys":[],
                     "type_name":"text","comment":"pgdog:tag=pii.ssn","security_labels":[{"provider":"pgdog","label":"pii.ssn"}]},
              "id":{"table_catalog":"pgdog","table_schema":"public","table_name":"users","column_name":"id","column_default":"","is_nullable":false,"data_type":"bigint","ordinal_position":1,"is_primary_key":true,"foreign_keys":[]}
            }},
            "user_ssns":{"schema":"public","name":"user_ssns","type_":"view","owner":"pgdog","persistence":"permanent",
            "access_method":"","description":"","oid":2,"parent_table_schema":null,"parent_table_name":null,"columns":{},
            "definition":" SELECT users.ssn FROM public.users;","options":["security_barrier=true"]}}},
            "aggregate_functions":[],"full_catalog":true,
            "functions":[{"oid":10,"schema":"public","name":"last4","kind":"function","argument_types":["text"],
              "argument_names":["value"],"argument_defaults":0,"variadic":false,"return_type":"text","result":"text",
              "returns_set":false,"output_names":[],"output_types":[],"language":"sql","source":"SELECT right(value, 4)",
              "sql_body":null,"volatility":"immutable","security_definer":false,"strict":true,"config":[],"extension":null}],
            "operators":[],"system_functions":["lower","right"]}}"#;
        let catalog = Catalog::from_json(json).unwrap();
        assert!(catalog.full);
        let users = catalog.resolve(None, "users", &["public".into()]).unwrap();
        assert_eq!(users.kind, RelationKind::Table);
        let names: Vec<_> = users.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["id", "ssn"]);
        let ssn = users.column("ssn").unwrap();
        assert_eq!(ssn.comment.as_deref(), Some("pgdog:tag=pii.ssn"));
        assert_eq!(ssn.security_labels, [("pgdog".into(), "pii.ssn".into())]);

        let view = catalog.get("public", "user_ssns").unwrap();
        assert_eq!(view.kind, RelationKind::View);
        assert!(view.option("security_barrier"));
        assert!(!view.option("security_invoker"));
        assert!(view.definition.is_some());

        let path = ["public".to_owned()];
        let last4 = catalog.functions(None, "last4", &path);
        assert_eq!(last4.len(), 1);
        assert!(last4[0].accepts(1));
        assert!(!last4[0].accepts(2));
        assert!(catalog.functions(None, "last4", &[]).is_empty());
        assert!(catalog.is_system_function("lower"));
        assert!(!catalog.is_system_function("last4"));
    }
}
