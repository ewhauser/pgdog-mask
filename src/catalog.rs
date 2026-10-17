//! Database schema, from the catalog PgDog sends to the plugin.
use std::collections::{HashMap, HashSet};

use pgdog_plugin::{CatalogParts, catalog as plugin};

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
    /// Type OID as `RowDescription` reports it; 0 if unknown.
    pub type_oid: u32,
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
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default)]
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
    /// The catalog has hidden columns, view definitions and functions. Without
    /// them, views and functions can't be analyzed.
    pub full: bool,
}

impl Catalog {
    /// Copy the catalog PgDog sent.
    pub fn from_plugin(catalog: &plugin::Catalog) -> Self {
        let relations = catalog
            .relations
            .iter()
            .map(|relation| {
                let kind = match relation.kind {
                    plugin::RelationKind::Table
                    | plugin::RelationKind::PartitionedTable
                    | plugin::RelationKind::ForeignTable => RelationKind::Table,
                    plugin::RelationKind::View => RelationKind::View,
                    plugin::RelationKind::MaterializedView => RelationKind::MaterializedView,
                    plugin::RelationKind::Other => RelationKind::Other,
                    // A kind added after this plugin was built: assume it holds
                    // data, so its columns are tagged and masked like a table's.
                    _ => RelationKind::Table,
                };
                let columns = relation
                    .columns
                    .iter()
                    .map(|column| Column {
                        name: column.name.clone(),
                        data_type: column.data_type.clone(),
                        type_name: column.type_name.clone(),
                        type_oid: column.type_oid,
                        comment: column.comment.clone(),
                        security_labels: column
                            .security_labels
                            .iter()
                            .map(|label| (label.provider.clone(), label.label.clone()))
                            .collect(),
                    })
                    .collect();
                let mut built = Relation::new(&relation.schema, &relation.name, kind, columns);
                built.parent = relation.parent.clone();
                built.definition = relation.definition.clone();
                built.options = relation.options.clone();
                built
            })
            .collect();

        let mut built = Self::new(catalog.search_path.clone(), relations);
        built.full = catalog.parts.contains(CatalogParts::ALL);
        built.add_functions(
            catalog
                .functions
                .iter()
                .map(|function| Function {
                    oid: function.oid.into(),
                    schema: function.schema.clone(),
                    name: function.name.clone(),
                    kind: function.kind.clone(),
                    argument_types: function.argument_types.clone(),
                    argument_names: function.argument_names.clone(),
                    argument_defaults: function.argument_defaults.into(),
                    variadic: function.variadic,
                    return_type: function.return_type.clone(),
                    returns_set: function.returns_set,
                    output_names: function.output_names.clone(),
                    output_types: function.output_types.clone(),
                    language: function.language.clone(),
                    source: function.source.clone(),
                    sql_body: function.sql_body.clone(),
                    volatility: function.volatility.clone(),
                    security_definer: function.security_definer,
                    strict: function.strict,
                    config: function.config.clone(),
                    extension: function.extension.clone(),
                })
                .collect(),
        );
        built.add_operators(
            catalog
                .operators
                .iter()
                .map(|operator| Operator {
                    schema: operator.schema.clone(),
                    name: operator.name.clone(),
                    left_type: operator.left_type.clone(),
                    right_type: operator.right_type.clone(),
                    function_oid: operator.function_oid.into(),
                    function_schema: operator.function_schema.clone(),
                    function_name: operator.function_name.clone(),
                })
                .collect(),
        );
        built.system_functions = catalog.system_functions.iter().cloned().collect();
        built
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

    /// Is there a user-defined function with this name, in any schema?
    pub fn has_function_named(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    /// Is there a user-defined operator with this name, in any schema?
    pub fn has_operator_named(&self, name: &str) -> bool {
        self.operators.contains_key(name)
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
    fn test_from_plugin() {
        let mut ssn = plugin::Column::new("ssn", "text");
        ssn.type_name = "text".into();
        ssn.comment = Some("pgdog:tag=pii.ssn".into());
        ssn.security_labels = vec![plugin::SecurityLabel::new("pgdog", "pii.ssn")];
        let mut users = plugin::Relation::new("public", "users", plugin::RelationKind::Table);
        users.columns = vec![plugin::Column::new("id", "bigint"), ssn];

        let mut view = plugin::Relation::new("public", "user_ssns", plugin::RelationKind::View);
        view.definition = Some(" SELECT users.ssn FROM public.users;".into());
        view.options = vec!["security_barrier=true".into()];

        let mut last4 = plugin::Function::new(10, "public", "last4");
        last4.kind = "function".into();
        last4.argument_types = vec!["text".into()];
        last4.argument_names = vec!["value".into()];
        last4.return_type = "text".into();
        last4.language = "sql".into();
        last4.source = "SELECT right(value, 4)".into();
        last4.volatility = "immutable".into();
        last4.strict = true;

        let mut catalog = plugin::Catalog::new(CatalogParts::ALL);
        catalog.search_path = vec!["$user".into(), "public".into()];
        catalog.relations = vec![users, view];
        catalog.functions = vec![last4];
        catalog.system_functions = vec!["lower".into(), "right".into()];
        let catalog = Catalog::from_plugin(&catalog);
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

    #[test]
    fn test_partial_catalog() {
        // Without every part, views and functions can't be analyzed.
        let catalog = Catalog::from_plugin(&plugin::Catalog::new(CatalogParts::COLUMNS));
        assert!(!catalog.full);
    }
}
