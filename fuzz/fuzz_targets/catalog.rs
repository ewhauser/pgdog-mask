//! The catalog hook: catalogs with arbitrary relations, columns, tags, view
//! definitions, functions and operators, loaded for one database, then
//! statements run against it as the masked user.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pgdog_mask::pgdog_plugin::catalog::{
    Column, Function, Operator, Relation, RelationKind, SecurityLabel,
};
use pgdog_mask::pgdog_plugin::{Catalog, CatalogParts};
use pgdog_mask_fuzz::fixture::{FUZZED_DATABASE, MASKED_USER, system_functions, type_oid};
use pgdog_mask_fuzz::plugin;
use pgdog_mask_fuzz::session::{Owned, check_verdict};

const MAX_ITEMS: usize = 8;

const SCHEMAS: &[&str] = &[
    "public",
    "other",
    "pg_catalog",
    "$user",
    "information_schema",
];
const RELATIONS: &[&str] = &[
    "users",
    "orders",
    "accounts",
    "users_2024",
    "user_ssns",
    "v",
    "w",
];
const COLUMNS: &[&str] = &[
    "id", "name", "ssn", "email", "opted_in", "salary", "phone", "token", "card", "balance",
    "note", "user_id",
];
const DATA_TYPES: &[&str] = &[
    "text",
    "character varying",
    "bigint",
    "integer",
    "smallint",
    "numeric",
    "boolean",
    "date",
    "timestamp with time zone",
    "bytea",
    "jsonb",
    "uuid",
    "ARRAY",
    "USER-DEFINED",
];
const COMMENTS: &[&str] = &[
    "pgdog:tag=pii.phone",
    "pgdog:tag=",
    "pgdog:tag=unknown",
    "pgdog:tag=pii.phone pgdog:tag=other",
    "not a tag",
];
const PROVIDERS: &[&str] = &["pgdog", "selinux"];
const LABELS: &[&str] = &["pii.phone", "pii.phone,other", "", " , "];
const DEFINITIONS: &[&str] = &[
    " SELECT users.id, users.ssn FROM public.users;",
    " SELECT users.ssn || 'x' AS ssn FROM public.users;",
    " SELECT v.ssn FROM public.v;",
    " SELECT w.ssn FROM public.w;",
    " SELECT users.ssn, count(*) AS n FROM public.users GROUP BY users.ssn;",
    " SELECT 1 AS id;",
    " SELECT * FROM public.users;",
    " SELECT public.f(users.ssn) AS ssn FROM public.users;",
    "not sql",
];
const OPTIONS: &[&str] = &[
    "security_barrier=true",
    "security_invoker=true",
    "check_option=local",
];
const FUNCTIONS: &[&str] = &["f", "user_ssn", "upper", "count", "g"];
const KINDS: &[&str] = &["function", "aggregate", "window", "procedure"];
const LANGUAGES: &[&str] = &["sql", "plpgsql", "c", "internal"];
const SOURCES: &[&str] = &[
    "SELECT ssn FROM public.users WHERE id = $1",
    "SELECT $1",
    "SELECT public.f($1)",
    "SELECT public.g($1)",
    "SELECT ssn FROM public.v",
    "BEGIN RETURN 1; END",
    "",
    "not sql",
];
const BODIES: &[&str] = &[
    "BEGIN ATOMIC\n SELECT users.ssn\n    FROM public.users;\nEND",
    "RETURN $1",
    "BEGIN ATOMIC\n SELECT public.f(1);\nEND",
];
const VOLATILITIES: &[&str] = &["immutable", "stable", "volatile"];
const OPERATORS: &[&str] = &["=", "===", "@@@", "||", "~"];

/// Statements every catalog is checked with.
const STATEMENTS: &[&str] = &[
    "SELECT * FROM users",
    "SELECT ssn FROM users WHERE id = 1",
    "SELECT * FROM user_ssns",
    "SELECT * FROM v JOIN w ON v.id = w.id",
    "SELECT f(ssn), g(1), user_ssn(1) FROM users",
    "SELECT ssn === 'x', id @@@ 1 FROM users",
    "SELECT upper(phone), count(*) FROM users GROUP BY 1",
    "SELECT token, card, balance, note FROM accounts",
    "COPY users TO STDOUT",
    "INSERT INTO users (ssn) VALUES ('x') RETURNING *",
    "WITH x AS (SELECT * FROM other.users) SELECT * FROM x",
];

#[derive(Debug, Arbitrary)]
enum Name {
    Known(u8),
    Other(String),
}

/// Longest name Postgres keeps (`NAMEDATALEN - 1`).
const MAX_NAME: usize = 63;

impl Name {
    /// A name as Postgres reports it: not empty, at most 63 bytes, no NUL.
    fn get(&self, pool: &[&str]) -> String {
        match self {
            Self::Known(i) => pool[*i as usize % pool.len()].to_owned(),
            Self::Other(name) => {
                let mut name = name.replace('\0', "");
                let mut end = name.len().min(MAX_NAME);
                while !name.is_char_boundary(end) {
                    end -= 1;
                }
                name.truncate(end);
                if name.is_empty() {
                    pool[0].to_owned()
                } else {
                    name
                }
            }
        }
    }

    /// Text, e.g. a definition or comment: anything but NUL.
    fn text(&self, pool: &[&str]) -> String {
        match self {
            Self::Known(i) => pool[*i as usize % pool.len()].to_owned(),
            Self::Other(text) => text.replace('\0', ""),
        }
    }
}

fn names(names: &[Name], pool: &[&str]) -> Vec<String> {
    names.iter().take(MAX_ITEMS).map(|n| n.get(pool)).collect()
}

#[derive(Debug, Arbitrary)]
struct Input {
    full: bool,
    search_path: Vec<Name>,
    relations: Vec<RelationInput>,
    functions: Vec<FunctionInput>,
    operators: Vec<OperatorInput>,
    statements: Vec<String>,
}

#[derive(Debug, Arbitrary)]
struct RelationInput {
    schema: Name,
    name: Name,
    kind: u8,
    columns: Vec<ColumnInput>,
    parent: Option<(Name, Name)>,
    definition: Option<Name>,
    options: Vec<Name>,
}

#[derive(Debug, Arbitrary)]
struct ColumnInput {
    name: Name,
    data_type: Name,
    type_oid: Option<u32>,
    is_primary_key: bool,
    comment: Option<Name>,
    labels: Vec<(Name, Name)>,
}

#[derive(Debug, Arbitrary)]
struct FunctionInput {
    oid: u8,
    schema: Name,
    name: Name,
    kind: Name,
    arguments: Vec<(Name, Name)>,
    argument_defaults: u8,
    variadic: bool,
    return_type: Name,
    returns_set: bool,
    outputs: Vec<(Name, Name)>,
    language: Name,
    source: Name,
    sql_body: Option<Name>,
    volatility: Name,
    security_definer: bool,
    strict: bool,
    extension: Option<String>,
}

#[derive(Debug, Arbitrary)]
struct OperatorInput {
    oid: u8,
    schema: Name,
    name: Name,
    left_type: Option<Name>,
    right_type: Option<Name>,
    function_oid: u8,
    function_schema: Name,
    function_name: Name,
}

impl RelationInput {
    fn build(&self) -> Relation {
        let kinds = [
            RelationKind::Table,
            RelationKind::PartitionedTable,
            RelationKind::View,
            RelationKind::MaterializedView,
            RelationKind::ForeignTable,
            RelationKind::Other,
        ];
        let mut relation = Relation::new(
            self.schema.get(SCHEMAS),
            self.name.get(RELATIONS),
            kinds[self.kind as usize % kinds.len()],
        );
        relation.columns = self
            .columns
            .iter()
            .take(MAX_ITEMS)
            .map(ColumnInput::build)
            .collect();
        relation.parent = self
            .parent
            .as_ref()
            .map(|(schema, name)| (schema.get(SCHEMAS), name.get(RELATIONS)));
        relation.definition = self.definition.as_ref().map(|d| d.text(DEFINITIONS));
        relation.options = names(&self.options, OPTIONS);
        relation
    }
}

impl ColumnInput {
    fn build(&self) -> Column {
        let data_type = self.data_type.get(DATA_TYPES);
        let mut column = Column::new(self.name.get(COLUMNS), data_type.clone());
        column.type_oid = self.type_oid.unwrap_or_else(|| type_oid(&data_type));
        column.type_name = data_type;
        column.is_primary_key = self.is_primary_key;
        column.comment = self.comment.as_ref().map(|c| c.text(COMMENTS));
        column.security_labels = self
            .labels
            .iter()
            .take(MAX_ITEMS)
            .map(|(provider, label)| {
                SecurityLabel::new(provider.get(PROVIDERS), label.text(LABELS))
            })
            .collect();
        column
    }
}

impl FunctionInput {
    fn build(&self) -> Function {
        let arguments = &self.arguments[..self.arguments.len().min(MAX_ITEMS)];
        let outputs = &self.outputs[..self.outputs.len().min(MAX_ITEMS)];
        let return_type = self.return_type.get(DATA_TYPES);
        let mut function = Function::new(
            self.oid.into(),
            self.schema.get(SCHEMAS),
            self.name.get(FUNCTIONS),
        );
        function.kind = self.kind.get(KINDS);
        function.argument_types = arguments.iter().map(|(_, t)| t.get(DATA_TYPES)).collect();
        function.argument_names = arguments.iter().map(|(n, _)| n.get(COLUMNS)).collect();
        function.argument_defaults = self.argument_defaults.into();
        function.variadic = self.variadic;
        function.result = return_type.clone();
        function.return_type = return_type;
        function.returns_set = self.returns_set;
        function.output_names = outputs.iter().map(|(n, _)| n.get(COLUMNS)).collect();
        function.output_types = outputs.iter().map(|(_, t)| t.get(DATA_TYPES)).collect();
        function.language = self.language.get(LANGUAGES);
        function.source = self.source.text(SOURCES);
        function.sql_body = self.sql_body.as_ref().map(|b| b.text(BODIES));
        function.volatility = self.volatility.get(VOLATILITIES);
        function.security_definer = self.security_definer;
        function.strict = self.strict;
        function.extension = self.extension.clone();
        function
    }
}

impl OperatorInput {
    fn build(&self) -> Operator {
        let mut operator = Operator::new(
            self.oid.into(),
            self.schema.get(SCHEMAS),
            self.name.get(OPERATORS),
        );
        operator.left_type = self.left_type.as_ref().map(|t| t.get(DATA_TYPES));
        operator.right_type = self.right_type.as_ref().map(|t| t.get(DATA_TYPES));
        operator.result_type = "boolean".into();
        operator.function_oid = self.function_oid.into();
        operator.function_schema = self.function_schema.get(SCHEMAS);
        operator.function_name = self.function_name.get(FUNCTIONS);
        operator
    }
}

fuzz_target!(|input: Input| {
    let mut catalog = Catalog::new(if input.full {
        CatalogParts::ALL
    } else {
        CatalogParts::NONE
    });
    catalog.search_path = names(&input.search_path, SCHEMAS);
    catalog.relations = input
        .relations
        .iter()
        .take(MAX_ITEMS)
        .map(RelationInput::build)
        .collect();
    catalog.functions = input
        .functions
        .iter()
        .take(MAX_ITEMS)
        .map(FunctionInput::build)
        .collect();
    catalog.system_functions = system_functions();
    catalog.operators = input
        .operators
        .iter()
        .take(MAX_ITEMS)
        .map(OperatorInput::build)
        .collect();

    let plugin = plugin();
    let before = plugin.generation();
    plugin.catalog(FUZZED_DATABASE, &catalog);
    assert!(
        plugin.generation() > before,
        "a new catalog changes the generation"
    );

    let owned = Owned::new(MASKED_USER, FUZZED_DATABASE, "");
    let session = owned.session();
    let fuzzed = input
        .statements
        .iter()
        .take(4)
        .map(String::as_str)
        .filter(|sql| !sql.contains('\0'));
    for sql in STATEMENTS.iter().copied().chain(fuzzed) {
        let verdict = plugin
            .statement(&session, sql)
            .unwrap_or_else(|err| panic!("statement hook failed: {err}"));
        check_verdict(&owned, sql, &verdict);
    }
});
