//! The plugin, configured once per fuzzing process with a fixed configuration
//! and the catalog of database [`DATABASE`].
use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

use pgdog_mask::pgdog_plugin::catalog::{
    Column, Function, Operator, Relation, RelationKind, SecurityLabel,
};
use pgdog_mask::pgdog_plugin::{
    Catalog, CatalogParts, ColumnTransform, Config, PluginVtable, Session, Verdict,
};
use pgdog_mask::proxy::Registry;

/// Database with the fixture catalog.
pub const DATABASE: &str = "db";

/// Database the `catalog` target loads fuzzed catalogs into.
pub const FUZZED_DATABASE: &str = "fuzzed";

/// Database whose catalog is never loaded.
pub const UNLOADED_DATABASE: &str = "unloaded";

/// Users of the configuration. `admin` is exempt from every policy.
pub const USERS: &[&str] = &["anonymous", "support", "admin"];

/// Masked with every policy's default mask.
pub const MASKED_USER: &str = "anonymous";

/// Exempt: statements are never analyzed.
pub const EXEMPT_USER: &str = "admin";

/// Columns `anonymous` can't read raw, as `(relation, column)`: masked
/// columns, the same columns of the partition, and view columns derived from
/// them.
pub const MASKED_COLUMNS: &[(&str, &str)] = &[
    ("users", "ssn"),
    ("users", "email"),
    ("users", "salary"),
    ("users", "phone"),
    ("users_2024", "ssn"),
    ("users_2024", "email"),
    ("users_2024", "salary"),
    ("users_2024", "phone"),
    ("accounts", "token"),
    ("accounts", "card"),
    ("accounts", "balance"),
    ("accounts", "note"),
    ("user_ssns", "ssn"),
    ("nested_v", "ssn"),
    ("ssn_barrier", "ssn"),
    ("ssn_barrier", "loud"),
    ("ssn_counts", "ssn"),
    ("ssn_flags", "starts_9"),
];

/// Functions whose results are computed from masked columns.
pub const MASKED_FUNCTIONS: &[&str] = &[
    "user_ssn",
    "user_ssn_p",
    "user_ssn_definer",
    "atomic_ssn",
    "volatile_ssn",
    "ssn_eq",
];

/// Of [`MASKED_COLUMNS`], those `anonymous` sees through proxy masks:
/// masked in the results only, read raw by the statement.
pub const PROXY_COLUMNS: &[(&str, &str)] = &[
    ("accounts", "token"),
    ("accounts", "card"),
    ("accounts", "balance"),
    ("accounts", "note"),
];

/// Is this column of this fixture relation masked for `anonymous`?
pub fn masked(relation: &str, column: &str) -> bool {
    MASKED_COLUMNS.contains(&(relation, column))
}

/// Is this column of this fixture relation masked by a proxy mask for `anonymous`?
pub fn proxy_masked(relation: &str, column: &str) -> bool {
    PROXY_COLUMNS.contains(&(relation, column))
}

/// Selects every column with a proxy mask, so their masks can be fuzzed.
pub const PROXY_STATEMENT: &str = "SELECT token, card, balance, note FROM accounts";

const HMAC_KEY: &str = "pgdog-mask fuzzing key";
const FF1_KEY: &str = "000102030405060708090a0b0c0d0e0f";

/// The configuration. Keys are `{dir}` placeholders, replaced by the
/// directory the key files are written to.
const CONFIG: &str = r#"
[general]
udf_allowlist = ["public.safe_fn"]
tag_source = "comment"
# Small, so eviction runs and fuzzing long statements doesn't fill memory.
cache_size = 1000

[[users]]
name = "admin"
roles = ["pii_admin"]

[[users]]
name = "support"
roles = ["support"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "sql"
expression = "'XXX-XX-' || right(val, 4)"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies.rules]]
roles = ["support"]
mask = "null"
search = "raw"

[[policies]]
name = "email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val ELSE NULL END"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "salary"
data_type = "numeric"
mask = "round"
digits = -4

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "phone"
data_type = "text"
mask = "partial"
keep_suffix = 2

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "token"
data_type = "text"
mask = "proxy"
proxy = "hmac_sha256"
options = { key_file = "{dir}/hmac.key", length = 16 }

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "card"
data_type = "character varying"
mask = "proxy"
proxy = "ff1"
options = { key_file = "{dir}/ff1.key" }

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "balance"
data_type = "integer"
mask = "proxy"
proxy = "fuzz.offset"
options = { offset = 1000 }

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "note"
data_type = "text"
mask = "proxy"
proxy = "fuzz.blocking"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[tags]]
name = "pii.phone"
policy = "phone"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"

[[masked_columns]]
name = "users"
column = "email"
policy = "email"
arguments = ["opted_in"]

[[masked_columns]]
column = "salary"
policy = "salary"

[[masked_columns]]
name = "accounts"
column = "token"
policy = "token"

[[masked_columns]]
name = "accounts"
column = "card"
policy = "card"

[[masked_columns]]
name = "accounts"
column = "balance"
policy = "balance"

[[masked_columns]]
name = "accounts"
column = "note"
policy = "note"
"#;

/// Replace `{dir}` with the directory holding the proxy mask keys.
pub fn with_key_dir(config: &str) -> String {
    config.replace("{dir}", &key_dir().display().to_string())
}

/// The fuzzing plugin's proxy masks: the built-in ones and the fuzzer's.
pub fn registry() -> Registry {
    let mut registry = Registry::default();
    crate::masks::register(&mut registry);
    registry
}

/// The configured plugin. Configured on first use.
pub fn plugin() -> &'static PluginVtable {
    static PLUGIN: LazyLock<&'static PluginVtable> = LazyLock::new(|| {
        let plugin = &crate::PGDOG_PLUGIN_VTABLE;
        let path = key_dir().join("masking.toml");
        fs::write(&path, with_key_dir(CONFIG)).expect("write the plugin config");
        let path = path.display().to_string();
        let configured = plugin.config(Config {
            log_level: "off".into(),
            log_json: false,
            plugin_config: path.as_str().into(),
        });
        assert!(configured, "the fuzzing config must load");
        plugin.catalog(DATABASE, &catalog());
        plugin
    });
    *PLUGIN
}

/// Proxy masks of [`PROXY_STATEMENT`]: valid mask IDs for `mask_rows`.
pub fn proxy_masks() -> &'static [ColumnTransform] {
    static MASKS: LazyLock<Vec<ColumnTransform>> = LazyLock::new(|| {
        let session = Session::new(MASKED_USER.into(), DATABASE.into());
        match plugin().statement(&session, PROXY_STATEMENT) {
            Ok(Verdict::Rewrite { columns, .. }) if columns.len() == 4 => columns,
            other => panic!("expected four proxy masks, got {other:?}"),
        }
    });
    &MASKS
}

/// Directory holding the config and the proxy mask keys.
pub fn key_dir() -> PathBuf {
    static DIR: LazyLock<PathBuf> = LazyLock::new(|| {
        let dir = std::env::temp_dir().join("pgdog-mask-fuzz");
        fs::create_dir_all(&dir).expect("create the fuzzing directory");
        fs::write(dir.join("hmac.key"), HMAC_KEY).expect("write the hmac key");
        fs::write(dir.join("ff1.key"), FF1_KEY).expect("write the ff1 key");
        dir
    });
    DIR.clone()
}

/// Type OID of a `data_type`, as Postgres reports it.
pub fn type_oid(data_type: &str) -> u32 {
    match data_type {
        "boolean" => 16,
        "bytea" => 17,
        "bigint" => 20,
        "smallint" => 21,
        "integer" => 23,
        "text" => 25,
        "real" => 700,
        "double precision" => 701,
        "character" => 1042,
        "character varying" => 1043,
        "date" => 1082,
        "timestamp without time zone" => 1114,
        "timestamp with time zone" => 1184,
        "numeric" => 1700,
        "uuid" => 2950,
        "jsonb" => 3802,
        _ => 0,
    }
}

pub fn column(name: &str, data_type: &str) -> Column {
    let mut column = Column::new(name, data_type);
    column.type_name = data_type.into();
    column.type_oid = type_oid(data_type);
    column
}

pub fn relation(name: &str, kind: RelationKind, columns: Vec<Column>) -> Relation {
    let mut relation = Relation::new("public", name, kind);
    relation.columns = columns;
    relation
}

fn view(name: &str, columns: &[&str], definition: &str) -> Relation {
    let mut view = relation(
        name,
        RelationKind::View,
        columns.iter().map(|c| column(c, "text")).collect(),
    );
    view.definition = Some(definition.into());
    view
}

fn users_columns() -> Vec<Column> {
    let mut phone = column("phone", "text");
    phone.comment = Some("pgdog:tag=pii.phone".into());
    phone.security_labels = vec![SecurityLabel::new("pgdog", "pii.phone")];
    let mut id = column("id", "bigint");
    id.is_primary_key = true;
    vec![
        id,
        column("name", "text"),
        column("ssn", "character varying"),
        column("email", "text"),
        column("opted_in", "boolean"),
        column("salary", "numeric"),
        phone,
    ]
}

/// The relations of the fixture catalog.
pub fn relations() -> Vec<Relation> {
    let mut partition = relation("users_2024", RelationKind::Table, users_columns());
    partition.parent = Some(("public".into(), "users".into()));

    let mut barrier = view(
        "ssn_barrier",
        &["id", "ssn", "loud"],
        " SELECT users.id, users.ssn, upper((users.ssn)::text) AS loud FROM public.users;",
    );
    barrier.options = vec!["security_barrier=true".into()];
    let mut counts = view(
        "ssn_counts",
        &["ssn", "n"],
        " SELECT users.ssn, count(*) AS n FROM public.users GROUP BY users.ssn;",
    );
    counts.kind = RelationKind::MaterializedView;
    // A boolean computed from a masked column, in a view that can't be inlined.
    let mut flags = relation(
        "ssn_flags",
        RelationKind::MaterializedView,
        vec![column("id", "bigint"), column("starts_9", "boolean")],
    );
    flags.definition = Some(
        " SELECT users.id, ((users.ssn)::text ~~ '9%'::text) AS starts_9 FROM public.users;".into(),
    );

    vec![
        relation("users", RelationKind::Table, users_columns()),
        partition,
        relation(
            "orders",
            RelationKind::Table,
            vec![
                column("id", "bigint"),
                column("user_id", "bigint"),
                column("total", "numeric"),
                column("placed_at", "timestamp with time zone"),
            ],
        ),
        relation(
            "accounts",
            RelationKind::Table,
            vec![
                column("id", "bigint"),
                column("user_id", "bigint"),
                column("token", "text"),
                column("card", "character varying"),
                column("balance", "integer"),
                column("note", "text"),
            ],
        ),
        // No definition: can't be analyzed.
        relation(
            "user_names",
            RelationKind::View,
            vec![column("name", "text")],
        ),
        view(
            "user_ssns",
            &["id", "ssn"],
            " SELECT users.id, users.ssn FROM public.users;",
        ),
        view(
            "user_names_v",
            &["id", "name"],
            " SELECT users.id, users.name FROM public.users;",
        ),
        view(
            "nested_v",
            &["ssn"],
            " SELECT user_ssns.ssn FROM public.user_ssns;",
        ),
        barrier,
        counts,
        flags,
    ]
}

fn sql_function(
    oid: u32,
    name: &str,
    args: &[(&str, &str)],
    returns: &str,
    body: &str,
) -> Function {
    let mut function = Function::new(oid, "public", name);
    function.kind = "function".into();
    function.argument_types = args.iter().map(|(_, t)| (*t).to_owned()).collect();
    function.argument_names = args.iter().map(|(n, _)| (*n).to_owned()).collect();
    function.return_type = returns.into();
    function.result = returns.into();
    function.language = "sql".into();
    function.source = body.into();
    function.volatility = "stable".into();
    function
}

/// The functions of the fixture catalog.
pub fn functions() -> Vec<Function> {
    let mut last4 = sql_function(
        1,
        "last4",
        &[("value", "text")],
        "text",
        "SELECT right(value, 4)",
    );
    last4.volatility = "immutable".into();
    last4.strict = true;

    let mut definer = sql_function(
        4,
        "user_ssn_definer",
        &[("uid", "bigint")],
        "text",
        "SELECT ssn FROM public.users WHERE id = uid",
    );
    definer.security_definer = true;

    let mut plpgsql = sql_function(5, "plpgsql_fn", &[], "integer", "BEGIN RETURN 1; END");
    plpgsql.language = "plpgsql".into();

    let mut ssns = sql_function(6, "ssns", &[], "record", "SELECT id, ssn FROM public.users");
    ssns.returns_set = true;
    ssns.output_names = vec!["id".into(), "ssn".into()];
    ssns.output_types = vec!["bigint".into(), "text".into()];

    let mut atomic = sql_function(8, "atomic_ssn", &[("uid", "bigint")], "text", "");
    atomic.sql_body = Some(
        "BEGIN ATOMIC\n SELECT users.ssn\n    FROM public.users\n   WHERE (users.id = atomic_ssn.uid);\nEND".into(),
    );

    let mut volatile = sql_function(
        10,
        "volatile_ssn",
        &[("uid", "bigint")],
        "text",
        "SELECT ssn FROM public.users WHERE id = uid",
    );
    volatile.volatility = "volatile".into();

    let mut safe = sql_function(13, "safe_fn", &[("value", "text")], "text", "SELECT 'x'");
    safe.language = "plpgsql".into();

    vec![
        last4,
        sql_function(
            2,
            "user_ssn",
            &[("uid", "bigint")],
            "text",
            "SELECT ssn FROM public.users WHERE id = uid",
        ),
        sql_function(
            3,
            "user_ssn_p",
            &[("", "bigint")],
            "text",
            "SELECT ssn FROM public.users WHERE id = $1",
        ),
        definer,
        plpgsql,
        ssns,
        sql_function(
            7,
            "count_users",
            &[],
            "bigint",
            "SELECT count(*) FROM public.users",
        ),
        atomic,
        sql_function(
            9,
            "recursive_fn",
            &[("x", "integer")],
            "integer",
            "SELECT public.recursive_fn(x)",
        ),
        volatile,
        sql_function(
            11,
            "same",
            &[("a", "text"), ("b", "text")],
            "boolean",
            "SELECT a = b",
        ),
        sql_function(
            12,
            "ssn_eq",
            &[("a", "bigint"), ("b", "bigint")],
            "boolean",
            "SELECT (SELECT ssn FROM public.users WHERE id = a) = (SELECT ssn FROM public.users WHERE id = b)",
        ),
        safe,
    ]
}

/// The operators of the fixture catalog.
pub fn operators() -> Vec<Operator> {
    let operator = |oid, name: &str, left: &str, function_oid, function: &str| {
        let mut operator = Operator::new(oid, "public", name);
        operator.left_type = Some(left.into());
        operator.right_type = Some(left.into());
        operator.result_type = "boolean".into();
        operator.function_oid = function_oid;
        operator.function_schema = "public".into();
        operator.function_name = function.into();
        operator
    };
    vec![
        operator(100, "===", "text", 11, "same"),
        operator(101, "@@@", "bigint", 12, "ssn_eq"),
    ]
}

/// Names of the functions in `pg_catalog`.
pub fn system_functions() -> Vec<String> {
    include_str!("../../src/analyzer/test_builtin_functions.txt")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The fixture catalog, as PgDog sends it.
pub fn catalog() -> Catalog {
    let mut catalog = Catalog::new(CatalogParts::ALL);
    catalog.search_path = vec!["$user".into(), "public".into()];
    catalog.relations = relations();
    catalog.functions = functions();
    catalog.system_functions = system_functions();
    catalog.operators = operators();
    catalog
}
