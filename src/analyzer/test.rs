use super::*;
use crate::catalog::{Column, Function, Operator, Relation, RelationKind};
use crate::config::Config;

pub(crate) mod proxy;

pub(crate) const CONFIG: &str = r#"
[general]
udf_allowlist = ["public.safe_fn"]

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
"#;

fn column(name: &str, data_type: &str) -> Column {
    let mut column = Column::new(name, data_type);
    column.type_oid = match data_type {
        "boolean" => 16,
        "bigint" => 20,
        "integer" => 23,
        "text" => 25,
        "character varying" => 1043,
        "numeric" => 1700,
        _ => 0,
    };
    column
}

fn relation(name: &str, kind: RelationKind, columns: Vec<Column>) -> Relation {
    Relation::new("public", name, kind, columns)
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

/// A SQL function.
fn sql_function(
    oid: i64,
    name: &str,
    args: &[(&str, &str)],
    returns: &str,
    body: &str,
) -> Function {
    Function {
        oid,
        schema: "public".into(),
        name: name.into(),
        kind: "function".into(),
        argument_types: args.iter().map(|(_, t)| (*t).to_owned()).collect(),
        argument_names: args.iter().map(|(n, _)| (*n).to_owned()).collect(),
        return_type: returns.into(),
        language: "sql".into(),
        source: body.into(),
        volatility: "stable".into(),
        ..Default::default()
    }
}

pub(crate) fn functions() -> Vec<Function> {
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

    let mut stash = sql_function(
        13,
        "stash",
        &[("v", "text")],
        "text",
        "INSERT INTO public.audit (note) VALUES (v) RETURNING note",
    );
    stash.volatility = "volatile".into();

    let mut digest = sql_function(
        15,
        "digest",
        &[("", "text"), ("", "text")],
        "bytea",
        "pg_digest",
    );
    digest.language = "c".into();
    digest.extension = Some("pgcrypto".into());

    let mut upper_safe = sql_function(
        18,
        "upper_safe",
        &[("v", "text")],
        "text",
        "SELECT upper(v)",
    );
    upper_safe.volatility = "immutable".into();

    // Mislabelled: it reads a table, so the planner may run it in advance.
    let mut imm_ssn = sql_function(
        25,
        "imm_ssn",
        &[("uid", "bigint")],
        "text",
        "SELECT ssn FROM public.users WHERE id = uid",
    );
    imm_ssn.volatility = "immutable".into();

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
        stash,
        sql_function(
            14,
            "ssn_is",
            &[("uid", "bigint"), ("guess", "text")],
            "boolean",
            "SELECT EXISTS (SELECT 1 FROM public.users WHERE id = uid AND ssn = guess)",
        ),
        digest,
        sql_function(
            16,
            "notify_fn",
            &[("v", "text")],
            "void",
            "SELECT pg_notify('c', v)",
        ),
        sql_function(
            17,
            "wrap_stash",
            &[("v", "text")],
            "text",
            "SELECT public.stash(v)",
        ),
        upper_safe,
        sql_function(
            19,
            "email_of",
            &[("uid", "bigint")],
            "text",
            "SELECT email FROM public.users WHERE id = uid",
        ),
        sql_function(
            20,
            "reroute",
            &[],
            "integer",
            "SET search_path TO other; SELECT 1",
        ),
        sql_function(
            21,
            "noisy_eq",
            &[("a", "text"), ("b", "text")],
            "boolean",
            "SELECT a = b FROM (SELECT pg_notify('c', a)) AS n",
        ),
        sql_function(
            23,
            "notify_p",
            &[("", "text")],
            "void",
            "SELECT pg_notify('c', $1)",
        ),
        sql_function(
            24,
            "notify_q",
            &[("v", "text")],
            "void",
            "SELECT pg_notify('c', notify_q.v)",
        ),
        imm_ssn,
        sql_function(
            26,
            "wrap_imm",
            &[("uid", "bigint")],
            "text",
            "SELECT public.imm_ssn(uid)",
        ),
    ]
}

pub(crate) fn catalog() -> Catalog {
    let users = vec![
        column("id", "bigint"),
        column("name", "text"),
        column("ssn", "character varying"),
        column("email", "text"),
        column("opted_in", "boolean"),
        column("salary", "numeric"),
    ];
    let mut partition = relation("users_2024", RelationKind::Table, users.clone());
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
    // A boolean computed from a masked column, in a view that isn't inlined.
    let mut flags = relation(
        "ssn_flags",
        RelationKind::MaterializedView,
        vec![column("id", "bigint"), column("starts_9", "boolean")],
    );
    flags.definition = Some(
        " SELECT users.id, ((users.ssn)::text ~~ '9%'::text) AS starts_9 FROM public.users;".into(),
    );

    let mut catalog = Catalog::new(
        vec!["$user".into(), "public".into()],
        vec![
            relation("users", RelationKind::Table, users),
            partition,
            relation(
                "orders",
                RelationKind::Table,
                vec![
                    column("id", "bigint"),
                    column("user_id", "bigint"),
                    column("total", "numeric"),
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
            relation(
                "archive",
                RelationKind::Table,
                vec![column("id", "bigint"), column("ssn", "character varying")],
            ),
            relation(
                "patients",
                RelationKind::Table,
                vec![
                    column("id", "bigint"),
                    column("user_id", "bigint"),
                    column("mrn", "text"),
                ],
            ),
            relation(
                "audit",
                RelationKind::Table,
                vec![column("id", "bigint"), column("note", "text")],
            ),
            relation(
                "legacy",
                RelationKind::Table,
                vec![column("id", "bigint"), column("code", "citext")],
            ),
            view(
                "user_loud",
                &["id", "loud"],
                " SELECT users.id, upper((users.ssn)::text) AS loud FROM public.users;",
            ),
            view(
                "user_contacts",
                &["id", "ssn", "email"],
                " SELECT users.id, users.ssn, users.email FROM public.users;",
            ),
            relation(
                "tags",
                RelationKind::Table,
                vec![column("id", "bigint"), column("labels", "text[]")],
            ),
        ],
    );
    catalog.full = true;
    catalog.set_system_functions(include_str!("test_builtin_functions.txt").lines());
    catalog.add_functions(functions());
    catalog.add_operators(vec![
        Operator {
            schema: "public".into(),
            name: "===".into(),
            left_type: Some("text".into()),
            right_type: Some("text".into()),
            function_oid: 11,
            function_schema: "public".into(),
            function_name: "same".into(),
        },
        Operator {
            schema: "public".into(),
            name: "@@@".into(),
            left_type: Some("bigint".into()),
            right_type: Some("bigint".into()),
            function_oid: 12,
            function_schema: "public".into(),
            function_name: "ssn_eq".into(),
        },
        Operator {
            schema: "public".into(),
            name: "~~~".into(),
            left_type: Some("text".into()),
            right_type: Some("text".into()),
            function_oid: 21,
            function_schema: "public".into(),
            function_name: "noisy_eq".into(),
        },
    ]);
    catalog
}

/// The catalog with a user-defined `public.set_config`, which unqualified
/// calls could resolve to.
fn catalog_shadowing_set_config() -> Catalog {
    let mut catalog = catalog();
    catalog.add_functions(vec![sql_function(
        22,
        "set_config",
        &[("name", "text"), ("value", "text"), ("is_local", "boolean")],
        "text",
        "SELECT value",
    )]);
    catalog
}

pub(crate) fn analyze_as(user: &str, sql: &str) -> Outcome {
    analyze_with(CONFIG, user, sql)
}

fn analyze_with(config: &str, user: &str, sql: &str) -> Outcome {
    analyze_in(&catalog(), config, user, sql)
}

fn analyze_in(catalog: &Catalog, config: &str, user: &str, sql: &str) -> Outcome {
    let policies = Policies::new(Config::from_toml(config).unwrap()).unwrap();
    let assignments = Assignments::new(&policies, "db", catalog);
    let profile = policies.profile(user, "db");
    let ctx = Context {
        catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec!["public".into()],
    };
    analyze(sql, &ctx)
}

fn rewritten(user: &str, sql: &str) -> String {
    match analyze_as(user, sql) {
        Outcome::Rewritten { sql, .. } => sql,
        other => panic!("expected a rewrite of {sql:?}, got {other:?}"),
    }
}

fn blocked(user: &str, sql: &str) -> String {
    match analyze_as(user, sql) {
        Outcome::Blocked { reason } => reason,
        other => panic!("expected {sql:?} to be blocked, got {other:?}"),
    }
}

fn unchanged(user: &str, sql: &str) {
    match analyze_as(user, sql) {
        Outcome::Unchanged { .. } => (),
        other => panic!("expected {sql:?} to be unchanged, got {other:?}"),
    }
}

const SSN: &str = r#"('XXX-XX-' || "right"(ssn, 4))::varchar"#;

fn raw_columns(user: &str, sql: &str) -> std::collections::BTreeSet<String> {
    match analyze_as(user, sql) {
        Outcome::Unchanged { raw, .. } | Outcome::Rewritten { raw, .. } => raw,
        Outcome::Blocked { reason } => panic!("{sql:?} blocked: {reason}"),
    }
}

#[test]
fn test_projection() {
    assert_eq!(
        rewritten("anonymous", "SELECT ssn FROM users"),
        format!("SELECT {SSN} AS ssn FROM users")
    );
    // Output names are kept, including through casts.
    assert_eq!(
        rewritten("anonymous", "SELECT ssn::text FROM users"),
        format!("SELECT {SSN}::text AS ssn FROM users")
    );
    assert_eq!(
        rewritten("anonymous", "SELECT ssn AS s FROM users"),
        format!("SELECT {SSN} AS s FROM users")
    );
}

#[test]
fn test_exempt_and_unmasked() {
    unchanged("admin", "SELECT ssn, email, salary FROM users");
    unchanged("anonymous", "SELECT id, name FROM users WHERE id = $1");
    unchanged("anonymous", "SELECT o.total FROM orders o");
    unchanged("anonymous", "SELECT 1");
    unchanged(
        "anonymous",
        "SELECT relname FROM pg_class WHERE relname = 'users'",
    );
    unchanged(
        "anonymous",
        "SELECT column_name FROM information_schema.columns",
    );
    unchanged("anonymous", "BEGIN");
    unchanged("anonymous", "SET statement_timeout TO 1000");
}

#[test]
fn test_masked_everywhere() {
    let sql = rewritten(
        "anonymous",
        "SELECT id FROM users WHERE ssn = $1 AND upper(ssn) LIKE 'A%' GROUP BY id, ssn HAVING max(ssn) > '1' ORDER BY ssn",
    );
    assert!(!sql.contains(" ssn = $1"), "{sql}");
    assert_eq!(sql.matches("'XXX-XX-'").count(), 5, "{sql}");
}

#[test]
fn test_conditional_mask() {
    assert_eq!(
        rewritten("anonymous", "SELECT u.email FROM users u"),
        "SELECT CASE WHEN u.opted_in THEN u.email ELSE NULL END::text AS email FROM users u"
    );
}

#[test]
fn test_star() {
    let sql = rewritten(
        "anonymous",
        "SELECT * FROM users u JOIN orders o ON o.user_id = u.id",
    );
    assert!(
        sql.starts_with("SELECT u.id AS id, u.name AS name, ('XXX-XX-'"),
        "{sql}"
    );
    assert!(sql.contains("o.*"), "{sql}");
    assert!(!sql.contains("u.*"), "{sql}");

    let sql = rewritten("anonymous", "SELECT o.*, u.* FROM users u, orders o");
    assert!(sql.starts_with("SELECT o.*, u.id AS id"), "{sql}");

    unchanged("anonymous", "SELECT * FROM orders");
    blocked("anonymous", "SELECT * FROM users JOIN orders USING (id)");
}

#[test]
fn test_column_aliases() {
    // Aliases map by position, which a stale catalog can get wrong: they
    // can't cover masked columns (`c` would be `ssn`).
    let reason = blocked("anonymous", "SELECT c FROM users AS x(a, b, c)");
    assert!(
        reason.contains("alias columns in the select list"),
        "{reason}"
    );
    blocked("anonymous", "SELECT a FROM ssn_flags AS f(a, b)");
    // Before the first masked column, and for users without masked columns,
    // they're fine.
    unchanged("anonymous", "SELECT b FROM users AS x(a, b) WHERE x.a = $1");
    unchanged("anonymous", "SELECT o.t FROM orders AS o(i, u, t)");
    unchanged("admin", "SELECT c FROM users AS x(a, b, c)");
    unchanged("anonymous", "SELECT f.a FROM ssn_flags AS f(a)");
}

#[test]
fn test_whole_row() {
    let sql = rewritten("anonymous", "SELECT row_to_json(u) FROM users u");
    assert!(sql.contains("ROW(u.id, u.name, ('XXX-XX-'"), "{sql}");
    // Output names of function calls are pinned, since calls can be inlined.
    assert!(
        sql.ends_with("::public.users) AS row_to_json FROM users u"),
        "{sql}"
    );

    let sql = rewritten("anonymous", "SELECT to_jsonb(u.*) FROM users u");
    assert!(sql.contains("ROW(u.id"), "{sql}");

    let sql = rewritten("anonymous", "SELECT u FROM users u");
    assert!(sql.contains("ROW(u.id"), "{sql}");

    unchanged("anonymous", "SELECT row_to_json(o) FROM orders o");
}

#[test]
fn test_subqueries_and_ctes() {
    let sql = rewritten("anonymous", "SELECT x.ssn FROM (SELECT ssn FROM users) x");
    assert_eq!(sql.matches("'XXX-XX-'").count(), 1, "{sql}");

    let sql = rewritten(
        "anonymous",
        "WITH s AS (SELECT ssn FROM users) SELECT ssn FROM s",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 1, "{sql}");

    // Correlated reference to the outer query.
    let sql = rewritten(
        "anonymous",
        "SELECT (SELECT ssn FROM orders o WHERE o.user_id = u.id LIMIT 1) FROM users u",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    let sql = rewritten(
        "anonymous",
        "SELECT id FROM orders WHERE user_id IN (SELECT id FROM users WHERE ssn = $1)",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    let sql = rewritten(
        "anonymous",
        "WITH RECURSIVE r AS (SELECT id, ssn FROM users UNION ALL SELECT id, ssn FROM r) SELECT ssn FROM r",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 1, "{sql}");
}

#[test]
fn test_set_operations() {
    let sql = rewritten(
        "anonymous",
        "SELECT ssn FROM users UNION SELECT name FROM orders o, users ORDER BY 1",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 1, "{sql}");
}

#[test]
fn test_dml() {
    let sql = rewritten(
        "anonymous",
        "INSERT INTO orders (user_id, total) SELECT id, salary FROM users",
    );
    assert!(sql.contains("round(salary::numeric, -4)"), "{sql}");

    let sql = rewritten(
        "anonymous",
        "UPDATE users SET name = ssn WHERE id = 1 RETURNING ssn",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 2, "{sql}");

    let sql = rewritten("anonymous", "DELETE FROM users WHERE id = $1 RETURNING *");
    assert!(
        sql.contains("RETURNING users.id AS id, users.name AS name, ('XXX-XX-'"),
        "{sql}"
    );

    let sql = rewritten(
        "anonymous",
        "INSERT INTO users (id) VALUES (1) ON CONFLICT DO NOTHING RETURNING *",
    );
    assert!(sql.contains("RETURNING users.id AS id"), "{sql}");
    assert!(!sql.contains("excluded"), "{sql}");

    unchanged("anonymous", "DELETE FROM orders RETURNING *");

    let sql = rewritten(
        "anonymous",
        "INSERT INTO users (id, ssn) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = users.ssn, ssn = excluded.ssn RETURNING ssn",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 2, "{sql}");
    assert!(sql.contains("ssn = excluded.ssn"), "{sql}");

    // Writing to a masked column is fine.
    unchanged("anonymous", "UPDATE users SET ssn = $1 WHERE id = $2");
}

#[test]
fn test_copy() {
    let sql = rewritten("anonymous", "COPY users TO STDOUT WITH (FORMAT csv)");
    assert!(sql.starts_with("COPY (SELECT id AS id"), "{sql}");
    assert!(sql.ends_with("FROM public.users) TO STDOUT CSV"), "{sql}");

    let sql = rewritten("anonymous", "COPY users (id, ssn) TO STDOUT");
    assert!(
        sql.starts_with("COPY (SELECT id AS id, ('XXX-XX-'"),
        "{sql}"
    );

    let sql = rewritten("anonymous", "COPY (SELECT ssn FROM users) TO STDOUT");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    unchanged("anonymous", "COPY users FROM STDIN");
    unchanged("anonymous", "COPY orders TO STDOUT");
    blocked("anonymous", "COPY users TO PROGRAM 'cat'");
    blocked("anonymous", "COPY users TO '/tmp/users.csv'");
}

/// COPY options the deparser can't print would crash the process, whether
/// the statement is rewritten or only logged. Postgres rejects them anyway.
#[test]
fn test_copy_options_deparser_can_print() {
    for sql in [
        "COPY users TO STDOUT WITH (FORMAT)",
        "COPY users TO STDOUT WITH (format 1)",
        "COPY users TO STDOUT WITH (format *)",
        "COPY users TO STDOUT WITH (delimiter)",
        "COPY users TO STDOUT WITH (delimiter 1)",
        "COPY users TO STDOUT WITH (delimiter (a))",
        "COPY users TO STDOUT WITH (null)",
        "COPY users TO STDOUT WITH (quote 1)",
        "COPY users TO STDOUT WITH (escape)",
        "COPY users TO STDOUT WITH (encoding 1)",
        "COPY users TO STDOUT WITH (force_quote)",
        "COPY users TO STDOUT WITH (format csv, force_not_null 1)",
        "COPY users TO STDOUT WITH (force_null)",
        "COPY users TO STDOUT (delimiter)",
        "/* hint */ COPY users TO STDOUT WITH (delimiter)",
        "COPY (SELECT ssn FROM users) TO STDOUT WITH (delimiter)",
        // Unchanged statements are deparsed when another one is rewritten.
        "SELECT ssn FROM users; COPY orders FROM STDIN WITH (delimiter)",
        "COPY orders TO STDOUT WITH (null)",
    ] {
        for user in ["anonymous", "support"] {
            let reason = blocked(user, sql);
            assert!(reason.contains("COPY option"), "{sql}: {reason}");
        }
    }

    // Valid options are kept.
    let sql = rewritten(
        "anonymous",
        "COPY users TO STDOUT WITH (format csv, force_quote *, delimiter ',', null '', header)",
    );
    assert!(sql.contains("FORCE_QUOTE *"), "{sql}");
    let sql = rewritten(
        "anonymous",
        "COPY users (id, ssn) TO STDOUT CSV FORCE QUOTE id",
    );
    assert!(sql.ends_with("TO STDOUT CSV FORCE QUOTE id"), "{sql}");
}

#[test]
fn test_wrapped_statements() {
    for sql in [
        "EXPLAIN ANALYZE SELECT ssn FROM users",
        "DECLARE c CURSOR FOR SELECT ssn FROM users",
        "PREPARE p AS SELECT ssn FROM users WHERE id = $1",
        "CREATE TABLE copy AS SELECT ssn FROM users",
        "SELECT ssn INTO copy FROM users",
    ] {
        assert!(rewritten("anonymous", sql).contains("'XXX-XX-'"), "{sql}");
    }
}

#[test]
fn test_partitions_inherit() {
    assert!(rewritten("anonymous", "SELECT ssn FROM users_2024").contains("'XXX-XX-'"));
}

#[test]
fn test_raw_search() {
    // support may search on the raw value but sees NULL.
    assert_eq!(
        rewritten("support", "SELECT ssn FROM users WHERE ssn = $1"),
        "SELECT NULL::varchar AS ssn FROM users WHERE ssn = $1"
    );

    for sql in [
        "SELECT id FROM users WHERE ssn = $1",
        "SELECT id FROM users WHERE ssn IN ($1, $2)",
        "SELECT id FROM users WHERE lower(ssn) = lower($1)",
        "SELECT id FROM users WHERE ssn IS NULL",
        "SELECT id FROM users WHERE ssn = ANY($1)",
        "SELECT o.id FROM orders o JOIN users u ON u.ssn = $1",
        "UPDATE users SET name = $1 WHERE ssn = $2",
    ] {
        assert!(
            raw_columns("support", sql).contains("public.users.ssn"),
            "{sql}"
        );
        unchanged("support", sql);
    }

    // Shapes that could exfiltrate the value stay masked.
    for sql in [
        "SELECT id FROM users WHERE ssn::int = 1",
        "SELECT id FROM users WHERE ssn LIKE $1",
        "SELECT id FROM users WHERE ssn > $1",
        "SELECT id FROM users WHERE pg_notify('c', ssn) IS NULL",
        "SELECT id FROM users WHERE set_config('x', ssn, false) = 'a'",
        "SELECT id FROM users WHERE ssn || 'x' = $1",
    ] {
        let rewritten = rewritten("support", sql);
        assert!(rewritten.contains("NULL"), "{sql} => {rewritten}");
    }

    // Other roles can't search raw values.
    assert!(rewritten("anonymous", "SELECT id FROM users WHERE ssn = $1").contains("'XXX-XX-'"));
}

#[test]
fn test_blocked() {
    for sql in [
        "SELECT my_func(id) FROM users",
        "SELECT public.lower(name) FROM users",
        "SELECT query_to_xml('SELECT ssn FROM users', true, true, '')",
        "SELECT * FROM pg_stats WHERE tablename = 'users'",
        "SELECT * FROM pg_catalog.pg_statistic",
        "DO $$ BEGIN PERFORM 1; END $$",
        "CREATE VIEW v AS SELECT ssn FROM users",
        "CREATE FUNCTION f() RETURNS int AS 'SELECT 1' LANGUAGE sql",
        "SELECT name FROM user_names",
        "SELECT * FROM unknown_table",
        "CREATE TEMP TABLE users (ssn text)",
        "SELECT 1 FROM users LIMIT salary",
        "SELECT id FROM orders WHERE my_func(id)",
        "MERGE INTO users u USING orders o ON u.id = o.user_id WHEN MATCHED THEN DELETE",
        "SELECT FROM",
    ] {
        blocked("anonymous", sql);
    }

    unchanged("anonymous", "SELECT public.safe_fn(id) FROM orders");
}

#[test]
fn test_multiple_statements() {
    let sql = rewritten("anonymous", "SELECT 1; SELECT ssn FROM users");
    assert_eq!(sql, format!("SELECT 1;SELECT {SSN} AS ssn FROM users"));
}

#[test]
fn test_leading_comments_kept() {
    let sql = rewritten("anonymous", "/* pgdog_shard: 1 */ SELECT ssn FROM users");
    assert!(sql.starts_with("/* pgdog_shard: 1 */ SELECT"), "{sql}");
}

fn touches_masked(user: &str, sql: &str) -> bool {
    match analyze_as(user, sql) {
        Outcome::Unchanged { touches_masked, .. } | Outcome::Rewritten { touches_masked, .. } => {
            touches_masked
        }
        Outcome::Blocked { reason } => panic!("{sql:?} blocked: {reason}"),
    }
}

#[test]
fn test_views_inlined() {
    let sql = rewritten("anonymous", "SELECT ssn FROM user_ssns");
    assert_eq!(
        sql,
        format!(
            "SELECT ssn AS ssn FROM (SELECT users.id AS id, {} AS ssn FROM public.users) user_ssns(id, ssn)",
            SSN.replace("(ssn", "(users.ssn")
        )
    );

    // Aliases and column aliases are kept.
    let sql = rewritten(
        "anonymous",
        "SELECT v.s FROM user_ssns AS v(i, s) WHERE v.i = 1",
    );
    assert!(sql.contains(") v(i, s) WHERE v.i = 1"), "{sql}");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    // Nested views and `*`.
    assert!(rewritten("anonymous", "SELECT ssn FROM nested_v").contains("'XXX-XX-'"));
    assert!(rewritten("anonymous", "SELECT * FROM user_ssns").contains("'XXX-XX-'"));
    assert!(rewritten("anonymous", "TABLE user_ssns").contains("'XXX-XX-'"));
    let sql = rewritten(
        "anonymous",
        "SELECT o.id FROM orders o JOIN user_ssns u ON u.id = o.user_id WHERE u.ssn = $1",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    // Views over unmasked columns are left alone.
    unchanged("anonymous", "SELECT name FROM user_names_v");
    unchanged(
        "anonymous",
        "UPDATE user_names_v SET name = $1 WHERE id = $2",
    );
    unchanged("admin", "SELECT ssn FROM user_ssns");

    // Writes through views over masked columns, and other non-FROM uses, are blocked.
    for sql in [
        "UPDATE user_ssns SET ssn = $1 WHERE id = $2",
        "DELETE FROM user_ssns WHERE id = 1",
        "INSERT INTO user_ssns (id) VALUES (1)",
        "LOCK TABLE user_ssns",
    ] {
        blocked("anonymous", sql);
    }
}

#[test]
fn test_views_as_tables() {
    // security_barrier views aren't inlined: passed-through columns are masked,
    // derived ones blocked.
    let sql = rewritten("anonymous", "SELECT ssn FROM ssn_barrier");
    assert!(sql.ends_with("FROM ssn_barrier"), "{sql}");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    unchanged("anonymous", "SELECT id FROM ssn_barrier");
    assert!(blocked("anonymous", "SELECT loud FROM ssn_barrier").contains("computed from masked"));
    blocked("anonymous", "SELECT * FROM ssn_barrier");
    unchanged("admin", "SELECT loud FROM ssn_barrier");

    // Derived columns are blocked as whole conditions too: filtering on them
    // reads the masked values they're computed from.
    for sql in [
        "SELECT id FROM ssn_flags WHERE starts_9",
        "SELECT id FROM ssn_flags f WHERE (f.starts_9)",
        "SELECT count(*) FROM ssn_flags GROUP BY starts_9 HAVING starts_9",
        "DELETE FROM orders USING ssn_flags f WHERE f.starts_9",
        "UPDATE orders SET total = 0 FROM ssn_flags f WHERE f.starts_9",
        "SELECT id FROM ssn_barrier WHERE loud",
        "SELECT id FROM ssn_flags WHERE starts_9 = true",
    ] {
        assert!(
            blocked("anonymous", sql).contains("computed from masked"),
            "{sql}"
        );
    }
    unchanged("admin", "SELECT id FROM ssn_flags WHERE starts_9");
    unchanged("anonymous", "SELECT id FROM users WHERE opted_in");

    // Materialized views hold their own data.
    let sql = rewritten("anonymous", "SELECT ssn, n FROM ssn_counts");
    assert!(
        sql.contains("'XXX-XX-'") && sql.ends_with("FROM ssn_counts"),
        "{sql}"
    );

    // With inline_views off, every view is a table.
    let config = CONFIG.replacen("[general]", "[general]\ninline_views = false", 1);
    let Outcome::Rewritten { sql, .. } =
        analyze_with(&config, "anonymous", "SELECT ssn FROM user_ssns")
    else {
        panic!("rewrite");
    };
    assert!(sql.ends_with("FROM user_ssns"), "{sql}");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
}

#[test]
fn test_functions() {
    // Functions that don't read masked columns are left alone.
    unchanged("anonymous", "SELECT last4(name) FROM users");
    unchanged("anonymous", "SELECT count_users()");
    unchanged("anonymous", "SELECT public.same('a', 'b')");

    // Functions that do are inlined, with masks applied.
    let sql = rewritten("anonymous", "SELECT user_ssn(o.user_id) FROM orders o");
    assert!(
        sql.starts_with(
            "SELECT (SELECT (SELECT __pgdog_body.__pgdog_out AS __pgdog_out FROM (SELECT"
        ),
        "{sql}"
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    assert!(
        sql.contains("FROM (SELECT o.user_id::bigint AS uid) __pgdog_args)"),
        "{sql}"
    );
    assert!(sql.ends_with("AS user_ssn FROM orders o"), "{sql}");

    for sql in [
        "SELECT user_ssn_p($1)",
        "SELECT atomic_ssn(1)",
        "SELECT id FROM orders WHERE user_ssn(user_id) = $1",
        "SELECT public.user_ssn(1)",
    ] {
        let rewritten = rewritten("anonymous", sql);
        assert!(rewritten.contains("'XXX-XX-'"), "{sql} => {rewritten}");
        assert!(rewritten.contains("__pgdog_args"), "{sql} => {rewritten}");
        assert!(
            !rewritten.contains("$1)") || sql.contains("$1"),
            "{rewritten}"
        );
    }

    // Set-returning functions in FROM.
    let sql = rewritten("anonymous", "SELECT s.ssn FROM ssns() s WHERE s.id = 1");
    assert!(
        sql.contains("FROM LATERAL (SELECT __pgdog_body.__pgdog_c1::bigint AS id"),
        "{sql}"
    );
    assert!(sql.contains(") s(id, ssn) WHERE s.id = 1"), "{sql}");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    // Scalar functions in FROM are one row.
    let sql = rewritten("anonymous", "SELECT * FROM user_ssn(1) AS s(x)");
    assert!(
        sql.starts_with("SELECT * FROM LATERAL (SELECT (SELECT (SELECT"),
        "{sql}"
    );
    assert!(sql.ends_with(") s(x)"), "{sql}");

    // Operators are calls to their functions.
    unchanged("anonymous", "SELECT 'a' === 'b'");
    let sql = rewritten("anonymous", "SELECT id FROM orders WHERE id @@@ user_id");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    // Nothing changes for exempt users.
    unchanged("admin", "SELECT user_ssn(1)");

    for (sql, reason) in [
        ("SELECT user_ssn_definer(1)", "SECURITY DEFINER"),
        ("SELECT volatile_ssn(1)", "VOLATILE"),
        ("SELECT plpgsql_fn()", "plpgsql"),
        ("SELECT recursive_fn(1)", "recursive"),
        ("SELECT unknown_fn(1)", "isn't in the catalog"),
        ("SELECT user_ssn(uid => 1)", "named arguments"),
        ("SELECT ssns()", "returns a set"),
        ("SELECT * FROM ssns() WITH ORDINALITY", "ORDINALITY"),
    ] {
        let blocked = blocked("anonymous", sql);
        assert!(blocked.contains(reason), "{sql}: {blocked}");
    }
}

#[test]
fn test_scrub_flag() {
    assert!(touches_masked(
        "anonymous",
        "UPDATE users SET name = $1 WHERE id = $2"
    ));
    assert!(touches_masked(
        "anonymous",
        "INSERT INTO users (id, name) VALUES ($1, $2)"
    ));
    assert!(touches_masked("anonymous", "SELECT ssn FROM users"));
    assert!(touches_masked("anonymous", "SELECT ssn FROM user_ssns"));
    assert!(touches_masked("anonymous", "SELECT count_users()"));
    assert!(!touches_masked("anonymous", "SELECT id FROM orders"));
}

#[test]
fn test_conditional_masks_bind_their_own_arguments() {
    // Two conditional policies with different argument names: each column must
    // bind its own policy's arguments.
    let config = r#"
[[policies]]
name = "by_flag"
data_type = "text"
arguments = ["flag"]
mask = "sql"
expression = "CASE WHEN flag THEN val ELSE NULL END"

[[policies]]
name = "by_amount"
data_type = "text"
arguments = ["amount"]
mask = "sql"
expression = "CASE WHEN amount > 0 THEN val ELSE NULL END"

[[masked_columns]]
name = "users"
column = "email"
policy = "by_flag"
arguments = ["opted_in"]

[[masked_columns]]
name = "users"
column = "ssn"
policy = "by_amount"
arguments = ["salary"]
"#;
    let Outcome::Rewritten { sql, .. } =
        analyze_with(config, "anonymous", "SELECT email, ssn FROM users")
    else {
        panic!("expected a rewrite");
    };
    assert!(sql.contains("CASE WHEN users.opted_in THEN email"), "{sql}");
    assert!(sql.contains("CASE WHEN users.salary > 0 THEN ssn"), "{sql}");
}

/// Statements with literals, covering every analyzer feature. The shape path
/// (analyze once with placeholders, render with literals) must agree with
/// analyzing each statement.
const SHAPE_CORPUS: &[&str] = &[
    "SELECT 5",
    "SELECT 'a' AS x, true, NULL, -1, 1.5, -2.5e3",
    "SELECT ssn, 'lit' FROM users WHERE id = 3",
    "SELECT ssn FROM users WHERE ssn = '123-45-6789'",
    "SELECT id FROM users WHERE ssn IN ('a', 'b', 'c') AND id > -5",
    "SELECT id FROM users WHERE lower(ssn) = lower('ABC')",
    "SELECT id FROM users WHERE ssn LIKE 'A%' AND name ILIKE '%x%'",
    "SELECT id FROM users WHERE ssn IS NULL OR salary > 100000",
    "SELECT id FROM users WHERE ssn::int = 5",
    "SELECT date_trunc('day', now()), ssn::text, '2020-01-01'::date FROM users",
    "SELECT interval '1 day', ssn FROM users LIMIT 10 OFFSET 5",
    "SELECT ssn FROM users ORDER BY 1 DESC LIMIT 1",
    "SELECT ssn, count(*) FROM users GROUP BY 1 HAVING count(*) > 2",
    "SELECT CASE WHEN salary > 1000 THEN 'high' ELSE ssn END FROM users",
    "SELECT * FROM users WHERE id = 1",
    "SELECT u.*, 'x' FROM users u WHERE u.salary BETWEEN 1 AND 2",
    "SELECT row_to_json(u), 1 FROM users u WHERE id = 7",
    "SELECT x.ssn FROM (SELECT ssn, 1 AS one FROM users WHERE id = 2) x WHERE x.one = 1",
    "WITH s AS (SELECT ssn FROM users WHERE id = 1) SELECT ssn, 'k' FROM s",
    "SELECT ssn FROM users WHERE id = 1 UNION SELECT 'constant' ORDER BY 1",
    "SELECT (SELECT ssn FROM users WHERE id = 1 LIMIT 1), 2",
    "SELECT o.id FROM orders o JOIN users u ON u.ssn = 'abc' AND o.total > 10",
    "SELECT id FROM users WHERE ssn = ANY(ARRAY['a', 'b'])",
    "SELECT ssn FROM user_ssns WHERE id = 1",
    "SELECT ssn FROM nested_v LIMIT 3",
    "SELECT id, ssn FROM ssn_barrier WHERE id = 5",
    "SELECT n FROM ssn_counts WHERE n > 1",
    "SELECT name FROM user_names_v WHERE id = 1",
    "SELECT last4('123456789')",
    "SELECT user_ssn(5)",
    "SELECT atomic_ssn(1), 'x'",
    "SELECT * FROM ssns() AS s(id bigint, ssn text) WHERE id = 1",
    "SELECT public.same('a', 'b')",
    "SELECT 'a' === 'b'",
    "INSERT INTO users (id, ssn, name) VALUES (1, '123', 'n')",
    "INSERT INTO orders (user_id, total) SELECT id, salary * 2 FROM users WHERE ssn = 'x'",
    "INSERT INTO users (id, ssn) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET name = users.ssn || '!' RETURNING ssn, 1",
    "UPDATE users SET name = 'x', salary = salary + 1 WHERE ssn = 'abc' RETURNING ssn",
    "UPDATE users SET name = ssn WHERE id = 1",
    "DELETE FROM users WHERE id = 1 RETURNING *",
    "SELECT 1; SELECT ssn FROM users WHERE id = 2",
    "/* pgdog_shard: 1 */ SELECT ssn FROM users WHERE id = 1",
    "SELECT my_func(1) FROM users",
    "SELECT query_to_xml('SELECT ssn FROM users', true, true, '')",
    "SELECT * FROM pg_stats WHERE tablename = 'users'",
    "SELECT name FROM user_names WHERE name = 'x'",
    "SELECT 1 FROM unknown_table WHERE x = 1",
    "SELECT plpgsql_fn() + 1",
    "SELECT volatile_ssn(1)",
    "SELECT user_ssn_definer(1)",
    "SELECT (SELECT s.v FROM archive a, (SELECT ssn AS v) s LIMIT 1) FROM users u",
    "SELECT (SELECT l.v FROM archive a, LATERAL (SELECT ssn AS v) l LIMIT 1) FROM users u",
    "SELECT g FROM users u, generate_series(1, length(ssn)) g",
    "SELECT (SELECT count(*) FROM archive a, orders b JOIN orders c ON c.id = length(ssn) + 1) FROM users u",
    "SELECT 1 FROM orders b JOIN archive a ON a.ssn = 'x'",
    "UPDATE orders SET total = 0 FROM (SELECT ssn AS v FROM archive) s WHERE s.v = 'x'",
    "UPDATE users SET name = 'x' FROM archive a, LATERAL (SELECT ssn AS v) l WHERE l.v = 'y'",
    "SELECT l.*, 1 FROM users u, LATERAL (SELECT u.*) l",
    "SELECT (u).*, 1 FROM users u WHERE id = 2",
    "SELECT u.row_to_json FROM users u WHERE id = 1",
    "UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.ssn, new.ssn",
    "UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.*",
    "DELETE FROM users WHERE id = 1 RETURNING old",
    "UPDATE users SET name = 'x' RETURNING WITH (OLD AS o, NEW AS n) o.ssn, n.ssn",
    "SELECT 1 INTO users UNION SELECT 2",
    "SELECT * FROM users, XMLTABLE('/r' PASSING ('<r/>'::xml) COLUMNS a text) x",
    "SELECT * FROM users, JSON_TABLE('{}'::jsonb, '$' COLUMNS (a text PATH '$.a')) j",
    "SELECT c FROM users AS x(a, b, c) WHERE id = 1",
    "SELECT b FROM users AS x(a, b) WHERE x.a = 1",
];

/// SQL as the deparser writes it, to compare rewrites.
fn canonical(sql: &str) -> String {
    let parsed = pg_raw_parse::parse(sql)
        .unwrap_or_else(|err| panic!("rewrite doesn't parse: {err}\n{sql}"))
        .into_inner();
    pg_raw_parse::deparse_stmts(parsed.iter()).unwrap()
}

#[test]
fn test_shape_path_matches_full_analysis() {
    let mut checked = 0;
    for user in ["anonymous", "support", "admin"] {
        for sql in SHAPE_CORPUS {
            let full = analyze_as(user, sql);
            let policies = Policies::new(Config::from_toml(CONFIG).unwrap()).unwrap();
            let catalog = catalog();
            let assignments = Assignments::new(&policies, "db", &catalog);
            let profile = policies.profile(user, "db");
            let ctx = Context {
                catalog: &catalog,
                assignments: &assignments,
                policies: &policies,
                profile: &profile,
                search_path: vec!["public".into()],
            };
            let Some(shaped) = analyze_shape(sql, &ctx) else {
                continue;
            };
            checked += 1;

            match (&full, &shaped) {
                (
                    Outcome::Rewritten {
                        sql: a,
                        masked: ma,
                        raw: ra,
                        touches_masked: ta,
                        results: pa,
                    },
                    Outcome::Rewritten {
                        sql: b,
                        masked: mb,
                        raw: rb,
                        touches_masked: tb,
                        results: pb,
                    },
                ) => {
                    assert_eq!(canonical(a), canonical(b), "{user}: {sql}");
                    assert_eq!((ma, ra, ta, pa), (mb, rb, tb, pb), "{user}: {sql}");
                }
                (Outcome::Blocked { .. }, Outcome::Blocked { .. }) => (),
                (a, b) => assert_eq!(a, b, "{user}: {sql}"),
            }
        }
    }
    assert!(checked > 100, "most of the corpus has a shape: {checked}");
}

#[test]
fn test_ddl() {
    for sql in [
        "DROP TABLE IF EXISTS scratch",
        "DROP TABLE users",
        "CREATE SEQUENCE s",
        "ALTER SEQUENCE s RESTART",
        "ALTER TABLE orders ADD COLUMN note text",
        "CREATE INDEX ON orders (user_id)",
        "CREATE TABLE scratch (id int)",
        "DROP INDEX orders_idx",
        "DROP FUNCTION f()",
    ] {
        match analyze_as("anonymous", sql) {
            Outcome::Unchanged { .. } => (),
            other => panic!("{sql}: {other:?}"),
        }
    }

    for sql in [
        // Leak values through errors.
        "ALTER TABLE users ALTER COLUMN ssn TYPE int USING ssn::int",
        "CREATE INDEX ON users ((ssn::int))",
        // Unmask.
        "ALTER TABLE users RENAME COLUMN ssn TO not_ssn",
        "ALTER TABLE users RENAME TO people",
        "ALTER SCHEMA public RENAME TO other",
        "ALTER TABLE users SET SCHEMA other",
        "COMMENT ON COLUMN users.ssn IS 'nothing to see'",
        // Change what a name resolves to before PgDog reloads its catalog.
        "ALTER TABLE orders RENAME COLUMN total TO amount",
        "ALTER TABLE orders RENAME TO purchases",
        "ALTER TABLE orders DROP COLUMN total",
        "ALTER TABLE orders ADD COLUMN note text, DROP COLUMN total",
        "DROP TABLE orders CASCADE",
        "DROP TYPE mood CASCADE",
        "DROP EXTENSION pgcrypto",
        "CREATE TABLE archive (id bigint)",
        "CREATE TABLE other.orders (id bigint)",
        "CREATE SEQUENCE archive",
        "SELECT 1 AS id INTO archive",
        "CREATE TABLE user_ssns AS SELECT 1",
        // Expose rows through an unmasked table.
        "ALTER TABLE orders ATTACH PARTITION users FOR VALUES IN (1)",
        "ALTER TABLE orders INHERIT users",
        // Functions are still checked.
        "ALTER TABLE orders ADD COLUMN x text DEFAULT my_func(1)",
        "GRANT SELECT ON users TO public",
    ] {
        blocked("anonymous", sql);
    }
}

/// The test catalog with a second `archive`, in schema `other`.
fn catalog_with_other_archive() -> Catalog {
    let mut relations: Vec<Relation> = catalog().relations().cloned().collect();
    relations.push(Relation::new(
        "other",
        "archive",
        RelationKind::Table,
        vec![column("id", "bigint")],
    ));
    let mut other = Catalog::new(vec!["$user".into(), "public".into()], relations);
    other.full = true;
    other.set_system_functions(include_str!("test_builtin_functions.txt").lines());
    other.add_functions(functions());
    other
}

/// Postgres resolves names to temporary relations first, and the plugin
/// can't see them: `CREATE TEMP TABLE archive (id bigint)` would make `ssn`
/// in `SELECT (SELECT ssn FROM archive) FROM users` read `users.ssn`, while
/// the catalog says `archive.ssn`.
#[test]
fn test_temporary_relations_blocked() {
    for sql in [
        "CREATE TEMP TABLE scratch (id bigint)",
        "CREATE TEMPORARY TABLE scratch (id bigint) ON COMMIT DROP",
        "CREATE TABLE pg_temp.scratch (id bigint)",
        "CREATE TABLE pg_temp_3.scratch (id bigint)",
        "CREATE TEMP TABLE scratch AS SELECT 1 AS id",
        "SELECT 1 AS id INTO TEMP scratch",
        "SELECT 1 AS id INTO TEMP scratch UNION SELECT 2",
        "CREATE TEMP TABLE scratch (LIKE orders)",
        "CREATE TEMP SEQUENCE scratch",
        "CREATE SEQUENCE pg_temp.scratch",
        "EXPLAIN ANALYZE CREATE TEMP TABLE scratch AS SELECT 1",
    ] {
        for user in ["anonymous", "support"] {
            let reason = blocked(user, sql);
            assert!(reason.contains("temporary"), "{sql}: {reason}");
        }
    }
}

/// Dropping a relation whose name another schema shares makes the name
/// resolve to that one in Postgres, while the catalog still has the first.
#[test]
fn test_drop_shared_name_blocked() {
    let catalog = catalog_with_other_archive();
    for sql in [
        "DROP TABLE archive",
        "DROP TABLE public.archive",
        "DROP TABLE IF EXISTS orders, archive",
        "DROP VIEW other.archive",
    ] {
        match analyze_in(&catalog, CONFIG, "anonymous", sql) {
            Outcome::Blocked { reason } => assert!(reason.contains("drop"), "{sql}: {reason}"),
            other => panic!("{sql}: {other:?}"),
        }
    }
    for sql in [
        "DROP TABLE orders",
        "DROP TABLE scratch",
        "DROP INDEX archive",
    ] {
        match analyze_in(&catalog, CONFIG, "anonymous", sql) {
            Outcome::Unchanged { .. } => (),
            other => panic!("{sql}: {other:?}"),
        }
    }
}

#[test]
fn test_scope_non_lateral_subquery() {
    // A FROM subquery without LATERAL can't see `a`: `ssn` is `u.ssn`.
    let sql = rewritten(
        "anonymous",
        "SELECT (SELECT s.v FROM archive a, (SELECT ssn AS v) s LIMIT 1) FROM users u",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    // The same through a JOIN.
    let sql = rewritten(
        "anonymous",
        "SELECT (SELECT s.v FROM archive a JOIN (SELECT ssn AS v) s ON true LIMIT 1) FROM users u",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    // CTEs stay visible.
    let sql = rewritten(
        "anonymous",
        "WITH c AS (SELECT ssn FROM users) SELECT x.ssn FROM orders o, (SELECT * FROM c) x",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
}

#[test]
fn test_scope_lateral_subquery() {
    // LATERAL sees `a`, whose ssn isn't masked.
    unchanged(
        "anonymous",
        "SELECT (SELECT l.v FROM archive a, LATERAL (SELECT ssn AS v) l LIMIT 1) FROM users u",
    );
    let sql = rewritten(
        "anonymous",
        "SELECT l.v FROM users u, LATERAL (SELECT ssn AS v) l",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    // Functions in FROM are implicitly LATERAL.
    let sql = rewritten(
        "anonymous",
        "SELECT g FROM users u, generate_series(1, length(ssn)) g",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
}

#[test]
fn test_scope_join_on() {
    // The ON clause only sees `b` and `c`: `ssn` is `u.ssn`.
    let sql = rewritten(
        "anonymous",
        "SELECT (SELECT count(*) FROM archive a, orders b JOIN orders c ON c.id = length(ssn)) FROM users u",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    unchanged(
        "anonymous",
        "SELECT 1 FROM orders b JOIN archive a ON a.ssn = $1",
    );
    // Nested joins see both sides of each join.
    let sql = rewritten(
        "anonymous",
        "SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id JOIN archive a ON a.id = u.id AND u.ssn = a.ssn",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 1, "{sql}");
}

#[test]
fn test_scope_update_from_subquery() {
    // The subquery resolves its own FROM; the target is invisible to it.
    unchanged(
        "anonymous",
        "UPDATE orders SET total = 0 FROM (SELECT ssn AS v FROM archive) s WHERE s.v = $1",
    );
    // The target is visible to SET and WHERE.
    let sql = rewritten(
        "anonymous",
        "UPDATE users SET name = 'x' FROM archive a WHERE a.id = users.id AND users.ssn = $1",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
}

#[test]
fn test_scope_update_from_lateral() {
    // The target is hidden from its FROM list, even from LATERAL items: `ssn`
    // is `a.ssn`.
    unchanged(
        "anonymous",
        "UPDATE users SET name = 'x' FROM archive a, LATERAL (SELECT ssn AS v) l WHERE l.v = $1",
    );
    unchanged(
        "anonymous",
        "DELETE FROM users USING archive a, LATERAL (SELECT ssn AS v) l WHERE l.v = $1",
    );
}

#[test]
fn test_scope_outer_star() {
    // `u.*` over an outer level is expanded, not turned into a row.
    let sql = rewritten(
        "anonymous",
        "SELECT l.* FROM users u, LATERAL (SELECT u.*) l",
    );
    assert!(
        sql.contains("(SELECT u.id AS id, u.name AS name, ('XXX-XX-'"),
        "{sql}"
    );
    assert!(!sql.contains("ROW("), "{sql}");
}

#[test]
fn test_indirection_star() {
    let sql = rewritten("anonymous", "SELECT (u).* FROM users u");
    assert!(
        sql.starts_with("SELECT u.id AS id, u.name AS name, ('XXX-XX-'"),
        "{sql}"
    );
    let sql = rewritten("anonymous", "SELECT (u.*).* FROM users u");
    assert!(
        sql.starts_with("SELECT u.id AS id, u.name AS name, ('XXX-XX-'"),
        "{sql}"
    );
    // Over unmasked relations, and over a column, it's left alone.
    unchanged("anonymous", "SELECT (o).* FROM orders o");
    unchanged(
        "anonymous",
        "SELECT (x).* FROM (SELECT o AS x FROM orders o) s",
    );
}

#[test]
fn test_attribute_notation() {
    // Postgres reads `u.row_to_json` as `row_to_json(u)`, on the raw row.
    let reason = blocked("anonymous", "SELECT u.row_to_json FROM users u");
    assert!(
        reason.contains("calls row_to_json() on the whole row"),
        "{reason}"
    );
    blocked(
        "anonymous",
        "SELECT public.users.to_jsonb FROM public.users",
    );
    blocked(
        "anonymous",
        "SELECT 1 FROM users u WHERE u.row_to_json IS NOT NULL",
    );
    blocked("anonymous", "SELECT id FROM users u WHERE u.some_flag");
    unchanged("anonymous", "SELECT o.row_to_json FROM orders o");
    // System columns are columns.
    unchanged("anonymous", "SELECT u.ctid, u.xmin FROM users u");
    unchanged("admin", "SELECT u.row_to_json FROM users u");
    let sql = rewritten("anonymous", "SELECT row_to_json(u) FROM users u");
    assert!(sql.contains("ROW(u.id, u.name, ('XXX-XX-'"), "{sql}");
}

#[test]
fn test_returning_old_new() {
    let sql = rewritten(
        "anonymous",
        "UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.ssn, new.ssn",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 2, "{sql}");

    let sql = rewritten(
        "anonymous",
        "UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.*",
    );
    assert!(
        sql.contains("RETURNING old.id AS id, old.name AS name, ('XXX-XX-'"),
        "{sql}"
    );

    let sql = rewritten("anonymous", "DELETE FROM users WHERE id = 1 RETURNING old");
    assert!(sql.contains("ROW(old.id, old.name, ('XXX-XX-'"), "{sql}");

    let sql = rewritten(
        "anonymous",
        "UPDATE users SET name = 'x' RETURNING WITH (OLD AS o, NEW AS n) o.ssn, n.ssn",
    );
    assert_eq!(sql.matches("'XXX-XX-'").count(), 2, "{sql}");

    let sql = rewritten(
        "anonymous",
        "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET name = 'x' RETURNING old.ssn",
    );
    assert!(sql.contains("'XXX-XX-'"), "{sql}");

    // `old` and `new` aren't covered by `*`, or by unqualified names.
    let sql = rewritten(
        "anonymous",
        "UPDATE users SET name = 'x' WHERE id = 1 RETURNING *",
    );
    assert!(
        sql.contains("RETURNING users.id AS id, users.name AS name, ('XXX-XX-'"),
        "{sql}"
    );
    assert!(!sql.contains("old."), "{sql}");
    unchanged("anonymous", "DELETE FROM orders RETURNING old.total");
}

#[test]
fn test_merge_anywhere() {
    for sql in [
        "EXPLAIN ANALYZE MERGE INTO orders o USING users u ON o.user_id = u.id WHEN MATCHED THEN UPDATE SET total = 0",
        "PREPARE p AS MERGE INTO orders o USING users u ON o.user_id = u.id WHEN MATCHED THEN DELETE",
    ] {
        let reason = blocked("anonymous", sql);
        assert!(reason.contains("MERGE"), "{sql}: {reason}");
    }
    // A parse error is a block too.
    blocked(
        "anonymous",
        "WITH m AS (MERGE INTO orders o USING users u ON o.user_id = u.id WHEN MATCHED THEN DELETE RETURNING o.id) SELECT * FROM m",
    );
}

#[test]
fn test_search_path_change() {
    for (sql, reason) in [
        (
            "SET search_path TO other; SELECT ssn FROM users",
            "name resolution",
        ),
        (
            "SET search_path TO public; SELECT ssn FROM users",
            "name resolution",
        ),
        (
            "SELECT set_config('search_path', 'other', false); SELECT id FROM orders",
            "set_config",
        ),
        (
            "SELECT set_config('search_path', 'public', false); SELECT ssn FROM users",
            "set_config",
        ),
        ("DISCARD ALL; SELECT * FROM orders", "name resolution"),
        ("RESET ALL; SELECT * FROM orders", "name resolution"),
        (
            "SET LOCAL search_path TO other; SELECT 1 FROM orders",
            "name resolution",
        ),
        (
            "SET \"Search_Path\" TO other; SELECT 1 FROM orders",
            "name resolution",
        ),
        (
            "SET SCHEMA 'other'; SELECT 1 FROM orders",
            "name resolution",
        ),
        ("SET ROLE someone; TABLE orders", "name resolution"),
        (
            "SET search_path TO other; SELECT last4('x')",
            "name resolution",
        ),
        // Bodies resolve names with the new path, even if the call is qualified.
        (
            "SET search_path TO other; SELECT public.count_users()",
            "name resolution",
        ),
        // Postgres analyzes prepared statements again with the new path.
        ("SET search_path TO other; EXECUTE p(1)", "name resolution"),
        (
            "SET search_path TO other; EXPLAIN EXECUTE p(1)",
            "name resolution",
        ),
        (
            "SET search_path TO other; SELECT 'a' === 'b'",
            "name resolution",
        ),
        (
            "SET search_path TO other; COPY orders TO STDOUT",
            "name resolution",
        ),
        (
            "SET search_path TO other; CREATE TABLE t (id int)",
            "name resolution",
        ),
        (
            "SET search_path TO other; ALTER TABLE orders ADD COLUMN x int",
            "name resolution",
        ),
        (
            "SET search_path TO other; SELECT ssn FROM user_ssns",
            "name resolution",
        ),
        (
            "SELECT set_config('search_path', 'other', false) FROM orders",
            "set_config",
        ),
        (
            "SELECT id, pg_catalog.set_config('SEARCH_PATH', 'other', true) FROM orders",
            "set_config",
        ),
        ("SELECT set_config($1, 'x', false)", "set_config"),
        (
            "SELECT * FROM set_config('search_path', 'x', false)",
            "set_config",
        ),
        (
            "SELECT set_config('role', 'x', false); SELECT id FROM orders",
            "name resolution",
        ),
        (
            "DROP TABLE archive; SELECT ssn FROM users",
            "name resolution",
        ),
        (
            "ALTER TABLE archive ADD COLUMN note text; SELECT ssn FROM users",
            "name resolution",
        ),
        (
            "CREATE TABLE t AS SELECT 1; SELECT id FROM orders",
            "name resolution",
        ),
        ("SELECT reroute()", "changes name resolution"),
        // PgDog doesn't follow it while its query parser is off.
        (
            "SELECT set_config('search_path', 'other', false)",
            "set_config",
        ),
        (
            "SELECT pg_catalog.set_config('search_path', 'other', true)",
            "set_config",
        ),
    ] {
        let blocked = blocked("anonymous", sql);
        assert!(blocked.contains(reason), "{sql}: {blocked}");
    }

    for sql in [
        "RESET search_path; SELECT 1",
        "SET search_path TO other; SELECT 1",
        "SET ROLE someone; SELECT now()",
        "SELECT set_config('app.tenant', '42', false)",
        "SELECT set_config('app.tenant', '42', false); SELECT id FROM orders",
        "CREATE TABLE t2 (id int); SELECT 1",
        "SET statement_timeout TO 1000; SELECT id FROM orders",
        "SELECT id FROM orders; SET search_path TO other",
    ] {
        unchanged("anonymous", sql);
    }

    for sql in [
        "SELECT ssn FROM users; SET search_path TO other",
        "BEGIN; SELECT ssn FROM users; COMMIT",
    ] {
        assert!(rewritten("anonymous", sql).contains("'XXX-XX-'"), "{sql}");
    }
}

#[test]
fn test_set_config_shadowed() {
    // A user-defined set_config doesn't hide the built-in's rules.
    let catalog = catalog_shadowing_set_config();
    for sql in [
        "SELECT set_config('search_path', 'other', false) FROM orders",
        "SELECT set_config('search_path', 'other', false); SELECT 1",
    ] {
        assert!(
            matches!(analyze_in(&catalog, CONFIG, "anonymous", sql), Outcome::Blocked { reason } if reason.contains("set_config")),
            "{sql}"
        );
    }
}

#[test]
fn test_shadowing_wrappers() {
    for sql in [
        "EXPLAIN ANALYZE CREATE TABLE users AS SELECT 1",
        "SELECT 1 INTO users UNION SELECT 2",
    ] {
        let reason = blocked("anonymous", sql);
        assert!(reason.contains("shadow"), "{sql}: {reason}");
    }
}

#[test]
fn test_table_functions_are_items() {
    let sql = rewritten(
        "anonymous",
        "SELECT * FROM users, XMLTABLE('/r' PASSING ('<r/>'::xml) COLUMNS a text) x",
    );
    assert!(sql.contains(", x.* FROM users, "), "{sql}");
    assert!(sql.ends_with(" AS x"), "{sql}");

    let sql = rewritten(
        "anonymous",
        "SELECT * FROM users, JSON_TABLE('{}'::jsonb, '$' COLUMNS (a text PATH '$.a')) j",
    );
    assert!(sql.contains(", j.* FROM users, "), "{sql}");

    unchanged(
        "anonymous",
        "SELECT x.a FROM XMLTABLE('/r' PASSING ('<r/>'::xml) COLUMNS a text) x",
    );
    // Their columns are known, so names don't resolve past them.
    unchanged(
        "anonymous",
        "SELECT (SELECT ssn FROM JSON_TABLE('{}'::jsonb, '$' COLUMNS (ssn text PATH '$.a', NESTED PATH '$.b' COLUMNS (b int))) j) FROM users",
    );
}
