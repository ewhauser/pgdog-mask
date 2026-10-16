use super::*;
use crate::catalog::{Column, Function, Operator, Relation, RelationKind};
use crate::config::Config;

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
    Column::new(name, data_type)
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
    ]);
    catalog
}

pub(crate) fn analyze_as(user: &str, sql: &str) -> Outcome {
    analyze_with(CONFIG, user, sql)
}

fn analyze_with(config: &str, user: &str, sql: &str) -> Outcome {
    let policies = Policies::new(Config::from_toml(config).unwrap()).unwrap();
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
    // `c` is `ssn` under the alias.
    let sql = rewritten("anonymous", "SELECT c FROM users AS x(a, b, c)");
    assert!(sql.contains("'XXX-XX-'"), "{sql}");
    assert!(sql.contains("AS c"), "{sql}");
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

#[test]
fn test_wrapped_statements() {
    for sql in [
        "EXPLAIN ANALYZE SELECT ssn FROM users",
        "DECLARE c CURSOR FOR SELECT ssn FROM users",
        "PREPARE p AS SELECT ssn FROM users WHERE id = $1",
        "CREATE TABLE copy AS SELECT ssn FROM users",
        "SELECT ssn INTO TEMP copy FROM users",
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
        ("SELECT unknown_fn(1)", "isn't in the schema snapshot"),
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
