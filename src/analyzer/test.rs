use super::*;
use crate::catalog::{Column, Relation, RelationKind};
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
    Column {
        name: name.into(),
        data_type: data_type.into(),
    }
}

fn relation(name: &str, kind: RelationKind, columns: Vec<Column>) -> Relation {
    Relation {
        schema: "public".into(),
        name: name.into(),
        kind,
        columns,
        parent: None,
    }
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

    Catalog::new(
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
            relation(
                "user_names",
                RelationKind::View,
                vec![column("name", "text")],
            ),
        ],
    )
}

pub(crate) fn analyze_as(user: &str, sql: &str) -> Outcome {
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
        Outcome::Unchanged { raw } | Outcome::Rewritten { raw, .. } => raw,
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
    assert!(sql.ends_with("::public.users) FROM users u"), "{sql}");

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
