//! Canary leak tests.
//!
//! Masked columns are seeded with unique canary values. Adversarial statements
//! are analyzed as a masked user and whatever the analyzer lets through is run
//! against Postgres. No canary may appear anywhere in what comes back: rows,
//! errors, notices or COPY data.
//!
//! Requires Postgres; set `PGDOG_MASKING_TEST_URL` to override the default
//! `host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog`.
use futures_util::{StreamExt as _, pin_mut};
use pgdog_masking::analyzer::{Context, Outcome, analyze};
use pgdog_masking::catalog::{Catalog, Column, Relation, RelationKind};
use pgdog_masking::config::Config;
use pgdog_masking::profile::{Assignments, Policies};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

const SCHEMA: &str = "masking_canary";

/// Values that must never reach a masked user.
const CANARIES: &[&str] = &["CANARYSSN", "canaryemail", "987654.32"];

const CONFIG: &str = r#"
[[users]]
name = "admin"
roles = ["pii_admin"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "sql"
expression = "'XXX-XX-' || right(val, 4)"

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies]]
name = "email"
data_type = "text"
mask = "email"

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

[[masked_columns]]
name = "users"
column = "salary"
policy = "salary"
"#;

async fn connect() -> Client {
    let url = std::env::var("PGDOG_MASKING_TEST_URL")
        .unwrap_or_else(|_| "host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog".into());
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .expect("connect to Postgres (set PGDOG_MASKING_TEST_URL)");
    tokio::spawn(connection);
    client
}

async fn setup(client: &Client) {
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {SCHEMA} CASCADE;
             CREATE SCHEMA {SCHEMA};
             SET search_path TO {SCHEMA};
             CREATE TABLE users (
                id BIGINT PRIMARY KEY,
                name TEXT,
                ssn VARCHAR(32),
                email TEXT,
                salary NUMERIC
             );
             CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total NUMERIC);
             INSERT INTO users VALUES
                (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com', 987654.32),
                (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com', 987654.32);
             INSERT INTO orders VALUES (1, 1, 10), (2, 2, 20);"
        ))
        .await
        .expect("setup");
}

/// Load the test schema the way PgDog's schema loader would see it.
async fn catalog(client: &Client) -> Catalog {
    let mut relations = vec![];
    for table in ["users", "orders"] {
        let rows = client
            .query(
                "SELECT column_name::text, data_type::text FROM information_schema.columns
                 WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
                &[&SCHEMA, &table],
            )
            .await
            .expect("columns");
        relations.push(Relation {
            schema: SCHEMA.into(),
            name: table.into(),
            kind: RelationKind::Table,
            columns: rows
                .iter()
                .map(|row| Column {
                    name: row.get(0),
                    data_type: row.get(1),
                })
                .collect(),
            parent: None,
        });
    }
    Catalog::new(vec![SCHEMA.into()], relations)
}

/// Everything a statement sends back, as text.
async fn run(client: &Client, sql: &str) -> Result<String, String> {
    if sql.trim_start().to_ascii_uppercase().starts_with("COPY") {
        let stream = client
            .copy_out(sql)
            .await
            .map_err(|err| format!("{err:?}"))?;
        pin_mut!(stream);
        let mut out = String::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| format!("{err:?}"))?;
            out.push_str(&String::from_utf8_lossy(&chunk));
        }
        return Ok(out);
    }

    let messages = client
        .simple_query(sql)
        .await
        .map_err(|err| format!("{err:?}"))?;
    let mut out = String::new();
    for message in messages {
        if let SimpleQueryMessage::Row(row) = message {
            for i in 0..row.len() {
                out.push_str(row.get(i).unwrap_or("NULL"));
                out.push('|');
            }
            out.push('\n');
        }
    }
    Ok(out)
}

fn leaked(text: &str) -> Option<&'static str> {
    CANARIES
        .iter()
        .copied()
        .find(|canary| text.contains(canary))
}

/// How a statement is expected to behave for a masked user.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Expect {
    /// Rewritten (or unchanged) and runs successfully.
    Runs,
    /// Blocked by the analyzer.
    Blocked,
    /// Anything, as long as nothing leaks (e.g., a Postgres error on masked data).
    NoLeak,
}

const CORPUS: &[(&str, Expect)] = &[
    ("SELECT ssn, email, salary FROM users", Expect::Runs),
    ("SELECT * FROM users", Expect::Runs),
    ("SELECT u.* FROM users u", Expect::Runs),
    (
        "SELECT * FROM users JOIN orders ON users.id = orders.user_id",
        Expect::Runs,
    ),
    ("SELECT row_to_json(u) FROM users u", Expect::Runs),
    ("SELECT u::text FROM users u", Expect::Runs),
    ("SELECT u FROM users u", Expect::Runs),
    ("SELECT to_jsonb(u.*) FROM users u", Expect::Runs),
    ("SELECT json_agg(u) FROM users u", Expect::Runs),
    (
        "SELECT ssn || '' , upper(email), salary * 1 FROM users",
        Expect::Runs,
    ),
    (
        "SELECT max(ssn), min(email), sum(salary), avg(salary) FROM users",
        Expect::Runs,
    ),
    (
        "SELECT string_agg(ssn, ','), array_agg(email) FROM users",
        Expect::Runs,
    ),
    (
        "SELECT format('%s %s', ssn, email) FROM users",
        Expect::Runs,
    ),
    ("SELECT ssn FROM users ORDER BY ssn LIMIT 1", Expect::Runs),
    ("SELECT ssn, count(*) FROM users GROUP BY ssn", Expect::Runs),
    ("SELECT (SELECT ssn FROM users LIMIT 1)", Expect::Runs),
    (
        "SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = o.user_id AND u.ssn LIKE 'CANARY%')",
        Expect::Runs,
    ),
    (
        "WITH x AS (SELECT * FROM users) SELECT * FROM x",
        Expect::Runs,
    ),
    ("SELECT * FROM (SELECT * FROM users) s", Expect::Runs),
    (
        "SELECT s.a FROM (SELECT ssn AS a FROM users) s",
        Expect::Runs,
    ),
    ("SELECT c FROM users AS t(a, b, c)", Expect::Runs),
    (
        "SELECT ssn FROM users UNION ALL SELECT email FROM users",
        Expect::Runs,
    ),
    (
        "SELECT ssn FROM users u JOIN orders o ON o.user_id = u.id",
        Expect::Runs,
    ),
    ("SELECT xmlelement(name x, ssn) FROM users", Expect::Runs),
    (
        "SELECT pg_notify('masking_canary', ssn) FROM users",
        Expect::Runs,
    ),
    (
        "SELECT set_config('masking.leak', ssn, false) FROM users",
        Expect::Runs,
    ),
    ("SELECT ssn::int FROM users", Expect::NoLeak),
    ("SELECT email::int FROM users", Expect::NoLeak),
    (
        "SELECT 1 / (CASE WHEN ssn LIKE 'CANARY%' THEN 0 ELSE 1 END) FROM users",
        Expect::Runs,
    ),
    ("COPY users TO STDOUT", Expect::Runs),
    (
        "COPY users (ssn, email) TO STDOUT WITH (FORMAT csv)",
        Expect::Runs,
    ),
    ("COPY (SELECT * FROM users) TO STDOUT", Expect::Runs),
    (
        "BEGIN; UPDATE users SET name = name RETURNING *; ROLLBACK",
        Expect::Runs,
    ),
    (
        "BEGIN; DELETE FROM users WHERE id = 1 RETURNING ssn, email; ROLLBACK",
        Expect::Runs,
    ),
    (
        "BEGIN; INSERT INTO orders SELECT 100 + id, id, salary FROM users RETURNING *; ROLLBACK",
        Expect::Runs,
    ),
    (
        "BEGIN; UPDATE orders SET total = (SELECT salary FROM users WHERE id = 1) RETURNING total; ROLLBACK",
        Expect::Runs,
    ),
    ("SELECT (u).ssn, (u).email FROM users u", Expect::Runs),
    ("SELECT (users.*).ssn FROM users", Expect::Runs),
    (
        "SELECT x FROM users u, LATERAL (SELECT u.ssn AS x) l",
        Expect::Runs,
    ),
    ("TABLE users", Expect::Runs),
    ("SELECT ssn FROM ONLY users", Expect::Runs),
    (
        "SELECT DISTINCT ON (ssn) ssn, email FROM users",
        Expect::Runs,
    ),
    (
        "SELECT first_value(ssn) OVER (ORDER BY ssn), lag(email) OVER () FROM users",
        Expect::Runs,
    ),
    ("VALUES ((SELECT ssn FROM users LIMIT 1))", Expect::Runs),
    ("SELECT ssn FROM masking_canary.users", Expect::Runs),
    (
        "SELECT masking_canary.users.ssn FROM masking_canary.users",
        Expect::Runs,
    ),
    (
        "SELECT jsonb_build_object('s', ssn, 'e', email) FROM users",
        Expect::Runs,
    ),
    (
        "SELECT id FROM users WHERE ssn IN (SELECT ssn FROM users)",
        Expect::Runs,
    ),
    ("SELECT ssn FROM users FOR UPDATE", Expect::Runs),
    (
        "BEGIN; DECLARE c CURSOR FOR SELECT ssn, email FROM users; FETCH ALL FROM c; ROLLBACK",
        Expect::Runs,
    ),
    (
        "PREPARE leak AS SELECT ssn FROM users WHERE id = $1; EXECUTE leak(1); DEALLOCATE leak",
        Expect::Runs,
    ),
    (
        "EXPLAIN (ANALYZE, VERBOSE, COSTS OFF) SELECT ssn FROM users",
        Expect::Runs,
    ),
    ("SELECT * FROM users NATURAL JOIN orders", Expect::NoLeak),
    (
        "SELECT * FROM (users u JOIN orders o ON true) AS j",
        Expect::NoLeak,
    ),
    (
        "SELECT j.ssn FROM (users u JOIN orders o ON true) AS j",
        Expect::NoLeak,
    ),
    (
        "SELECT query_to_xml('SELECT ssn FROM masking_canary.users', true, true, '')",
        Expect::Blocked,
    ),
    (
        "SELECT * FROM pg_stats WHERE tablename = 'users'",
        Expect::Blocked,
    ),
    (
        "SELECT * FROM users JOIN orders USING (id)",
        Expect::Blocked,
    ),
    ("COPY users TO PROGRAM 'cat'", Expect::Blocked),
    (
        "DO $$ BEGIN RAISE NOTICE '%', (SELECT ssn FROM masking_canary.users LIMIT 1); END $$",
        Expect::Blocked,
    ),
];

#[tokio::test]
async fn test_no_canary_leaks() {
    let client = connect().await;
    setup(&client).await;
    let catalog = catalog(&client).await;

    let policies = Policies::new(Config::from_toml(CONFIG).unwrap()).unwrap();
    let assignments = Assignments::new(&policies, "pgdog", &catalog);

    // Control: an exempt user sees the canaries, so the test can detect leaks.
    let admin = policies.profile("admin", "pgdog");
    assert!(admin.exempt);
    let out = run(&client, "SELECT ssn, email, salary FROM users")
        .await
        .unwrap();
    for canary in CANARIES {
        assert!(out.contains(canary), "seed data missing {canary}: {out}");
    }

    let profile = policies.profile("anonymous", "pgdog");
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec![SCHEMA.into()],
    };

    let mut failures = vec![];
    for (sql, expect) in CORPUS {
        let outcome = analyze(sql, &ctx);
        let to_run = match &outcome {
            Outcome::Blocked { reason } => {
                if *expect == Expect::Runs {
                    failures.push(format!("{sql}\n  unexpectedly blocked: {reason}"));
                }
                continue;
            }
            Outcome::Rewritten { sql, .. } => sql.clone(),
            Outcome::Unchanged { .. } => sql.to_string(),
        };

        if *expect == Expect::Blocked {
            failures.push(format!("{sql}\n  expected a block, got {outcome:?}"));
            continue;
        }

        let result = run(&client, &to_run).await;
        // Leave no transaction open after an error.
        let _ = client.batch_execute("ROLLBACK").await;

        let text = match &result {
            Ok(out) | Err(out) => out,
        };
        if let Some(canary) = leaked(text) {
            failures.push(format!(
                "{sql}\n  LEAKED {canary}\n  ran: {to_run}\n  got: {text}"
            ));
        }
        if *expect == Expect::Runs
            && let Err(err) = &result
        {
            failures.push(format!("{sql}\n  failed to run: {err}\n  ran: {to_run}"));
        }
    }

    // Masked predicates can't be used as an oracle.
    let outcome = analyze("SELECT id FROM users WHERE ssn LIKE 'CANARY%'", &ctx);
    let Outcome::Rewritten { sql, .. } = outcome else {
        panic!("expected a rewrite, got {outcome:?}");
    };
    let out = run(&client, &sql).await.unwrap();
    if !out.is_empty() {
        failures.push(format!(
            "predicate on masked column matched raw values: {out}"
        ));
    }

    client
        .batch_execute(&format!("DROP SCHEMA {SCHEMA} CASCADE"))
        .await
        .expect("cleanup");

    assert!(failures.is_empty(), "\n{}", failures.join("\n\n"));
}

/// `search = "raw"` lets support find rows by SSN, still masked in results.
#[tokio::test]
async fn test_raw_search_finds_rows_without_leaking() {
    let client = connect().await;
    // Separate schema so tests can run in parallel.
    let schema = "masking_canary_raw";
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE;
             CREATE SCHEMA {schema};
             SET search_path TO {schema};
             CREATE TABLE users (id BIGINT PRIMARY KEY, ssn TEXT);
             INSERT INTO users VALUES (1, 'CANARYSSN-1111'), (2, 'CANARYSSN-2222');"
        ))
        .await
        .unwrap();

    let config = r#"
[[users]]
name = "support"
roles = ["support"]

[[policies]]
name = "ssn"
data_type = "text"
mask = "null"

[[policies.rules]]
roles = ["support"]
mask = "default"
search = "raw"

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"
"#;
    let catalog = Catalog::new(
        vec![schema.into()],
        vec![Relation {
            schema: schema.into(),
            name: "users".into(),
            kind: RelationKind::Table,
            columns: vec![
                Column {
                    name: "id".into(),
                    data_type: "bigint".into(),
                },
                Column {
                    name: "ssn".into(),
                    data_type: "text".into(),
                },
            ],
            parent: None,
        }],
    );
    let policies = Policies::new(Config::from_toml(config).unwrap()).unwrap();
    let assignments = Assignments::new(&policies, "pgdog", &catalog);
    let profile = policies.profile("support", "pgdog");
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec![schema.into()],
    };

    let Outcome::Rewritten { sql, raw, .. } = analyze(
        "SELECT id, ssn FROM users WHERE ssn = 'CANARYSSN-2222'",
        &ctx,
    ) else {
        panic!("expected a rewrite");
    };
    assert!(raw.contains(&format!("{schema}.users.ssn")));
    let out = run(&client, &sql).await.unwrap();
    assert_eq!(out, "2|****|\n", "found by raw value, returned masked");

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
