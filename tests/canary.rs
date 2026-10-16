//! Canary leak tests.
//!
//! Masked columns are seeded with unique canary values. Adversarial statements
//! are analyzed as a masked user and whatever the analyzer lets through is run
//! against Postgres. No canary may appear anywhere in what comes back: rows,
//! errors, notices or COPY data. Errors and notices of statements that touch
//! masked relations go through the plugin's `DETAIL` scrubbing first, as they
//! would through PgDog.
//!
//! The schema is loaded with PgDog's own catalog queries.
//!
//! Requires Postgres; set `PGDOG_MASK_TEST_URL` to override the default
//! `host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog`.
mod support;

use std::sync::{Arc, Mutex};

use futures_util::{StreamExt as _, pin_mut, stream};
use pgdog_mask::analyzer::{Context, Outcome, analyze, analyze_shape};
use pgdog_mask::config::Config;
use pgdog_mask::profile::{Assignments, Policies};
use pgdog_mask::scrub::scrub_detail;
use tokio_postgres::error::DbError;
use tokio_postgres::{AsyncMessage, Client, NoTls, SimpleQueryMessage};

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

/// A connection, and the notices it receives.
struct Connection {
    client: Client,
    notices: Arc<Mutex<Vec<DbError>>>,
}

async fn connect() -> Connection {
    let url = std::env::var("PGDOG_MASK_TEST_URL")
        .unwrap_or_else(|_| "host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog".into());
    let (client, mut connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .expect("connect to Postgres (set PGDOG_MASK_TEST_URL)");
    let notices = Arc::new(Mutex::new(vec![]));
    let sink = notices.clone();
    tokio::spawn(async move {
        let mut messages = stream::poll_fn(move |cx| connection.poll_message(cx));
        while let Some(Ok(message)) = messages.next().await {
            if let AsyncMessage::Notice(notice) = message {
                sink.lock().unwrap().push(notice);
            }
        }
    });
    Connection { client, notices }
}

async fn setup(client: &Client) {
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {SCHEMA} CASCADE;
             CREATE SCHEMA {SCHEMA};
             SET search_path TO {SCHEMA};
             CREATE TABLE users (
                id BIGINT PRIMARY KEY,
                name TEXT NOT NULL CHECK (name <> 'forbidden'),
                ssn VARCHAR(32),
                email TEXT,
                salary NUMERIC
             );
             CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total NUMERIC);
             INSERT INTO users VALUES
                (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com', 987654.32),
                (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com', 987654.32);
             INSERT INTO orders VALUES (1, 1, 10), (2, 2, 20);

             -- A trigger that puts a masked value in a notice's DETAIL.
             CREATE FUNCTION audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                RAISE NOTICE 'user changed' USING DETAIL = NEW.ssn;
                RETURN NEW;
             END $$;
             CREATE TRIGGER audit BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION audit();

             CREATE VIEW user_ssns AS SELECT id, ssn, email FROM users;
             CREATE VIEW user_names AS SELECT id, name FROM users;
             CREATE VIEW nested AS SELECT ssn FROM user_ssns;
             CREATE VIEW renamed (a, b) AS SELECT id, ssn FROM users;
             CREATE VIEW user_orders AS
                SELECT u.id, u.ssn, o.total FROM users u JOIN orders o ON o.user_id = u.id;
             CREATE VIEW barrier WITH (security_barrier) AS
                SELECT id, ssn, upper(ssn) AS loud FROM users;
             CREATE MATERIALIZED VIEW ssn_mv AS SELECT id, ssn, salary FROM users;

             CREATE FUNCTION last4(v TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE STRICT
                AS $$ SELECT right(v, 4) $$;
             CREATE FUNCTION get_ssn(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                AS $$ SELECT ssn FROM users WHERE id = uid $$;
             CREATE FUNCTION get_ssn_atomic(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                BEGIN ATOMIC SELECT ssn FROM masking_canary.users WHERE id = uid; END;
             CREATE FUNCTION get_ssn_positional(BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                AS $$ SELECT ssn FROM users WHERE id = $1 $$;
             CREATE FUNCTION all_ssns() RETURNS TABLE (id BIGINT, ssn TEXT) LANGUAGE sql STABLE
                AS $$ SELECT id, ssn FROM users $$;
             CREATE FUNCTION get_ssn_definer(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                SECURITY DEFINER AS $$ SELECT ssn FROM users WHERE id = uid $$;
             CREATE FUNCTION get_ssn_volatile(uid BIGINT) RETURNS TEXT LANGUAGE sql
                AS $$ SELECT ssn FROM users WHERE id = uid $$;
             CREATE FUNCTION leak_plpgsql() RETURNS TEXT LANGUAGE plpgsql
                AS $$ BEGIN RETURN (SELECT ssn FROM users LIMIT 1); END $$;
             CREATE FUNCTION users_named(p TEXT) RETURNS SETOF users LANGUAGE sql STABLE
                AS $$ SELECT * FROM users WHERE name = p $$;
             CREATE FUNCTION user_count() RETURNS BIGINT LANGUAGE sql STABLE
                AS $$ SELECT count(*) FROM users $$;
             CREATE FUNCTION ssn_is(uid BIGINT, guess TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
                AS $$ SELECT EXISTS (SELECT 1 FROM users WHERE id = uid AND ssn = guess) $$;
             CREATE OPERATOR === (LEFTARG = BIGINT, RIGHTARG = TEXT, FUNCTION = ssn_is);"
        ))
        .await
        .expect("setup");
}

/// Fields of an error or notice, encoded as an `ErrorResponse` body and
/// scrubbed the way the plugin's transform does it, then rendered as text.
fn render(error: &DbError, scrub: bool) -> String {
    let mut body = vec![];
    let fields = [
        (b'S', Some(error.severity())),
        (b'C', Some(error.code().code())),
        (b'M', Some(error.message())),
        (b'D', error.detail()),
        (b'H', error.hint()),
        (b'W', error.where_()),
        (b's', error.schema()),
        (b't', error.table()),
        (b'c', error.column()),
        (b'd', error.datatype()),
        (b'n', error.constraint()),
    ];
    for (code, value) in fields {
        if let Some(value) = value {
            body.push(code);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
    }
    body.push(0);
    if scrub && let Some(scrubbed) = scrub_detail(&body) {
        body = scrubbed;
    }
    String::from_utf8_lossy(&body).replace('\0', " | ")
}

/// Everything a statement sends back, as text: rows, COPY data, the error and notices.
async fn run(conn: &Connection, sql: &str, scrub: bool) -> Result<String, String> {
    conn.notices.lock().unwrap().clear();
    let client = &conn.client;
    let result = if sql.trim_start().to_ascii_uppercase().starts_with("COPY") {
        copy_out(client, sql).await
    } else {
        query(client, sql).await
    };
    let notices: String = conn
        .notices
        .lock()
        .unwrap()
        .iter()
        .map(|notice| format!("NOTICE {}\n", render(notice, scrub)))
        .collect();
    let error = |err: tokio_postgres::Error| match err.as_db_error() {
        Some(db) => render(db, scrub),
        None => format!("{err:?}"),
    };
    match result {
        Ok(out) => Ok(format!("{out}{notices}")),
        Err(err) => Err(format!("{}\n{notices}", error(err))),
    }
}

async fn copy_out(client: &Client, sql: &str) -> Result<String, tokio_postgres::Error> {
    let stream = client.copy_out(sql).await?;
    pin_mut!(stream);
    let mut out = String::new();
    while let Some(chunk) = stream.next().await {
        out.push_str(&String::from_utf8_lossy(&chunk?));
    }
    Ok(out)
}

async fn query(client: &Client, sql: &str) -> Result<String, tokio_postgres::Error> {
    let mut out = String::new();
    for message in client.simple_query(sql).await? {
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
    // Views over masked columns are inlined with masks applied.
    ("SELECT * FROM user_ssns", Expect::Runs),
    (
        "SELECT ssn, email FROM user_ssns WHERE id = 1",
        Expect::Runs,
    ),
    ("SELECT ssn FROM nested", Expect::Runs),
    ("SELECT a, b FROM renamed", Expect::Runs),
    ("SELECT r.y FROM renamed AS r(x, y)", Expect::Runs),
    ("SELECT * FROM user_orders", Expect::Runs),
    (
        "SELECT u.ssn FROM user_ssns u JOIN orders o ON o.user_id = u.id",
        Expect::Runs,
    ),
    ("SELECT row_to_json(v) FROM user_ssns v", Expect::Runs),
    (
        "WITH x AS (SELECT * FROM user_ssns) SELECT * FROM x",
        Expect::Runs,
    ),
    ("SELECT (SELECT ssn FROM user_ssns LIMIT 1)", Expect::Runs),
    ("COPY (SELECT * FROM user_ssns) TO STDOUT", Expect::Runs),
    ("SELECT name FROM user_names", Expect::Runs),
    // security_barrier and materialized views are queried like tables.
    ("SELECT ssn FROM barrier", Expect::Runs),
    ("SELECT id FROM barrier", Expect::Runs),
    ("SELECT loud FROM barrier", Expect::Blocked),
    ("SELECT * FROM ssn_mv", Expect::Runs),
    // Writes through views over masked columns are blocked.
    (
        "BEGIN; UPDATE user_ssns SET email = email; ROLLBACK",
        Expect::Blocked,
    ),
    (
        "BEGIN; DELETE FROM user_ssns RETURNING *; ROLLBACK",
        Expect::Blocked,
    ),
    // SQL functions: analyzed, and inlined when they read masked columns.
    ("SELECT last4(ssn) FROM users", Expect::Runs),
    ("SELECT get_ssn(1)", Expect::Runs),
    ("SELECT masking_canary.get_ssn(2)", Expect::Runs),
    (
        "SELECT get_ssn(id), get_ssn_atomic(id), get_ssn_positional(id) FROM users",
        Expect::Runs,
    ),
    (
        "SELECT string_agg(get_ssn(id), ',') FROM users",
        Expect::Runs,
    ),
    (
        "SELECT id FROM users WHERE get_ssn(id) LIKE 'CANARY%'",
        Expect::Runs,
    ),
    ("SELECT * FROM all_ssns()", Expect::Runs),
    (
        "SELECT a.ssn FROM all_ssns() a WHERE a.id = 2",
        Expect::Runs,
    ),
    ("SELECT * FROM get_ssn(1)", Expect::Runs),
    ("SELECT user_count()", Expect::Runs),
    (
        "SELECT id FROM users WHERE id === 'CANARYSSN-1111'",
        Expect::Runs,
    ),
    ("SELECT get_ssn_definer(1)", Expect::Blocked),
    ("SELECT get_ssn_volatile(1)", Expect::Blocked),
    ("SELECT leak_plpgsql()", Expect::Blocked),
    ("SELECT * FROM users_named('alice')", Expect::Blocked),
    // Errors and notices with row values in their DETAIL.
    (
        "UPDATE users SET name = 'forbidden' WHERE id = 1",
        Expect::NoLeak,
    ),
    ("UPDATE users SET name = NULL WHERE id = 2", Expect::NoLeak),
    (
        "UPDATE user_names SET name = 'forbidden' WHERE id = 1",
        Expect::NoLeak,
    ),
    (
        "BEGIN; UPDATE users SET name = name WHERE id = 1; ROLLBACK",
        Expect::Runs,
    ),
    (
        "BEGIN; UPDATE user_names SET name = name WHERE id = 1 RETURNING *; ROLLBACK",
        Expect::Runs,
    ),
];

#[tokio::test]
async fn test_no_canary_leaks() {
    let conn = connect().await;
    let client = &conn.client;
    setup(client).await;
    let catalog = support::load_catalog(client, &[SCHEMA], &[SCHEMA]).await;

    let policies = Policies::new(Config::from_toml(CONFIG).unwrap()).unwrap();
    let assignments = Assignments::new(&policies, "pgdog", &catalog);

    // Control: an exempt user sees the canaries, so the test can detect leaks.
    let admin = policies.profile("admin", "pgdog");
    assert!(admin.exempt);
    let out = run(&conn, "SELECT ssn, email, salary FROM users", false)
        .await
        .unwrap();
    for canary in CANARIES {
        assert!(out.contains(canary), "seed data missing {canary}: {out}");
    }
    // Control: errors and notices do carry row values in their DETAIL.
    let err = run(
        &conn,
        "UPDATE users SET name = 'forbidden' WHERE id = 1",
        false,
    )
    .await
    .unwrap_err();
    assert!(leaked(&err).is_some(), "{err}");
    let out = run(
        &conn,
        "BEGIN; UPDATE users SET name = name WHERE id = 1; ROLLBACK",
        false,
    )
    .await
    .unwrap();
    assert!(leaked(&out).is_some(), "{out}");

    let profile = policies.profile("anonymous", "pgdog");
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec![SCHEMA.into()],
    };

    let mut failures = vec![];
    // Every statement goes through full analysis, and statements with literals
    // also through the shape path that simple-protocol traffic takes.
    for ((sql, expect), path) in CORPUS
        .iter()
        .flat_map(|entry| [(entry, "full"), (entry, "shape")])
    {
        let outcome = match path {
            "full" => analyze(sql, &ctx),
            _ => match analyze_shape(sql, &ctx) {
                Some(outcome) => outcome,
                None => continue,
            },
        };
        let (to_run, scrub) = match &outcome {
            Outcome::Blocked { reason } => {
                if *expect == Expect::Runs {
                    failures.push(format!("[{path}] {sql}\n  unexpectedly blocked: {reason}"));
                }
                continue;
            }
            Outcome::Rewritten {
                sql,
                touches_masked,
                ..
            } => (sql.clone(), *touches_masked),
            Outcome::Unchanged { touches_masked, .. } => (sql.to_string(), *touches_masked),
        };

        if *expect == Expect::Blocked {
            failures.push(format!(
                "[{path}] {sql}\n  expected a block, got {outcome:?}"
            ));
            continue;
        }

        let result = run(&conn, &to_run, scrub).await;
        // Leave no transaction open after an error.
        let _ = client.batch_execute("ROLLBACK").await;

        let text = match &result {
            Ok(out) | Err(out) => out,
        };
        if let Some(canary) = leaked(text) {
            failures.push(format!(
                "[{path}] {sql}\n  LEAKED {canary}\n  ran: {to_run}\n  got: {text}"
            ));
        }
        if *expect == Expect::Runs
            && let Err(err) = &result
        {
            failures.push(format!(
                "[{path}] {sql}\n  failed to run: {err}\n  ran: {to_run}"
            ));
        }
    }

    // Masked predicates can't be used as an oracle, directly or through views,
    // functions and operators.
    for sql in [
        "SELECT id FROM users WHERE ssn LIKE 'CANARY%'",
        "SELECT id FROM user_ssns WHERE ssn LIKE 'CANARY%'",
        "SELECT id FROM users WHERE get_ssn(id) LIKE 'CANARY%'",
        "SELECT id FROM users WHERE id === 'CANARYSSN-1111'",
    ] {
        let outcome = analyze(sql, &ctx);
        let Outcome::Rewritten { sql: rewritten, .. } = outcome else {
            panic!("expected a rewrite of {sql}, got {outcome:?}");
        };
        let out = run(&conn, &rewritten, true).await.unwrap();
        if !out.is_empty() {
            failures.push(format!(
                "{sql}\n  predicate on masked column matched raw values: {out}"
            ));
        }
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
    let conn = connect().await;
    let client = &conn.client;
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
    let catalog = support::load_catalog(client, &[schema], &[schema]).await;
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
    let out = run(&conn, &sql, true).await.unwrap();
    assert_eq!(out, "2|****|\n", "found by raw value, returned masked");

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
