//! Canary leak tests.
//!
//! Masked columns are seeded with unique canary values. Adversarial statements
//! are analyzed as a masked user and whatever the analyzer lets through is run
//! against Postgres. No canary may appear anywhere in what comes back: rows,
//! errors, notices or COPY data. What comes back is what PgDog would pass on
//! to the masked user: errors and notices lose their `DETAIL`, result masks
//! replace proxy-masked columns, and statements whose errors are redacted
//! keep only their errors' SQLSTATE and location.
//!
//! The schema is loaded with PgDog's own catalog queries.
//!
//! Requires Postgres; set `PGDOG_MASK_TEST_URL` to override the default
//! `host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog`.
mod support;

use std::sync::{Arc, Mutex};

use futures_util::{StreamExt as _, pin_mut, stream};
use pgdog_mask::analyzer::{Context, Outcome, ResultMask, Results, analyze, analyze_shape};
use pgdog_mask::catalog::Catalog;
use pgdog_mask::config::Config;
use pgdog_mask::profile::{Assignments, Policies, ProxyInstance};
use pgdog_mask::proxy::Datum;
use tokio_postgres::error::{DbError, ErrorPosition};
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
             -- Unmasked, with a column named like a masked one.
             CREATE TABLE contacts (id BIGINT, email TEXT);
             INSERT INTO users VALUES
                (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com', 987654.32),
                (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com', 987654.32);
             INSERT INTO orders VALUES (1, 1, 10), (2, 2, 20);
             INSERT INTO contacts VALUES (1, 'contact-1');

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

/// What reaches the client of a statement.
#[derive(Clone, Copy)]
enum View<'a> {
    /// Everything Postgres sends, as an exempt user gets it.
    Raw,
    /// What a masked user gets through PgDog: errors and notices without
    /// `DETAIL`, and the statement's result masks and error redaction.
    Masked {
        results: &'a Results,
        /// Proxy masks the result masks name.
        proxies: &'a [ProxyInstance],
    },
}

/// No result masks, no error redaction.
static NO_RESULTS: Results = Results {
    columns: vec![],
    redact_errors: false,
};

impl View<'_> {
    /// A masked user's view of a statement without result masks.
    fn masked() -> View<'static> {
        View::Masked {
            results: &NO_RESULTS,
            proxies: &[],
        }
    }

    fn redacts_errors(&self) -> bool {
        matches!(self, View::Masked { results, .. } if results.redact_errors)
    }
}

/// The message PgDog puts in errors and notices of statements whose errors
/// the plugin redacts (`statement_plugins/errors.rs`).
const STATEMENT_REDACTED: &str =
    "error message removed: the statement reads values this user can't see";

/// Fields of an error or notice, rendered as text, as `view` gets them.
fn render(error: &DbError, view: View<'_>) -> String {
    let position = error.position().and_then(|position| match position {
        ErrorPosition::Original(position) => Some(position.to_string()),
        ErrorPosition::Internal { .. } => None,
    });
    let line = error.line().map(|line| line.to_string());
    let fields: Vec<(u8, Option<&str>)> = if view.redacts_errors() {
        // PgDog keeps the severity, SQLSTATE and the fields locating the error.
        vec![
            (b'S', Some(error.severity())),
            (b'C', Some(error.code().code())),
            (b'M', Some(STATEMENT_REDACTED)),
            (b'P', position.as_deref()),
            (b'F', error.file()),
            (b'L', line.as_deref()),
            (b'R', error.routine()),
            (b's', error.schema()),
            (b't', error.table()),
            (b'c', error.column()),
            (b'd', error.datatype()),
            (b'n', error.constraint()),
        ]
    } else {
        vec![
            (b'S', Some(error.severity())),
            (b'C', Some(error.code().code())),
            (b'M', Some(error.message())),
            (b'D', error.detail().filter(|_| matches!(view, View::Raw))),
            (b'H', error.hint()),
            (b'W', error.where_()),
            (b's', error.schema()),
            (b't', error.table()),
            (b'c', error.column()),
            (b'd', error.datatype()),
            (b'n', error.constraint()),
        ]
    };
    let mut body = vec![];
    for (code, value) in fields {
        if let Some(value) = value {
            body.push(code);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
    }
    String::from_utf8_lossy(&body).replace('\0', " | ")
}

/// Everything a statement sends back, as text: rows, COPY data, the error and notices.
async fn run(conn: &Connection, sql: &str, view: View<'_>) -> Result<String, String> {
    conn.notices.lock().unwrap().clear();
    let client = &conn.client;
    let result = if sql.trim_start().to_ascii_uppercase().starts_with("COPY") {
        copy_out(client, sql).await
    } else {
        query(client, sql, view).await
    };
    let notices: String = conn
        .notices
        .lock()
        .unwrap()
        .iter()
        .map(|notice| format!("NOTICE {}\n", render(notice, view)))
        .collect();
    let error = |err: tokio_postgres::Error| match err.as_db_error() {
        Some(db) => render(db, view),
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

/// Rows as `view` gets them. Like PgDog, results are numbered by
/// statement: each statement ends with a CommandComplete.
async fn query(
    client: &Client,
    sql: &str,
    view: View<'_>,
) -> Result<String, tokio_postgres::Error> {
    let mut out = String::new();
    let mut result = 0;
    for message in client.simple_query(sql).await? {
        match message {
            SimpleQueryMessage::Row(row) => {
                for i in 0..row.len() {
                    out.push_str(&masked_value(view, result, i, row.get(i)));
                    out.push('|');
                }
                out.push('\n');
            }
            SimpleQueryMessage::CommandComplete(_) => result += 1,
            _ => (),
        }
    }
    Ok(out)
}

/// A value of column `column` of result `result`, as `view` gets it.
fn masked_value(view: View<'_>, result: u16, column: usize, value: Option<&str>) -> String {
    let View::Masked { results, proxies } = view else {
        return value.unwrap_or("NULL").to_owned();
    };
    let mask = results
        .columns
        .iter()
        .find(|mask| mask.result == result && usize::from(mask.column) == column);
    match (mask.map(|mask| mask.mask), value) {
        (None, value) | (Some(ResultMask::Proxy { .. }), value @ None) => {
            value.unwrap_or("NULL").to_owned()
        }
        (Some(ResultMask::Null), _) => "NULL".to_owned(),
        // The canary schema's proxy masks are on text columns.
        (Some(ResultMask::Proxy { proxy, .. }), Some(value)) => {
            match proxies[proxy].mask.mask(Datum::Text(value.to_owned())) {
                Ok(Datum::Text(token)) => token,
                other => panic!("proxy mask {proxy} failed on a text value: {other:?}"),
            }
        }
    }
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
    /// Runs into an error with this SQLSTATE, redacted.
    Fails(&'static str),
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
    // Column aliases map by position, so they can't cover masked columns.
    ("SELECT c FROM users AS t(a, b, c)", Expect::Blocked),
    ("SELECT b FROM users AS t(a, b)", Expect::Runs),
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
    // A relation hiding `contacts`, or `contacts` losing its `email` column,
    // would make `email` below read `users.email` while the catalog says
    // `contacts.email`. Statements run on one connection, in order.
    ("CREATE TEMP TABLE contacts (id BIGINT)", Expect::Blocked),
    ("CREATE TABLE pg_temp.contacts (id BIGINT)", Expect::Blocked),
    ("CREATE TEMP SEQUENCE contacts", Expect::Blocked),
    ("SELECT 1 AS id INTO TEMP contacts", Expect::Blocked),
    (
        "CREATE TEMP TABLE contacts AS SELECT 1 AS id",
        Expect::Blocked,
    ),
    ("CREATE TEMP TABLE contacts (LIKE orders)", Expect::Blocked),
    ("ALTER TABLE contacts DROP COLUMN email", Expect::Blocked),
    (
        "ALTER TABLE contacts RENAME COLUMN email TO e",
        Expect::Blocked,
    ),
    (
        "SELECT (SELECT email FROM contacts LIMIT 1) FROM users",
        Expect::Runs,
    ),
    // An aliased join hides its items: u.ssn is the outer users'.
    (
        "SELECT l.v FROM users u, LATERAL (SELECT u.ssn AS v FROM (orders u CROSS JOIN orders o) AS j) l",
        Expect::Runs,
    ),
    (
        "SELECT (SELECT u.ssn FROM (orders u CROSS JOIN orders o) AS j LIMIT 1) FROM users u",
        Expect::Runs,
    ),
    (
        "SELECT l.v FROM users u, LATERAL (SELECT u.email AS v FROM (orders u JOIN orders o ON true) AS j) l",
        Expect::Runs,
    ),
    (
        "SELECT l.v FROM users u, LATERAL (SELECT u.salary AS v FROM (orders u CROSS JOIN orders o) AS j) l",
        Expect::Runs,
    ),
    (
        "SELECT * FROM (orders a JOIN orders b ON true) j, users u",
        Expect::Runs,
    ),
    (
        "SELECT x.email FROM users u, LATERAL (SELECT email FROM contacts) x",
        Expect::Runs,
    ),
];

/// Analyze each statement as the context's user and run what the analyzer
/// lets through, as PgDog would for that user: rows with the statement's
/// result masks applied, errors and notices without `DETAIL`, and only the
/// SQLSTATE and location of a redacted statement's errors. Every statement
/// goes through full analysis, and statements with literals also through the
/// shape path simple-protocol traffic takes. Returns what went wrong.
async fn check_corpus(
    conn: &Connection,
    ctx: &Context<'_>,
    corpus: &[(&str, &str, Expect)],
) -> Vec<String> {
    let mut failures = vec![];
    for ((id, sql, expect), path) in corpus
        .iter()
        .flat_map(|entry| [(entry, "full"), (entry, "shape")])
    {
        let outcome = match path {
            "full" => analyze(sql, ctx),
            _ => match analyze_shape(sql, ctx) {
                Some(outcome) => outcome,
                None => continue,
            },
        };
        let (to_run, results) = match &outcome {
            Outcome::Blocked { reason } => {
                if matches!(expect, Expect::Runs | Expect::Fails(_)) {
                    failures.push(format!(
                        "[{path}] {id} {sql}\n  unexpectedly blocked: {reason}"
                    ));
                }
                continue;
            }
            Outcome::Rewritten { sql, results, .. } => (sql.clone(), results),
            Outcome::Unchanged { results, .. } => (sql.to_string(), results),
        };

        if *expect == Expect::Blocked {
            failures.push(format!(
                "[{path}] {id} {sql}\n  expected a block, got {outcome:?}"
            ));
            continue;
        }

        let view = View::Masked {
            results,
            proxies: &ctx.policies.proxies,
        };
        let result = run(conn, &to_run, view).await;
        // Leave no transaction open after an error.
        let _ = conn.client.batch_execute("ROLLBACK").await;

        let text = match &result {
            Ok(out) | Err(out) => out,
        };
        if let Some(canary) = leaked(text) {
            failures.push(format!(
                "[{path}] {id} {sql}\n  LEAKED {canary}\n  ran: {to_run}\n  got: {text}"
            ));
        }
        match (expect, &result) {
            (Expect::Runs, Err(err)) => failures.push(format!(
                "[{path}] {id} {sql}\n  failed to run: {err}\n  ran: {to_run}"
            )),
            (Expect::Fails(code), Err(err))
                if err.contains(&format!("C{code} ")) && err.contains(STATEMENT_REDACTED) => {}
            (Expect::Fails(code), _) => failures.push(format!(
                "[{path}] {id} {sql}\n  expected a redacted {code} error, got {result:?}\n  ran: {to_run}"
            )),
            _ => (),
        }
    }
    failures
}

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
    let out = run(&conn, "SELECT ssn, email, salary FROM users", View::Raw)
        .await
        .unwrap();
    for canary in CANARIES {
        assert!(out.contains(canary), "seed data missing {canary}: {out}");
    }
    // Control: errors and notices do carry row values in their DETAIL.
    let err = run(
        &conn,
        "UPDATE users SET name = 'forbidden' WHERE id = 1",
        View::Raw,
    )
    .await
    .unwrap_err();
    assert!(leaked(&err).is_some(), "{err}");
    let out = run(
        &conn,
        "BEGIN; UPDATE users SET name = name WHERE id = 1; ROLLBACK",
        View::Raw,
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

    let corpus: Vec<_> = CORPUS
        .iter()
        .map(|(sql, expect)| ("", *sql, *expect))
        .collect();
    let mut failures = check_corpus(&conn, &ctx, &corpus).await;

    // Masked predicates can't be used as an oracle, directly or through views,
    // functions and operators.
    for sql in [
        "SELECT id FROM users WHERE ssn LIKE 'CANARY%'",
        "SELECT id FROM user_ssns WHERE ssn LIKE 'CANARY%'",
        "SELECT id FROM users WHERE get_ssn(id) LIKE 'CANARY%'",
        "SELECT id FROM users WHERE id === 'CANARYSSN-1111'",
        // `u` inside the aliased join is hidden: u.ssn is the outer users'.
        "SELECT u.id FROM users u WHERE EXISTS (SELECT 1 FROM (orders u CROSS JOIN orders o) AS j WHERE u.ssn LIKE 'CANARY%')",
    ] {
        let outcome = analyze(sql, &ctx);
        let Outcome::Rewritten { sql: rewritten, .. } = outcome else {
            panic!("expected a rewrite of {sql}, got {outcome:?}");
        };
        let out = run(&conn, &rewritten, View::masked()).await.unwrap();
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
    let out = run(&conn, &sql, View::masked()).await.unwrap();
    assert_eq!(out, "2|****|\n", "found by raw value, returned masked");

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Schema of the proxy mask canaries.
const PROXY_SCHEMA: &str = "masking_canary_proxy";

/// `ssn` is masked in the results by a proxy mask; `email` and `salary` keep
/// their SQL masks. `{key}` is the file holding the proxy mask's key.
const PROXY_CONFIG: &str = r#"
[general]
udf_allowlist = ["masking_canary_proxy.safe_fn"]

[[users]]
name = "admin"
roles = ["pii_admin"]

[[policies]]
name = "ssn"
data_type = "character varying"
mask = "proxy"
proxy = "hmac_sha256"
options = { key_file = "{key}" }

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

[[masked_columns]]
name = "users_2024"
column = "ssn"
policy = "ssn"

[[masked_columns]]
name = "users_2024"
column = "email"
policy = "email"

[[masked_columns]]
name = "users_2024"
column = "salary"
policy = "salary"
"#;

/// The objects of the regression corpus (`src/analyzer/test/proxy.rs`),
/// seeded with canaries. `archive` holds no canaries: it's unmasked.
async fn setup_proxy(client: &Client) {
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {PROXY_SCHEMA} CASCADE;
             CREATE SCHEMA {PROXY_SCHEMA};
             SET search_path TO {PROXY_SCHEMA};
             CREATE TABLE users (
                id BIGINT PRIMARY KEY,
                name TEXT NOT NULL CHECK (name <> 'forbidden'),
                ssn VARCHAR(32),
                email TEXT,
                opted_in BOOLEAN,
                salary NUMERIC
             );
             CREATE TABLE users_2024 (LIKE users INCLUDING ALL);
             CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT, total NUMERIC);
             CREATE TABLE archive (id BIGINT, ssn TEXT);
             CREATE TABLE audit (id BIGSERIAL, note TEXT);
             CREATE TABLE tags (id BIGINT, labels TEXT[]);
             CREATE SEQUENCE order_seq;
             INSERT INTO users VALUES
                (1, 'alice', 'CANARYSSN-1111', 'canaryemail-alice@example.com', true, 987654.32),
                (2, 'bob', 'CANARYSSN-2222', 'canaryemail-bob@example.com', false, 987654.32);
             INSERT INTO users_2024 VALUES
                (3, 'carol', 'CANARYSSN-3333', 'canaryemail-carol@example.com', true, 987654.32);
             INSERT INTO orders VALUES (1, 1, 10), (2, 2, 20);
             INSERT INTO archive VALUES (1, 'archived-1');
             INSERT INTO tags VALUES (1, ARRAY['a', 'b']);

             -- Writes raise the proxy-masked value in a notice's MESSAGE.
             CREATE FUNCTION audit_ssn() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                RAISE NOTICE 'user % changed', NEW.ssn;
                RETURN NEW;
             END $$;
             CREATE TRIGGER audit_ssn BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION audit_ssn();

             CREATE VIEW user_ssns AS SELECT id, ssn FROM users;
             CREATE VIEW user_contacts AS SELECT id, ssn, email FROM users;
             CREATE VIEW user_loud AS SELECT id, upper(ssn) AS loud FROM users;
             CREATE VIEW nested_v AS SELECT ssn FROM user_ssns;
             CREATE VIEW ssn_barrier WITH (security_barrier) AS
                SELECT id, ssn, upper(ssn) AS loud FROM users;
             CREATE MATERIALIZED VIEW ssn_counts AS SELECT ssn, count(*) AS n FROM users GROUP BY ssn;
             CREATE MATERIALIZED VIEW ssn_flags AS
                SELECT id, ssn LIKE 'CANARY%' AS starts_9 FROM users;

             CREATE FUNCTION last4(v TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE STRICT
                AS $$ SELECT right(v, 4) $$;
             CREATE FUNCTION user_ssn(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                AS $$ SELECT ssn FROM users WHERE id = uid $$;
             CREATE FUNCTION user_ssn_definer(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                SECURITY DEFINER AS $$ SELECT ssn FROM {PROXY_SCHEMA}.users WHERE id = uid $$;
             CREATE FUNCTION volatile_ssn(uid BIGINT) RETURNS TEXT LANGUAGE sql
                AS $$ SELECT ssn FROM users WHERE id = uid $$;
             CREATE FUNCTION atomic_ssn(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                BEGIN ATOMIC SELECT ssn FROM {PROXY_SCHEMA}.users WHERE id = uid; END;
             CREATE FUNCTION ssns() RETURNS TABLE (id BIGINT, ssn TEXT) LANGUAGE sql STABLE
                AS $$ SELECT id, ssn FROM users $$;
             CREATE FUNCTION count_users() RETURNS BIGINT LANGUAGE sql STABLE
                AS $$ SELECT count(*) FROM users $$;
             CREATE FUNCTION same(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
                AS $$ SELECT a = b $$;
             CREATE FUNCTION ssn_eq(a BIGINT, b BIGINT) RETURNS BOOLEAN LANGUAGE sql STABLE
                AS $$ SELECT (SELECT ssn FROM users WHERE id = a) = (SELECT ssn FROM users WHERE id = b) $$;
             CREATE FUNCTION ssn_is(uid BIGINT, guess TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE
                AS $$ SELECT EXISTS (SELECT 1 FROM users WHERE id = uid AND ssn = guess) $$;
             CREATE FUNCTION stash(v TEXT) RETURNS TEXT LANGUAGE sql
                AS $$ INSERT INTO audit (note) VALUES (v) RETURNING note $$;
             CREATE FUNCTION notify_fn(v TEXT) RETURNS VOID LANGUAGE sql
                AS $$ SELECT pg_notify('c', v) $$;
             CREATE FUNCTION wrap_stash(v TEXT) RETURNS TEXT LANGUAGE sql
                AS $$ SELECT stash(v) $$;
             CREATE FUNCTION upper_safe(v TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE
                AS $$ SELECT upper(v) $$;
             CREATE FUNCTION email_of(uid BIGINT) RETURNS TEXT LANGUAGE sql STABLE
                AS $$ SELECT email FROM users WHERE id = uid $$;
             CREATE FUNCTION noisy_eq(a TEXT, b TEXT) RETURNS BOOLEAN LANGUAGE sql
                AS $$ SELECT a = b FROM (SELECT pg_notify('c', a)) AS n $$;
             CREATE FUNCTION recursive_fn(x INTEGER) RETURNS INTEGER LANGUAGE sql
                AS $$ SELECT recursive_fn(x) $$;
             CREATE FUNCTION plpgsql_fn() RETURNS INTEGER LANGUAGE plpgsql
                AS $$ BEGIN RETURN 1; END $$;
             CREATE FUNCTION safe_fn(v TEXT) RETURNS TEXT LANGUAGE plpgsql
                AS $$ BEGIN RETURN 'x'; END $$;
             CREATE OPERATOR === (LEFTARG = TEXT, RIGHTARG = TEXT, FUNCTION = same);
             CREATE OPERATOR @@@ (LEFTARG = BIGINT, RIGHTARG = BIGINT, FUNCTION = ssn_eq);
             CREATE OPERATOR ~~~ (LEFTARG = TEXT, RIGHTARG = TEXT, FUNCTION = noisy_eq);"
        ))
        .await
        .expect("setup");
}

/// The regression corpus (`src/analyzer/test/proxy.rs`, rows by ID) on the
/// canary schema, for the user with the proxy mask. Parameters are literals,
/// so statements run through the simple protocol; writes run in a rolled
/// back transaction.
const PROXY_CORPUS: &[(&str, &str, Expect)] = &[
    // Plain outputs.
    ("A1", "SELECT ssn FROM users", Expect::Runs),
    ("A2", "SELECT id, ssn FROM users WHERE id = 1", Expect::Runs),
    ("A3", "SELECT ssn AS s FROM users", Expect::Runs),
    ("A4", "SELECT u.ssn FROM users u", Expect::Runs),
    (
        "A5",
        "SELECT masking_canary_proxy.users.ssn FROM masking_canary_proxy.users",
        Expect::Runs,
    ),
    ("A6", "SELECT c FROM users AS x(a, b, c)", Expect::Blocked),
    ("A7", "SELECT ssn, ssn AS again FROM users", Expect::Runs),
    ("A8", "SELECT ssn AS email FROM users", Expect::Runs),
    (
        "A9",
        "SELECT email AS ssn FROM users ORDER BY ssn",
        Expect::Runs,
    ),
    ("A10", "SELECT ssn FROM users_2024", Expect::Runs),
    ("A11", "SELECT ssn FROM ONLY users FOR UPDATE", Expect::Runs),
    ("A12", "SELECT ssn::text FROM users", Expect::Runs),
    ("A13", "SELECT ssn::varchar FROM users", Expect::Runs),
    // Stars.
    ("B1", "SELECT * FROM users", Expect::Runs),
    (
        "B2",
        "SELECT u.* FROM users u JOIN orders o ON o.user_id = u.id",
        Expect::Runs,
    ),
    (
        "B3",
        "SELECT o.*, u.ssn FROM orders o JOIN users u ON o.user_id = u.id",
        Expect::Runs,
    ),
    ("B4", "TABLE users", Expect::Runs),
    ("B6", "SELECT ssn, *, upper(ssn) FROM users", Expect::Runs),
    (
        "B8",
        "SELECT x.* FROM (SELECT id, ssn FROM users) x",
        Expect::Runs,
    ),
    (
        "B9",
        "SELECT f.*, u.ssn FROM users u, generate_series(1, 2) f",
        Expect::Blocked,
    ),
    (
        "B10",
        "SELECT * FROM users u, generate_series(1, 2) g",
        Expect::Runs,
    ),
    (
        "B11",
        "SELECT * FROM users JOIN orders USING (id)",
        Expect::Blocked,
    ),
    (
        "B12",
        "SELECT ssn, total FROM users JOIN orders USING (id)",
        Expect::Runs,
    ),
    ("B13", "SELECT (u).*, u.ssn FROM users u", Expect::Runs),
    (
        "B14",
        "SELECT (o).*, u.ssn FROM orders o JOIN users u ON o.user_id = u.id",
        Expect::Runs,
    ),
    ("B15", "SELECT * FROM pg_class c, users u", Expect::Blocked),
    (
        "B16",
        "SELECT * FROM (SELECT ssn, id FROM users) s JOIN orders o USING (id)",
        Expect::Blocked,
    ),
    (
        "B17",
        "SELECT (ROW(1, 2)).*, ssn FROM users",
        Expect::Blocked,
    ),
    (
        "B18",
        "SELECT * FROM users, XMLTABLE('/r' PASSING ('<r/>'::xml) COLUMNS a text) x",
        Expect::Runs,
    ),
    (
        "B19",
        "SELECT s.*, u.ssn FROM (SELECT * FROM pg_class) s, users u",
        Expect::Blocked,
    ),
    (
        "B20",
        "SELECT *, (SELECT upper(ssn) FROM users LIMIT 1) FROM orders a JOIN orders b USING (id)",
        Expect::Blocked,
    ),
    (
        "B21",
        "SELECT s.*, upper(u.ssn) FROM (SELECT * FROM orders a JOIN orders b USING (id)) s, users u",
        Expect::Blocked,
    ),
    (
        "B22",
        "SELECT s.*, upper(u.ssn) FROM (SELECT * FROM orders) s, users u",
        Expect::Runs,
    ),
    (
        "B23",
        "SELECT l.* FROM users u, LATERAL (SELECT u.*) l",
        Expect::Runs,
    ),
    (
        "B24",
        "SELECT * FROM (SELECT * FROM orders) s",
        Expect::Runs,
    ),
    // Subqueries and CTEs.
    (
        "C1",
        "SELECT s.ssn FROM (SELECT ssn FROM users) s",
        Expect::Runs,
    ),
    (
        "C2",
        "SELECT s.x FROM (SELECT ssn AS x, id FROM users WHERE id > 0) s",
        Expect::Runs,
    ),
    ("C3", "SELECT * FROM (SELECT * FROM users) s", Expect::Runs),
    (
        "C4",
        "SELECT s.u FROM (SELECT upper(ssn) AS u FROM users) s",
        Expect::Runs,
    ),
    (
        "C5",
        "SELECT count(*) FROM (SELECT DISTINCT ssn FROM users) s",
        Expect::Runs,
    ),
    (
        "C6",
        "SELECT count(s.ssn) FROM (SELECT ssn FROM users) s",
        Expect::Runs,
    ),
    (
        "C7",
        "WITH s AS (SELECT id, ssn FROM users) SELECT ssn FROM s",
        Expect::Runs,
    ),
    (
        "C8",
        "WITH s(a, b) AS (SELECT id, ssn FROM users) SELECT b, a FROM s",
        Expect::Runs,
    ),
    (
        "C9",
        "WITH s AS MATERIALIZED (SELECT * FROM users) SELECT ssn, email FROM s",
        Expect::Runs,
    ),
    (
        "C10",
        "WITH s AS (SELECT ssn || '' AS x FROM users) SELECT x FROM s",
        Expect::Runs,
    ),
    (
        "C11",
        "WITH RECURSIVE r AS (SELECT id, ssn FROM users WHERE id = 1 UNION ALL SELECT u.id, u.ssn FROM users u JOIN r ON u.id = r.id + 1) SELECT ssn FROM r",
        Expect::Runs,
    ),
    (
        "C12",
        "WITH RECURSIVE r(n, s) AS (SELECT 1, ssn FROM users WHERE id = 1 UNION ALL SELECT n + 1, s FROM r WHERE n < 3) SELECT s FROM r",
        Expect::Runs,
    ),
    (
        "C13",
        "WITH RECURSIVE r(n, s) AS (SELECT 1, ssn::text FROM users WHERE id = 1 UNION ALL SELECT n + 1, s || '!' FROM r WHERE n < 3) SELECT n, s FROM r",
        Expect::Runs,
    ),
    (
        "C14",
        "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 5) SELECT t.n, u.ssn FROM t, users u",
        Expect::Runs,
    ),
    (
        "C15",
        "SELECT (SELECT s.v FROM archive a, (SELECT ssn AS v) s LIMIT 1) FROM users u",
        Expect::Runs,
    ),
    (
        "C16",
        "SELECT (SELECT l.v FROM archive a, LATERAL (SELECT ssn AS v) l LIMIT 1) FROM users u",
        Expect::Runs,
    ),
    (
        "C17",
        "SELECT (WITH c AS (SELECT u.ssn AS x) SELECT x FROM c) FROM users u",
        Expect::Runs,
    ),
    (
        "C18",
        "WITH RECURSIVE a AS (SELECT x FROM b), b AS (SELECT ssn AS x FROM users) SELECT * FROM a",
        Expect::Runs,
    ),
    (
        "C19",
        "WITH RECURSIVE d AS (INSERT INTO audit (note) SELECT x FROM t RETURNING 1), t AS (SELECT ssn AS x FROM users) SELECT count(*) FROM d",
        Expect::Blocked,
    ),
    (
        "C20",
        "WITH RECURSIVE t(n, s) AS (SELECT 1, ssn FROM users WHERE id = 1 UNION ALL SELECT n + 1, s FROM t WHERE n < 3) SEARCH DEPTH FIRST BY s SET ord SELECT * FROM t",
        Expect::Runs,
    ),
    (
        "C21",
        "WITH archive AS (SELECT ssn FROM users) SELECT x.ssn FROM orders o, (SELECT * FROM archive) x",
        Expect::Runs,
    ),
    // Set operations.
    (
        "D1",
        "SELECT ssn FROM users UNION ALL SELECT ssn FROM users_2024",
        Expect::Runs,
    ),
    (
        "D2",
        "SELECT ssn FROM users UNION SELECT ssn FROM users",
        Expect::Runs,
    ),
    (
        "D3",
        "SELECT ssn FROM users UNION ALL SELECT name FROM users",
        Expect::Runs,
    ),
    (
        "D5",
        "SELECT id, ssn FROM users INTERSECT SELECT id, ssn FROM users_2024",
        Expect::Runs,
    ),
    (
        "D6",
        "SELECT ssn FROM users EXCEPT SELECT name FROM users",
        Expect::Runs,
    ),
    (
        "D7",
        "SELECT ssn FROM users UNION ALL SELECT upper(ssn) FROM users",
        Expect::Runs,
    ),
    (
        "D8",
        "SELECT ssn FROM users UNION SELECT ssn FROM users_2024 ORDER BY 1 LIMIT 3",
        Expect::Runs,
    ),
    (
        "D9",
        "SELECT ssn FROM users UNION ALL SELECT email FROM users",
        Expect::Runs,
    ),
    (
        "D10",
        "SELECT ssn FROM users UNION ALL SELECT ssn FROM users ORDER BY ssn",
        Expect::Runs,
    ),
    (
        "D11",
        "SELECT ssn FROM users UNION SELECT 'x'",
        Expect::Runs,
    ),
    (
        "D12",
        "SELECT ssn AS s FROM users UNION ALL SELECT ssn FROM users_2024 ORDER BY s",
        Expect::Runs,
    ),
    // VALUES, LATERAL, joins, table functions.
    ("E1", "VALUES (1, 'a')", Expect::Runs),
    (
        "E2",
        "SELECT * FROM (VALUES ((SELECT ssn FROM users LIMIT 1))) v(s)",
        Expect::Runs,
    ),
    (
        "E3",
        "SELECT l.x FROM users u, LATERAL (SELECT u.ssn AS x) l",
        Expect::Runs,
    ),
    (
        "E4",
        "SELECT l.x FROM users u CROSS JOIN LATERAL (SELECT upper(u.ssn) AS x) l",
        Expect::Runs,
    ),
    (
        "E5",
        "SELECT o.id, l.ssn FROM orders o LEFT JOIN LATERAL (SELECT u.ssn FROM users u WHERE u.id = o.user_id LIMIT 1) l ON true",
        Expect::Runs,
    ),
    (
        "E6",
        "SELECT u.ssn, o.total FROM users u JOIN orders o ON o.user_id = u.id",
        Expect::Runs,
    ),
    (
        "E7",
        "SELECT u.ssn FROM orders o LEFT JOIN users u ON u.id = o.user_id",
        Expect::Runs,
    ),
    (
        "E8",
        "SELECT a.id, b.id FROM users a JOIN users_2024 b ON a.ssn = b.ssn",
        Expect::Runs,
    ),
    (
        "E9",
        "SELECT j.ssn FROM (users u JOIN orders o ON true) AS j",
        Expect::Blocked,
    ),
    (
        "E10",
        "SELECT * FROM users NATURAL JOIN orders",
        Expect::Blocked,
    ),
    (
        "E11",
        "SELECT (SELECT count(*) FROM archive a, orders b JOIN orders c ON c.id = length(ssn)) FROM users u",
        Expect::Runs,
    ),
    (
        "E12",
        "SELECT ssn FROM users u JOIN users_2024 p USING (ssn)",
        Expect::Runs,
    ),
    // `CANARYSSN-1111` is XML content, not a document.
    (
        "E13",
        "SELECT x.a FROM users u, XMLTABLE('/r' PASSING (u.ssn::xml) COLUMNS a text PATH '.') x",
        Expect::NoLeak,
    ),
    // JSON_TABLE is Postgres 17.
    (
        "E14",
        "SELECT j.a FROM users u, JSON_TABLE(to_jsonb(u.ssn), '$' COLUMNS (a text PATH '$')) j",
        Expect::NoLeak,
    ),
    (
        "E15",
        "SELECT g.x FROM users u, unnest(ARRAY[u.ssn]) g(x)",
        Expect::Runs,
    ),
    (
        "E16",
        "SELECT c.relname, u.ssn FROM pg_class c, users u",
        Expect::Runs,
    ),
    (
        "E18",
        "SELECT l.v FROM orders o2, LATERAL (SELECT total AS v FROM ((SELECT ssn FROM users) s CROSS JOIN (SELECT 1 AS k) k) AS j(total)) l",
        Expect::Runs,
    ),
    (
        "E18",
        "SELECT x.* FROM orders o2, LATERAL (SELECT total FROM ((SELECT ssn FROM users) s CROSS JOIN (SELECT 1 AS k) k) AS j(total)) x",
        Expect::Runs,
    ),
    (
        "E18",
        "SELECT (SELECT total FROM ((SELECT ssn FROM users) s CROSS JOIN (SELECT 1 AS k) k) AS j(total) LIMIT 1) FROM orders",
        Expect::Runs,
    ),
    (
        "E19",
        "SELECT l.v FROM users u, LATERAL (SELECT u.ssn AS v FROM (orders u CROSS JOIN orders o) AS j) l",
        Expect::Runs,
    ),
    (
        "E19",
        "SELECT (SELECT u.ssn FROM (orders u CROSS JOIN orders o) AS j LIMIT 1) FROM users u",
        Expect::Runs,
    ),
    (
        "E19",
        "SELECT l.v FROM users u, LATERAL (SELECT u.email AS v FROM (orders u CROSS JOIN orders o) AS j) l",
        Expect::Runs,
    ),
    (
        "E19",
        "SELECT l.v FROM users u, LATERAL (SELECT u.salary AS v FROM (orders u CROSS JOIN orders o) AS j) l",
        Expect::Runs,
    ),
    (
        "E20",
        "SELECT l.v FROM (SELECT ssn FROM users) s, LATERAL (SELECT s.ssn AS v FROM ((SELECT 'clean'::varchar AS ssn) s CROSS JOIN orders o) AS j) l",
        Expect::Runs,
    ),
    (
        "E20",
        "SELECT (SELECT s.ssn FROM ((SELECT 'clean'::varchar AS ssn) s CROSS JOIN orders o) AS j LIMIT 1) FROM (SELECT ssn FROM users) s",
        Expect::Runs,
    ),
    (
        "E21",
        "SELECT l.v FROM (SELECT 'c'::varchar AS ssn) x, LATERAL (SELECT x.ssn AS v FROM (SELECT ssn FROM users) a JOIN (SELECT ssn FROM users) b USING (ssn) AS x) l",
        Expect::Runs,
    ),
    (
        "E22",
        "SELECT j.x FROM ((SELECT ssn AS x FROM users) s JOIN orders o ON true) AS j",
        Expect::Runs,
    ),
    (
        "E23",
        "SELECT * FROM (orders a JOIN orders b ON true) j, users u",
        Expect::Blocked,
    ),
    (
        "E23",
        "SELECT 1 WHERE EXISTS (SELECT * FROM (orders a JOIN orders b ON true) j)",
        Expect::Runs,
    ),
    (
        "E23",
        "SELECT * FROM (SELECT * FROM (orders a JOIN orders b ON true) j) s",
        Expect::Runs,
    ),
    // Grouping, DISTINCT, ordering.
    ("F1", "SELECT DISTINCT ssn FROM users", Expect::Runs),
    (
        "F2",
        "SELECT ssn, count(*) FROM users GROUP BY ssn HAVING count(*) > 0",
        Expect::Runs,
    ),
    (
        "F3",
        "SELECT count(*) FROM users GROUP BY ssn",
        Expect::Runs,
    ),
    (
        "F4",
        "SELECT ssn FROM users ORDER BY ssn DESC LIMIT 5 OFFSET 0",
        Expect::Runs,
    ),
    ("F5", "SELECT ssn FROM users ORDER BY 1", Expect::Runs),
    (
        "F6",
        "SELECT DISTINCT ON (ssn) ssn, email FROM users ORDER BY ssn, id",
        Expect::Runs,
    ),
    ("F7", "SELECT ssn FROM users GROUP BY 1", Expect::Runs),
    (
        "F8",
        "SELECT id FROM users GROUP BY id HAVING max(ssn) > 'C'",
        Expect::Runs,
    ),
    (
        "F9",
        "SELECT ssn FROM users ORDER BY upper(ssn) LIMIT 1",
        Expect::Runs,
    ),
    (
        "F10",
        "SELECT upper(name) AS n FROM users ORDER BY n",
        Expect::Runs,
    ),
    (
        "F11",
        "SELECT ssn AS name FROM users ORDER BY name",
        Expect::Runs,
    ),
    (
        "F12",
        "SELECT upper(name) AS n, count(*) FROM users GROUP BY n",
        Expect::Runs,
    ),
    // Conditions.
    (
        "G1",
        "SELECT id FROM users WHERE ssn = 'CANARYSSN-1111'",
        Expect::Runs,
    ),
    (
        "G2",
        "SELECT id FROM users WHERE ssn::int > 5",
        Expect::Fails("22P02"),
    ),
    (
        "G3",
        "SELECT id, name FROM users WHERE upper(ssn) LIKE upper('canaryssn%') AND name = 'alice'",
        Expect::Runs,
    ),
    (
        "G4",
        "SELECT id FROM users WHERE ssn IN (SELECT ssn FROM users_2024)",
        Expect::Runs,
    ),
    (
        "G5",
        "SELECT id FROM users WHERE ssn = ANY('{CANARYSSN-1111}') OR ssn IS NULL",
        Expect::Runs,
    ),
    (
        "G6",
        "SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id AND u.ssn = 'CANARYSSN-2222'",
        Expect::Runs,
    ),
    (
        "G7",
        "SELECT id FROM users WHERE ssn = 'CANARYSSN-1111' AND email = 'x'",
        Expect::Runs,
    ),
    (
        "G8",
        "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM users_2024 p WHERE p.ssn = users.ssn)",
        Expect::Runs,
    ),
    (
        "G9",
        "SELECT id FROM users u WHERE row_to_json(u)::text LIKE '%9%'",
        Expect::Runs,
    ),
    (
        "G10",
        "SELECT id FROM user_loud WHERE loud = 'CANARYSSN-1111'",
        Expect::Runs,
    ),
    (
        "G11",
        "SELECT id FROM ssn_flags WHERE starts_9",
        Expect::Runs,
    ),
    // Computed outputs.
    ("H1", "SELECT upper(ssn) FROM users", Expect::Runs),
    ("H2", "SELECT 'x' || ssn AS tagged FROM users", Expect::Runs),
    ("H3", "SELECT ssn::int FROM users", Expect::Fails("22P02")),
    ("H4", "SELECT coalesce(ssn, '') FROM users", Expect::Runs),
    (
        "H5",
        "SELECT CASE WHEN ssn IS NULL THEN 'none' ELSE ssn END FROM users",
        Expect::Runs,
    ),
    (
        "H6",
        "SELECT id, ssn = 'CANARYSSN-1111' AS hit FROM users",
        Expect::Runs,
    ),
    (
        "H7",
        "SELECT length(ssn), ssn IS NULL FROM users",
        Expect::Runs,
    ),
    (
        "H8",
        "SELECT max(ssn), count(ssn), count(*) FROM users",
        Expect::Runs,
    ),
    ("H9", "SELECT string_agg(ssn, ',') FROM users", Expect::Runs),
    (
        "H10",
        "SELECT id, lag(ssn) OVER (ORDER BY id) FROM users",
        Expect::Runs,
    ),
    (
        "H11",
        "SELECT id, row_number() OVER (ORDER BY ssn) FROM users",
        Expect::Runs,
    ),
    (
        "H12",
        "SELECT count(*) FILTER (WHERE ssn LIKE 'C%') FROM users",
        Expect::Runs,
    ),
    (
        "H13",
        "SELECT json_build_object('s', ssn), to_jsonb(ssn) FROM users",
        Expect::Runs,
    ),
    (
        "H14",
        "SELECT ROW(id, ssn), ARRAY[ssn] FROM users",
        Expect::Runs,
    ),
    ("H15", "SELECT u FROM users u", Expect::Runs),
    ("H16", "SELECT row_to_json(u) FROM users u", Expect::Runs),
    ("H18", "SELECT (u).ssn FROM users u", Expect::Runs),
    (
        "H19",
        "SELECT xmlelement(name x, ssn) FROM users",
        Expect::Runs,
    ),
    (
        "H20",
        "SELECT string_agg(name, ',' ORDER BY ssn) FROM users",
        Expect::Runs,
    ),
    (
        "H21",
        "SELECT id, rank() OVER w FROM users WINDOW w AS (PARTITION BY ssn)",
        Expect::Runs,
    ),
    (
        "H22",
        "SELECT id, rank() OVER (w ORDER BY id) FROM users WINDOW w AS (PARTITION BY ssn)",
        Expect::Runs,
    ),
    (
        "H23",
        "SELECT CASE WHEN ssn LIKE 'C%' THEN 'c' ELSE 'other' END FROM users",
        Expect::Runs,
    ),
    ("H24", "SELECT u::text FROM users u", Expect::Runs),
    ("H25", "SELECT u.row_to_json FROM users u", Expect::Blocked),
    (
        "H26",
        "SELECT masking_canary_proxy.users.to_jsonb FROM masking_canary_proxy.users",
        Expect::Blocked,
    ),
    (
        "H28",
        "SELECT s.to_json FROM (SELECT ssn FROM users) s",
        Expect::Blocked,
    ),
    ("H29", "SELECT o.row_to_json FROM orders o", Expect::Runs),
    // Sublinks in outputs.
    (
        "I1",
        "SELECT (SELECT ssn FROM users WHERE id = 1)",
        Expect::Runs,
    ),
    (
        "I2",
        "SELECT o.id, (SELECT u.ssn FROM users u WHERE u.id = o.user_id) FROM orders o",
        Expect::Runs,
    ),
    (
        "I3",
        "SELECT (SELECT upper(ssn) FROM users LIMIT 1)",
        Expect::Runs,
    ),
    ("I4", "SELECT ARRAY(SELECT ssn FROM users)", Expect::Runs),
    (
        "I5",
        "SELECT EXISTS (SELECT 1 FROM users WHERE ssn = 'CANARYSSN-1111')",
        Expect::Runs,
    ),
    (
        "I6",
        "SELECT 'x'::text IN (SELECT ssn FROM users) AS found",
        Expect::Runs,
    ),
    (
        "I7",
        "SELECT o.id, o.user_id IN (SELECT id FROM users WHERE ssn LIKE 'C%') FROM orders o",
        Expect::Runs,
    ),
    ("I8", "SELECT EXISTS (SELECT ssn FROM users)", Expect::Runs),
    // RETURNING: the trigger raises the proxy-masked value on every update.
    (
        "J1",
        "BEGIN; UPDATE users SET name = 'x' WHERE id = 1 RETURNING ssn; ROLLBACK",
        Expect::Runs,
    ),
    (
        "J2",
        "BEGIN; DELETE FROM users WHERE id = 1 RETURNING *; ROLLBACK",
        Expect::Runs,
    ),
    (
        "J3",
        "BEGIN; UPDATE users SET name = 'x' WHERE id = 1 RETURNING id, upper(ssn); ROLLBACK",
        Expect::Runs,
    ),
    (
        "J4",
        "BEGIN; INSERT INTO users (id, name, ssn) VALUES (9, 'z', 'CANARYSSN-9999') RETURNING id, ssn; ROLLBACK",
        Expect::Runs,
    ),
    (
        "J5",
        "BEGIN; INSERT INTO users (id, name, ssn) VALUES (1, 'z', 'x') ON CONFLICT (id) DO UPDATE SET ssn = excluded.ssn RETURNING ssn; ROLLBACK",
        Expect::Runs,
    ),
    (
        "J6",
        "BEGIN; UPDATE orders o SET total = 0 FROM users u WHERE u.id = o.user_id AND u.ssn = 'CANARYSSN-1111' RETURNING o.id, u.ssn; ROLLBACK",
        Expect::Runs,
    ),
    (
        "J7",
        "BEGIN; UPDATE users SET name = 'x' WHERE ssn = 'CANARYSSN-1111' RETURNING id; ROLLBACK",
        Expect::Runs,
    ),
    (
        "J8",
        "BEGIN; INSERT INTO users (id, name) SELECT id + 100, name FROM users WHERE ssn LIKE 'C%' RETURNING ssn; ROLLBACK",
        Expect::Runs,
    ),
    // RETURNING old and new are Postgres 18.
    (
        "J9",
        "BEGIN; UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.ssn, new.ssn; ROLLBACK",
        Expect::NoLeak,
    ),
    (
        "J10",
        "BEGIN; UPDATE users SET name = 'x' WHERE id = 1 RETURNING old.*; ROLLBACK",
        Expect::NoLeak,
    ),
    (
        "J11",
        "BEGIN; DELETE FROM users WHERE id = 1 RETURNING old; ROLLBACK",
        Expect::NoLeak,
    ),
    (
        "J12",
        "BEGIN; UPDATE users SET name = 'x' RETURNING WITH (OLD AS o) o.ssn; ROLLBACK",
        Expect::NoLeak,
    ),
    (
        "J13",
        "BEGIN; UPDATE orders SET total = 0 WHERE id = 1 RETURNING id; ROLLBACK",
        Expect::Runs,
    ),
    // Writes.
    (
        "K1",
        "INSERT INTO orders (id, user_id, total) SELECT id, id, length(ssn) FROM users",
        Expect::Blocked,
    ),
    (
        "K2",
        "INSERT INTO users_2024 (id, name) SELECT id, ssn FROM users",
        Expect::Blocked,
    ),
    (
        "K3",
        "INSERT INTO users_2024 SELECT * FROM users",
        Expect::Blocked,
    ),
    (
        "K4",
        "BEGIN; INSERT INTO orders (id, user_id, total) SELECT id + 100, id, 0 FROM users WHERE ssn = 'CANARYSSN-1111'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "K5",
        "BEGIN; INSERT INTO orders (id, user_id, total) VALUES (100, (SELECT id FROM users WHERE ssn = 'CANARYSSN-1111'), 0); ROLLBACK",
        Expect::Runs,
    ),
    (
        "K6",
        "INSERT INTO users (id, name) VALUES (3, (SELECT ssn FROM users WHERE id = 1))",
        Expect::Blocked,
    ),
    (
        "K7",
        "INSERT INTO users (id, name, ssn) VALUES (1, 'z', 'x') ON CONFLICT (id) DO UPDATE SET name = users.ssn",
        Expect::Blocked,
    ),
    (
        "K8",
        "UPDATE users SET name = ssn WHERE id = 1",
        Expect::Blocked,
    ),
    (
        "K9",
        "UPDATE users SET name = CASE WHEN ssn LIKE 'C%' THEN 'c' ELSE name END",
        Expect::Blocked,
    ),
    (
        "K10",
        "UPDATE orders SET total = (SELECT length(ssn) FROM users WHERE users.id = orders.user_id)",
        Expect::Blocked,
    ),
    (
        "K11",
        "UPDATE users SET ssn = upper(ssn) WHERE id = 1",
        Expect::Blocked,
    ),
    (
        "K12",
        "BEGIN; UPDATE users SET ssn = 'CANARYSSN-0000' WHERE id = 2; ROLLBACK",
        Expect::Runs,
    ),
    (
        "K13",
        "BEGIN; UPDATE orders o SET total = 0 FROM users u WHERE u.id = o.user_id AND u.ssn LIKE 'C%'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "K14",
        "BEGIN; DELETE FROM users WHERE ssn = 'CANARYSSN-1111'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "K15",
        "BEGIN; DELETE FROM orders USING users u WHERE u.id = orders.user_id AND u.ssn = 'CANARYSSN-1111'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "K16",
        "BEGIN; INSERT INTO users (id, name, ssn) VALUES (9, 'z', 'CANARYSSN-9999'); ROLLBACK",
        Expect::Runs,
    ),
    (
        "K17",
        "UPDATE users SET email = ssn WHERE id = 1",
        Expect::Blocked,
    ),
    ("K18", "UPDATE users SET ssn = ssn", Expect::Blocked),
    (
        "K19",
        "INSERT INTO audit (note) SELECT ssn FROM users WHERE false",
        Expect::Blocked,
    ),
    (
        "K20",
        "UPDATE users SET (name, opted_in) = (SELECT ssn, true FROM users_2024 LIMIT 1)",
        Expect::Blocked,
    ),
    (
        "K21",
        "BEGIN; INSERT INTO audit DEFAULT VALUES; ROLLBACK",
        Expect::Runs,
    ),
    (
        "K22",
        "UPDATE tags SET labels[length(u.ssn)] = 'x' FROM users u WHERE u.id = tags.id",
        Expect::Blocked,
    ),
    // CREATE TABLE AS, SELECT INTO, data-modifying CTEs.
    (
        "L1",
        "CREATE TABLE scratch AS SELECT id, ssn FROM users",
        Expect::Blocked,
    ),
    (
        "L2",
        "BEGIN; CREATE TABLE scratch AS SELECT id FROM users WHERE ssn = 'CANARYSSN-1111'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "L3",
        "SELECT id, ssn INTO scratch FROM users",
        Expect::Blocked,
    ),
    (
        "L4",
        "BEGIN; SELECT id INTO scratch FROM users WHERE ssn LIKE 'C%'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "L5",
        "CREATE MATERIALIZED VIEW mv AS SELECT upper(ssn) FROM users",
        Expect::Blocked,
    ),
    (
        "L6",
        "CREATE TABLE scratch AS SELECT ssn FROM users WITH NO DATA",
        Expect::Blocked,
    ),
    (
        "L7",
        "WITH moved AS (DELETE FROM users WHERE id = 1 RETURNING id, ssn) INSERT INTO orders (id, user_id, total) SELECT id, id, length(ssn) FROM moved",
        Expect::Blocked,
    ),
    (
        "L8",
        "WITH u AS (UPDATE users SET name = ssn WHERE id = 1 RETURNING id) SELECT id FROM u",
        Expect::Blocked,
    ),
    (
        "L9",
        "BEGIN; WITH d AS (DELETE FROM users WHERE id = 1 RETURNING ssn) SELECT ssn FROM d; ROLLBACK",
        Expect::Runs,
    ),
    (
        "L10",
        "BEGIN; WITH ins AS (INSERT INTO orders (id, user_id, total) SELECT id + 100, id, 0 FROM users WHERE ssn = 'CANARYSSN-1111' RETURNING id) SELECT count(*) FROM ins; ROLLBACK",
        Expect::Runs,
    ),
    (
        "L11",
        "BEGIN; WITH d AS (DELETE FROM users WHERE id = 1 RETURNING *) SELECT * FROM d; ROLLBACK",
        Expect::Runs,
    ),
    ("L12", "CREATE TABLE users AS SELECT 1", Expect::Blocked),
    (
        "L13",
        "SELECT id::text INTO t FROM users UNION ALL SELECT ssn FROM users",
        Expect::Blocked,
    ),
    // COPY.
    ("M1", "COPY users TO STDOUT", Expect::Blocked),
    (
        "M2",
        "COPY users (id, ssn) TO STDOUT WITH (FORMAT csv)",
        Expect::Blocked,
    ),
    ("M3", "COPY users (id, name) TO STDOUT", Expect::Runs),
    ("M4", "COPY users (id, email) TO STDOUT", Expect::Runs),
    (
        "M5",
        "COPY (SELECT id, upper(ssn) FROM users) TO STDOUT",
        Expect::Blocked,
    ),
    (
        "M6",
        "COPY (SELECT id FROM users WHERE ssn = 'CANARYSSN-1111') TO STDOUT",
        Expect::Runs,
    ),
    (
        "M7",
        "COPY (SELECT * FROM user_ssns) TO STDOUT",
        Expect::Blocked,
    ),
    ("M8", "COPY users_2024 TO STDOUT", Expect::Blocked),
    ("M10", "COPY orders TO STDOUT", Expect::Runs),
    ("M11", "COPY users TO '/tmp/x'", Expect::Blocked),
    // DECLARE, PREPARE, EXECUTE, FETCH.
    (
        "N1",
        "DECLARE c CURSOR FOR SELECT id, ssn FROM users",
        Expect::Blocked,
    ),
    (
        "N2",
        "BEGIN; DECLARE c CURSOR FOR SELECT id, name FROM users; FETCH ALL FROM c; ROLLBACK",
        Expect::Runs,
    ),
    (
        "N3",
        "DECLARE c CURSOR FOR SELECT id FROM users WHERE ssn::int > 5",
        Expect::Blocked,
    ),
    (
        "N4",
        "PREPARE p AS SELECT ssn FROM users WHERE id = $1",
        Expect::Blocked,
    ),
    (
        "N5",
        "PREPARE n5 AS SELECT id, name FROM users WHERE id = $1; DEALLOCATE n5",
        Expect::Runs,
    ),
    (
        "N6",
        "PREPARE p AS SELECT id FROM users WHERE ssn = $1",
        Expect::Blocked,
    ),
    ("N7", "EXECUTE p(1)", Expect::Blocked),
    (
        "N8",
        "BEGIN; DECLARE c CURSOR FOR SELECT id FROM orders; FETCH ALL FROM c; MOVE NEXT IN c; ROLLBACK",
        Expect::Runs,
    ),
    (
        "N9",
        "PREPARE p AS UPDATE users SET name = ssn WHERE id = $1",
        Expect::Blocked,
    ),
    (
        "N10",
        "BEGIN; DECLARE c CURSOR FOR SELECT ssn FROM users; FETCH ALL FROM c; COMMIT",
        Expect::Blocked,
    ),
    (
        "N11",
        "DECLARE c CURSOR WITH HOLD FOR SELECT id FROM users WHERE ssn::int > 5",
        Expect::Blocked,
    ),
    (
        "N12",
        "EXECUTE p((SELECT ssn FROM users LIMIT 1))",
        Expect::Blocked,
    ),
    (
        "N13",
        "PREPARE p AS UPDATE users SET name = $1 WHERE id = $2 RETURNING ssn",
        Expect::Blocked,
    ),
    ("N14", "CREATE TABLE t AS EXECUTE p(1)", Expect::Blocked),
    (
        "N15",
        "PREPARE n15 AS SELECT id, name FROM users WHERE id = $1; EXECUTE n15(1); DEALLOCATE n15",
        Expect::Runs,
    ),
    ("N16", "EXECUTE __pgdog_1", Expect::Blocked),
    (
        "N17",
        "PREPARE p AS SELECT id FROM users ORDER BY ssn",
        Expect::Blocked,
    ),
    // Side-effect built-ins.
    (
        "O1",
        "SELECT set_config('app.x', ssn, false) FROM users",
        Expect::Blocked,
    ),
    (
        "O2",
        "SELECT pg_notify('ch', ssn) FROM users",
        Expect::Blocked,
    ),
    (
        "O3",
        "SELECT setval('order_seq', length(ssn)) FROM users",
        Expect::Blocked,
    ),
    (
        "O4",
        "SELECT pg_logical_emit_message(true, 'pfx', ssn) FROM users",
        Expect::Blocked,
    ),
    (
        "O5",
        "SELECT id FROM users WHERE set_config('app.x', ssn, false) IS NOT NULL",
        Expect::Blocked,
    ),
    (
        "O6",
        "SELECT pg_advisory_lock(hashtext(ssn)) FROM users",
        Expect::Blocked,
    ),
    (
        "O7",
        "SELECT lo_from_bytea(0, convert_to(ssn, 'UTF8')) FROM users",
        Expect::Blocked,
    ),
    (
        "O8",
        "SELECT set_config('app.matched', 'yes', false) FROM users WHERE ssn = 'CANARYSSN-1111'",
        Expect::Runs,
    ),
    (
        "O9",
        "SELECT pg_notify('ch', name) FROM users ORDER BY ssn",
        Expect::Runs,
    ),
    (
        "O10",
        "SELECT pg_catalog.set_config('app.x', upper(ssn), true) FROM users",
        Expect::Blocked,
    ),
    ("O11", "SELECT current_setting('app.x', true)", Expect::Runs),
    (
        "O12",
        "SELECT id FROM users WHERE pg_advisory_xact_lock(hashtext(ssn)) IS NOT NULL",
        Expect::Blocked,
    ),
    (
        "O13",
        "SELECT * FROM pg_logical_slot_get_changes('s', NULL, NULL)",
        Expect::Blocked,
    ),
    (
        "O14",
        "SELECT setseed(length(ssn) / 100.0) FROM users",
        Expect::Blocked,
    ),
    (
        "O15",
        "SELECT * FROM set_config('app.x', (SELECT ssn FROM users LIMIT 1), false)",
        Expect::Blocked,
    ),
    (
        "O18",
        "SELECT pg_replication_slot_advance('s', ssn::pg_lsn) FROM users",
        Expect::Blocked,
    ),
    (
        "O19",
        "SELECT pg_copy_logical_replication_slot(ssn, 'x') FROM users",
        Expect::Blocked,
    ),
    ("O20", "SELECT nextval(ssn) FROM users", Expect::Blocked),
    // Functions and operators.
    ("P1", "SELECT my_func(ssn) FROM users", Expect::Blocked),
    ("P2", "SELECT stash(ssn) FROM users", Expect::Blocked),
    (
        "P3",
        "SELECT stash(name) FROM users WHERE ssn = 'none'",
        Expect::Runs,
    ),
    ("P4", "SELECT safe_fn(ssn) FROM users", Expect::Runs),
    ("P6", "SELECT last4(ssn) FROM users", Expect::Runs),
    (
        "P7",
        "SELECT id FROM users WHERE last4(ssn) = '1111'",
        Expect::Runs,
    ),
    (
        "P8",
        "SELECT user_ssn(o.user_id) FROM orders o",
        Expect::Runs,
    ),
    (
        "P9",
        "SELECT s.ssn FROM ssns() s WHERE s.id = 1",
        Expect::Runs,
    ),
    ("P10", "SELECT user_ssn_definer(1)", Expect::Runs),
    ("P10", "SELECT volatile_ssn(1)", Expect::Runs),
    ("P10", "SELECT atomic_ssn(1)", Expect::Runs),
    ("P11", "SELECT plpgsql_fn()", Expect::Blocked),
    ("P12", "SELECT last4(name) FROM users", Expect::Runs),
    ("P13", "SELECT ssn_is(1, 'CANARYSSN-1111')", Expect::Runs),
    ("P14", "SELECT notify_fn(ssn) FROM users", Expect::Blocked),
    ("P15", "SELECT wrap_stash(ssn) FROM users", Expect::Blocked),
    ("P16", "SELECT upper_safe(ssn) FROM users", Expect::Runs),
    (
        "P17",
        "SELECT id FROM orders WHERE id @@@ user_id",
        Expect::Runs,
    ),
    ("P18", "SELECT ssn === 'x' FROM users", Expect::Runs),
    ("P19", "SELECT email_of(1)", Expect::Runs),
    (
        "P20",
        "SELECT * FROM stash((SELECT ssn FROM users LIMIT 1)) s",
        Expect::Blocked,
    ),
    ("P21", "SELECT * FROM ssns()", Expect::Blocked),
    ("P22", "SELECT count_users()", Expect::Runs),
    (
        "P23",
        "SELECT id FROM users WHERE ssn ~~~ 'x'",
        Expect::Blocked,
    ),
    (
        "P24",
        "SELECT recursive_fn(length(ssn)) FROM users",
        Expect::Blocked,
    ),
    // Views.
    ("Q1", "SELECT ssn FROM user_ssns", Expect::Runs),
    (
        "Q2",
        "SELECT ssn, email FROM user_contacts WHERE id = 1",
        Expect::Runs,
    ),
    ("Q3", "SELECT loud FROM user_loud", Expect::Runs),
    ("Q4", "SELECT ssn FROM ssn_barrier", Expect::Runs),
    ("Q5", "SELECT loud FROM ssn_barrier", Expect::Runs),
    (
        "Q6",
        "SELECT id FROM ssn_barrier WHERE loud = 'CANARYSSN-1111'",
        Expect::Runs,
    ),
    ("Q7", "SELECT * FROM ssn_barrier", Expect::Runs),
    ("Q8", "SELECT ssn FROM ssn_counts", Expect::Runs),
    (
        "Q10",
        "SELECT v.s FROM user_ssns AS v(i, s) WHERE v.i = 1",
        Expect::Runs,
    ),
    (
        "Q11",
        "UPDATE user_ssns SET ssn = 'x' WHERE id = 1",
        Expect::Blocked,
    ),
    ("Q12", "SELECT ssn FROM nested_v", Expect::Runs),
    ("Q13", "SELECT * FROM user_ssns", Expect::Runs),
    ("Q14", "LOCK TABLE user_ssns", Expect::Blocked),
    // EXPLAIN. Plans quote the statement's literals, so they're no canaries.
    (
        "R1",
        "EXPLAIN SELECT ssn FROM users WHERE ssn = 'x'",
        Expect::Runs,
    ),
    (
        "R2",
        "EXPLAIN (ANALYZE, BUFFERS) SELECT id FROM users WHERE ssn::int > 5",
        Expect::Fails("22P02"),
    ),
    (
        "R3",
        "EXPLAIN ANALYZE SELECT upper(ssn) FROM users",
        Expect::Runs,
    ),
    ("R4", "EXPLAIN SELECT * FROM users", Expect::Runs),
    (
        "R5",
        "EXPLAIN ANALYZE UPDATE users SET name = ssn WHERE id = 1",
        Expect::Blocked,
    ),
    (
        "R6",
        "BEGIN; EXPLAIN ANALYZE UPDATE users SET name = 'x' WHERE ssn = 'x'; ROLLBACK",
        Expect::Runs,
    ),
    (
        "R7",
        "EXPLAIN UPDATE users SET name = ssn WHERE id = 1",
        Expect::Runs,
    ),
    (
        "R8",
        "EXPLAIN ANALYZE SELECT pg_notify('ch', ssn) FROM users",
        Expect::Blocked,
    ),
    (
        "R9",
        "EXPLAIN (ANALYZE) CREATE TABLE scratch AS SELECT ssn FROM users",
        Expect::Blocked,
    ),
    (
        "R10",
        "EXPLAIN (FORMAT JSON) SELECT ssn FROM users",
        Expect::Runs,
    ),
    (
        "R11",
        "EXPLAIN INSERT INTO audit (note) SELECT ssn FROM users",
        Expect::Runs,
    ),
    (
        "R12",
        "EXPLAIN (ANALYZE false) UPDATE users SET name = ssn",
        Expect::Runs,
    ),
    (
        "R13",
        "EXPLAIN (ANALYZE, VERBOSE) SELECT ssn FROM users",
        Expect::Runs,
    ),
    (
        "R14",
        "EXPLAIN ANALYZE MERGE INTO orders o USING users u ON o.user_id = u.id WHEN MATCHED THEN DELETE",
        Expect::Blocked,
    ),
    (
        "R15",
        "EXPLAIN SELECT set_config('x.y', ssn, false) FROM users",
        Expect::Runs,
    ),
    (
        "R16",
        "EXPLAIN EXECUTE p((SELECT ssn FROM users LIMIT 1))",
        Expect::Blocked,
    ),
    ("R16", "EXPLAIN ANALYZE EXECUTE p(1)", Expect::Blocked),
    (
        "R17",
        "EXPLAIN SELECT id FROM users WHERE ssn ~~~ 'x'",
        Expect::Blocked,
    ),
    // Multi-statement queries.
    ("S1", "SELECT 1; SELECT ssn FROM users", Expect::Runs),
    (
        "S2",
        "BEGIN; SELECT id, ssn FROM users WHERE id = 1; COMMIT",
        Expect::Runs,
    ),
    (
        "S3",
        "SET application_name = 'dbg'; SELECT * FROM users; SELECT ssn FROM users WHERE ssn = 'CANARYSSN-1111'",
        Expect::Runs,
    ),
    (
        "S4",
        "BEGIN; UPDATE users SET name = 'x' WHERE id = 1 RETURNING ssn; SELECT upper(ssn) FROM users; ROLLBACK",
        Expect::Runs,
    ),
    (
        "S5",
        "SELECT ssn FROM users; UPDATE users SET name = ssn",
        Expect::Blocked,
    ),
    (
        "S6",
        "SELECT ssn FROM users; COPY users TO STDOUT",
        Expect::Blocked,
    ),
    (
        "S7",
        "PREPARE s7 AS SELECT id FROM users WHERE id = $1; EXECUTE s7(1); DEALLOCATE s7",
        Expect::Runs,
    ),
    ("S8", "SELECT ssn FROM users;", Expect::Runs),
    (
        "S9",
        "EXPLAIN SELECT ssn FROM users; SELECT ssn FROM users",
        Expect::Runs,
    ),
    (
        "S10",
        "SELECT id FROM orders; SELECT ssn FROM users WHERE id = 1; SELECT name FROM users",
        Expect::Runs,
    ),
    (
        "S11",
        "SET search_path TO masking_canary_proxy; SELECT ssn FROM users",
        Expect::Blocked,
    ),
    (
        "S12",
        "SELECT set_config('search_path', 'masking_canary_proxy', false); SELECT ssn FROM users",
        Expect::Blocked,
    ),
    (
        "S13",
        "SELECT ssn FROM users; SET search_path TO masking_canary_proxy",
        Expect::Runs,
    ),
    (
        "S14",
        "SET search_path TO masking_canary_proxy; SELECT 1",
        Expect::Runs,
    ),
    ("S15", "SELECT 1;; SELECT ssn FROM users", Expect::Runs),
    (
        "S16",
        "SELECT upper(ssn) FROM users; SELECT 1",
        Expect::Runs,
    ),
    (
        "S17",
        "DROP TABLE archive; SELECT ssn FROM users",
        Expect::Blocked,
    ),
    (
        "S18",
        "SELECT set_config('search_path', 'masking_canary_proxy', false)",
        Expect::Blocked,
    ),
    (
        "S19",
        "SELECT id, set_config('search_path', 'masking_canary_proxy', false) FROM orders",
        Expect::Blocked,
    ),
    // Parameters and literals.
    ("V1", "SELECT ssn FROM users WHERE id = 1", Expect::Runs),
    (
        "V2",
        "SELECT ssn, email FROM users WHERE ssn = 'CANARYSSN-1111' AND email = 'x'",
        Expect::Runs,
    ),
    (
        "V3",
        "SELECT ssn FROM users WHERE ssn = 'CANARYSSN-1111' AND id = 1",
        Expect::Runs,
    ),
    (
        "V4",
        "SELECT id FROM users WHERE ssn::int = 5",
        Expect::Fails("22P02"),
    ),
    (
        "V5",
        "SELECT 'lit', ssn FROM users WHERE id = 1",
        Expect::Runs,
    ),
    // Existing blocks, DDL and maintenance.
    ("W1", "DO $$ BEGIN PERFORM 1; END $$", Expect::Blocked),
    (
        "W2",
        "MERGE INTO users u USING orders o ON u.id = o.user_id WHEN MATCHED THEN DELETE",
        Expect::Blocked,
    ),
    (
        "W3",
        "SELECT * FROM pg_stats WHERE tablename = 'users'",
        Expect::Blocked,
    ),
    ("W4", "CREATE INDEX ON users ((ssn::int))", Expect::Blocked),
    (
        "W5",
        "SELECT query_to_xml('SELECT ssn FROM masking_canary_proxy.users', true, true, '')",
        Expect::Blocked,
    ),
    ("W7", "SELECT lo_get(1)", Expect::Blocked),
    (
        "W8",
        "SELECT pg_logical_slot_peek_changes('s', NULL, NULL)",
        Expect::Blocked,
    ),
    (
        "W9",
        "ALTER TABLE orders ADD COLUMN x text DEFAULT masking_canary_proxy.user_ssn(1)",
        Expect::Blocked,
    ),
    (
        "W10",
        "CREATE TABLE t (x text DEFAULT masking_canary_proxy.user_ssn(1))",
        Expect::Blocked,
    ),
    (
        "W11",
        "ALTER TABLE audit ALTER note TYPE text USING masking_canary_proxy.user_ssn(id)",
        Expect::Blocked,
    ),
    (
        "W12",
        "CREATE INDEX ON audit ((masking_canary_proxy.user_ssn(id)))",
        Expect::Blocked,
    ),
    (
        "W13",
        "BEGIN; CREATE TABLE t (x text DEFAULT 'a'); ROLLBACK",
        Expect::Runs,
    ),
    ("W14", "VACUUM ANALYZE users", Expect::Runs),
    ("W15", "BEGIN; LOCK TABLE users; ROLLBACK", Expect::Runs),
    ("W15", "BEGIN; TRUNCATE users; ROLLBACK", Expect::Runs),
    ("W16", "ANALYZE orders", Expect::Runs),
    // A relation hiding `archive`, or `archive` losing its `ssn` column, would
    // make `ssn` below read `users.ssn` while the catalog says `archive.ssn`.
    // Statements run on one connection, in order.
    (
        "R-temp",
        "CREATE TEMP TABLE archive (id BIGINT)",
        Expect::Blocked,
    ),
    (
        "R-temp",
        "CREATE TABLE pg_temp.archive (id BIGINT)",
        Expect::Blocked,
    ),
    ("R-temp", "CREATE TEMP SEQUENCE archive", Expect::Blocked),
    (
        "R-temp",
        "SELECT 1 AS id INTO TEMP archive",
        Expect::Blocked,
    ),
    (
        "R-temp",
        "CREATE TEMP TABLE archive AS SELECT 1 AS id",
        Expect::Blocked,
    ),
    (
        "R-temp",
        "CREATE TEMP TABLE archive (LIKE orders)",
        Expect::Blocked,
    ),
    (
        "R-ddl",
        "ALTER TABLE archive DROP COLUMN ssn",
        Expect::Blocked,
    ),
    (
        "R-ddl",
        "ALTER TABLE archive RENAME COLUMN ssn TO s2",
        Expect::Blocked,
    ),
    (
        "R-ddl",
        "ALTER TABLE archive DROP COLUMN ssn, ADD COLUMN note TEXT",
        Expect::Blocked,
    ),
    (
        "R-ddl",
        "ALTER TABLE archive RENAME TO old",
        Expect::Blocked,
    ),
    ("R-ddl", "CREATE TABLE archive (id BIGINT)", Expect::Blocked),
    (
        "R-temp",
        "SELECT x.ssn FROM users u, LATERAL (SELECT ssn FROM archive) x",
        Expect::Runs,
    ),
    (
        "R-temp",
        "SELECT x.ssn FROM users u JOIN LATERAL (SELECT ssn FROM archive) x ON true",
        Expect::Runs,
    ),
    (
        "R-temp",
        "WITH c AS (SELECT x.ssn FROM users u, LATERAL (SELECT ssn FROM archive) x) SELECT * FROM c",
        Expect::Runs,
    ),
    (
        "R-temp",
        "SELECT (SELECT ssn FROM archive LIMIT 1) FROM users",
        Expect::Runs,
    ),
    (
        "R-temp",
        "SELECT x.ssn FROM users u, LATERAL (SELECT ssn FROM archive WHERE id = 1) x",
        Expect::Runs,
    ),
    // The trigger raises the proxy-masked value in MESSAGE: the write redacts.
    (
        "I-3",
        "BEGIN; UPDATE users SET name = name WHERE id = 1; ROLLBACK",
        Expect::Runs,
    ),
];

/// Write the proxy mask's key to a file, and the config reading it.
fn proxy_config() -> Config {
    let key = std::env::temp_dir().join("pgdog-mask-canary-hmac.key");
    std::fs::write(&key, "canary-hmac-key").expect("write the proxy mask key");
    let config = PROXY_CONFIG.replace("{key}", &key.display().to_string());
    Config::from_toml(&config).expect("valid config")
}

/// The proxy canary schema, set up on a connection of its own.
async fn proxy_fixture() -> (Connection, Catalog, Policies) {
    let conn = connect().await;
    setup_proxy(&conn.client).await;
    let catalog = support::load_catalog(&conn.client, &[PROXY_SCHEMA], &[PROXY_SCHEMA]).await;
    let policies = Policies::new(proxy_config()).expect("valid policies");
    (conn, catalog, policies)
}

/// Proxy masks: statements run on real values and only results are masked.
/// Run as PgDog would, nothing a statement sends back carries a canary.
#[tokio::test]
async fn test_no_canary_leaks_proxy() {
    let (conn, catalog, policies) = proxy_fixture().await;
    let assignments = Assignments::new(&policies, "pgdog", &catalog);

    // Control: the raw results, errors and notices carry the canaries, so
    // the test can detect leaks.
    let out = run(&conn, "SELECT ssn, email, salary FROM users", View::Raw)
        .await
        .unwrap();
    for canary in CANARIES {
        assert!(out.contains(canary), "seed data missing {canary}: {out}");
    }
    for sql in [
        "SELECT ssn::int FROM users",
        "BEGIN; UPDATE users SET name = name WHERE id = 1; ROLLBACK",
    ] {
        let raw = run(&conn, sql, View::Raw).await;
        let _ = conn.client.batch_execute("ROLLBACK").await;
        let text = match &raw {
            Ok(out) | Err(out) => out,
        };
        assert!(leaked(text).is_some(), "{sql}: {text}");
    }

    let profile = policies.profile("anonymous", "pgdog");
    assert!(profile.proxies);
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec![PROXY_SCHEMA.into()],
    };

    // The SQL mask corpus, and the regression corpus.
    let corpus: Vec<_> = CORPUS
        .iter()
        .map(|(sql, _)| ("", *sql, Expect::NoLeak))
        .chain(PROXY_CORPUS.iter().copied())
        .collect();
    let failures = check_corpus(&conn, &ctx, &corpus).await;

    conn.client
        .batch_execute(&format!("DROP SCHEMA {PROXY_SCHEMA} CASCADE"))
        .await
        .expect("cleanup");

    assert!(failures.is_empty(), "\n{}", failures.join("\n\n"));
}

/// Conditions on proxy-masked columns compare real values: they find rows,
/// which come back with the column's token.
#[tokio::test]
async fn test_proxy_filters_find_rows() {
    let conn = connect().await;
    // Separate schema so tests can run in parallel.
    let schema = "masking_canary_filters";
    conn.client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE;
             CREATE SCHEMA {schema};
             SET search_path TO {schema};
             CREATE TABLE users (id BIGINT PRIMARY KEY, ssn VARCHAR(32));
             INSERT INTO users VALUES
                (1, 'CANARYSSN-1111'), (2, 'CANARYSSN-2222'), (3, 'other');"
        ))
        .await
        .unwrap();
    let catalog = support::load_catalog(&conn.client, &[schema], &[schema]).await;
    let policies = Policies::new(proxy_config()).unwrap();
    let assignments = Assignments::new(&policies, "pgdog", &catalog);
    let profile = policies.profile("anonymous", "pgdog");
    let ctx = Context {
        catalog: &catalog,
        assignments: &assignments,
        policies: &policies,
        profile: &profile,
        search_path: vec![schema.into()],
    };

    let sql = "SELECT id, ssn FROM users WHERE ssn LIKE 'CANARY%' ORDER BY ssn";
    let Outcome::Unchanged { results, .. } = analyze(sql, &ctx) else {
        panic!("expected the statement unchanged");
    };
    let view = View::Masked {
        results: &results,
        proxies: &policies.proxies,
    };
    let out = run(&conn, sql, view).await.unwrap();
    let token = |ssn: &str| match policies.proxies[0].mask.mask(Datum::Text(ssn.into())) {
        Ok(Datum::Text(token)) => token,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        out,
        format!(
            "1|{}|\n2|{}|\n",
            token("CANARYSSN-1111"),
            token("CANARYSSN-2222")
        )
    );
    assert!(leaked(&out).is_none(), "{out}");

    conn.client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
