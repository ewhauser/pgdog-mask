//! Protocol matrix (DESIGN.md §13, item 4): the canary leak invariant through
//! PgDog, over every way a client can ask for results.
//!
//! Each scenario runs as an exempt user, who must receive canaries (so the
//! scenario reads them and the check can catch a leak), then as users with
//! masks, whose byte stream from PgDog must hold none: rows, row
//! descriptions, errors, notices and COPY data, in either format.
//!
//! Run with `bash integration/run.sh`; skipped unless `PGDOG_MASK_E2E=1`.
#[path = "support/wire.rs"]
mod wire;

use futures_util::future::try_join_all;
use tokio_postgres::NoTls;
use wire::{BINARY, Response, TEXT, Wire};

const ADDR: &str = "127.0.0.1:6432";

/// The exempt user first, then users with SQL and proxy masks, and with SQL
/// masks only.
const USERS: [&str; 3] = ["admin", "masked", "analyst"];

/// Bytes of the raw values of masked columns (integration/setup.sql), as they
/// would appear on the wire.
const CANARIES: &[(&str, &[u8])] = &[
    // ssn, email, phone and secret_note: SQL masks and tags.
    ("CANARY", b"CANARY"),
    ("canary", b"canary"),
    // card and tax_id: proxy masks. Text and binary encodings are the same.
    ("card 1", b"4111-1111-1111-1111"),
    ("card 2", b"5500-0000-0000-0004"),
    ("tax_id 1", b"TAX-1111"),
    ("tax_id 2", b"TAX-2222"),
    // balance: proxy mask, as a length-prefixed field in text and binary
    // (DataRow, binary COPY), and between delimiters in text and CSV COPY.
    ("balance 1 text", b"\0\0\0\x041000"),
    ("balance 2 text", b"\0\0\0\x042000"),
    ("balance 1 binary", b"\0\0\0\x08\0\0\0\0\0\0\x03\xe8"),
    ("balance 2 binary", b"\0\0\0\x08\0\0\0\0\0\0\x07\xd0"),
    ("balance 1 copy", b"\t1000\t"),
    ("balance 2 copy", b"\t2000\t"),
    ("balance 1 csv", b",1000,"),
    ("balance 2 csv", b",2000,"),
];

fn enabled() -> bool {
    std::env::var("PGDOG_MASK_E2E").is_ok_and(|v| v == "1")
}

async fn connect(user: &str) -> Wire {
    Wire::connect(ADDR, user, "pgdog", "pgdog").await
}

/// Canaries in a byte stream, with some context around each.
fn leaks(bytes: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    for (name, canary) in CANARIES {
        for (offset, window) in bytes.windows(canary.len()).enumerate() {
            if window == *canary {
                let context = &bytes
                    [offset.saturating_sub(24)..(offset + canary.len() + 24).min(bytes.len())];
                found.push(format!(
                    "{name} at byte {offset}: {:?}",
                    String::from_utf8_lossy(context)
                ));
            }
        }
    }
    found
}

/// The session is still usable, and its byte stream holds canaries for the
/// exempt user and none for the others.
async fn check(scenario: &str, user: &str, wire: &mut Wire) {
    let response = wire.query("SELECT 1").run().await;
    assert_eq!(
        response.rows(),
        vec![vec![Some(b"1".to_vec())]],
        "{scenario}, {user}: session not usable: {response:?}"
    );
    let leaks = leaks(wire.transcript());
    if user == "admin" {
        assert!(
            !leaks.is_empty(),
            "{scenario}: the exempt user got no canaries, so the scenario can't detect a leak"
        );
    } else {
        assert!(
            leaks.is_empty(),
            "{scenario}, {user}: canary bytes reached the client:\n{}",
            leaks.join("\n")
        );
        // Not only errors: masked users got results.
        assert!(wire.data > 1, "{scenario}, {user}: no results");
    }
}

/// A test running a scenario for every user.
macro_rules! matrix {
    ($($test:ident => $scenario:ident,)*) => {$(
        #[tokio::test]
        async fn $test() {
            if !enabled() {
                return;
            }
            for user in USERS {
                let mut wire = connect(user).await;
                $scenario(&mut wire).await;
                check(stringify!($scenario), user, &mut wire).await;
            }
        }
    )*};
}

matrix! {
    test_simple_protocol => simple_protocol,
    test_extended_unnamed => extended_unnamed,
    test_extended_named => extended_named,
    test_binary_results => binary_results,
    test_mixed_result_formats => mixed_result_formats,
    test_execute_without_describe => execute_without_describe,
    test_pipelined => pipelined,
    test_pipelined_transaction_control => pipelined_transaction_control,
    test_portal_suspended => portal_suspended,
    test_split_prepare => split_prepare,
    test_unnamed_after_denied_parse => unnamed_after_denied_parse,
    test_sql_prepare_execute => sql_prepare_execute,
    test_cursors => cursors,
    test_multi_statement => multi_statement,
    test_copy_formats => copy_formats,
    test_copy_extended => copy_extended,
    test_errors_and_notices => errors_and_notices,
}

/// Statements reading masked columns in different ways, with `$1` = 1 where
/// they take a parameter.
const QUERIES: &[&str] = &[
    "SELECT * FROM masking_e2e.users ORDER BY id",
    "SELECT id, ssn, email, phone, secret_note, tax_id, card, balance FROM masking_e2e.users WHERE id = $1",
    "SELECT card, tax_id, balance FROM masking_e2e.users ORDER BY id",
    "SELECT upper(card), tax_id || '', balance + 0, lower(ssn) FROM masking_e2e.users",
    "SELECT * FROM masking_e2e.user_ssns ORDER BY id",
    "SELECT masking_e2e.get_ssn($1)",
    "WITH u AS (SELECT * FROM masking_e2e.users) SELECT u.* FROM u",
    "SELECT card FROM (SELECT card FROM masking_e2e.users) s UNION ALL SELECT card FROM masking_e2e.users",
    "SELECT u, (SELECT ssn FROM masking_e2e.users WHERE id = 2) FROM masking_e2e.users u",
];

fn params(sql: &str) -> &'static [Option<&'static str>] {
    if sql.contains("$1") {
        &[Some("1")]
    } else {
        &[]
    }
}

/// The statement with its parameter inlined, for the simple protocol.
fn inline(sql: &str) -> String {
    sql.replace("$1", "1")
}

/// Fields in the `RowDescription` of a response.
fn width(response: &Response) -> usize {
    let description = response
        .messages
        .iter()
        .find(|msg| msg.code == b'T')
        .unwrap_or_else(|| panic!("no RowDescription: {response:?}"));
    i16::from_be_bytes([description.body[0], description.body[1]]) as usize
}

async fn simple_protocol(wire: &mut Wire) {
    for sql in QUERIES {
        wire.query(&inline(sql)).run().await;
    }
    // DML returning masked columns.
    wire.query("BEGIN").run().await;
    wire.query(
        "UPDATE masking_e2e.users SET name = name WHERE id = 1 RETURNING ssn, card, balance",
    )
    .run()
    .await;
    wire.query("ROLLBACK").run().await;
}

async fn extended_unnamed(wire: &mut Wire) {
    for sql in QUERIES {
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[])
            .describe_portal("")
            .execute("", 0)
            .sync()
            .run()
            .await;
    }
}

async fn extended_named(wire: &mut Wire) {
    for (i, sql) in QUERIES.iter().enumerate() {
        let name = format!("s{i}");
        wire.parse(&name, sql, &[])
            .describe_statement(&name)
            .sync()
            .run()
            .await;
        // Executed twice, in text then binary, through named and unnamed portals.
        for (portal, format) in [("", TEXT), ("p", BINARY)] {
            wire.bind(portal, &name, params(sql), &[format])
                .describe_portal(portal)
                .execute(portal, 0)
                .sync()
                .run()
                .await;
        }
        wire.close_statement(&name).sync().run().await;
    }
}

async fn binary_results(wire: &mut Wire) {
    for sql in QUERIES {
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[BINARY])
            .describe_portal("")
            .execute("", 0)
            .sync()
            .run()
            .await;
    }
}

/// One format code per column, alternating, starting with each format.
async fn mixed_result_formats(wire: &mut Wire) {
    for sql in QUERIES {
        let described = wire
            .parse("", sql, &[])
            .describe_statement("")
            .sync()
            .run()
            .await;
        if !described.errors().is_empty() {
            continue;
        }
        let width = width(&described);
        for first in [TEXT, BINARY] {
            let formats: Vec<i16> = (0..width).map(|i| (first + i as i16) % 2).collect();
            wire.bind("", "", params(sql), &formats)
                .execute("", 0)
                .sync()
                .run()
                .await;
        }
    }
}

/// No `RowDescription` reaches PgDog, so masks are placed without one.
async fn execute_without_describe(wire: &mut Wire) {
    for (i, sql) in QUERIES.iter().enumerate() {
        for format in [TEXT, BINARY] {
            wire.parse("", sql, &[])
                .bind("", "", params(sql), &[format])
                .execute("", 0)
                .sync()
                .run()
                .await;
        }
        let name = format!("x{i}");
        wire.parse(&name, sql, &[])
            .bind("", &name, params(sql), &[BINARY])
            .execute("", 0)
            .close_statement(&name)
            .sync()
            .run()
            .await;
    }
}

/// Many statements in one request: results must be attributed to the
/// statement that produced them.
async fn pipelined(wire: &mut Wire) {
    // One Sync for all of them, statements without masks in between.
    for sql in QUERIES {
        wire.parse("", "SELECT 'clean' AS card", &[])
            .bind("", "", &[], &[])
            .execute("", 0)
            .parse("", sql, &[])
            .bind("", "", params(sql), &[BINARY])
            .execute("", 0);
    }
    wire.sync().run().await;

    // A Sync after each.
    for sql in QUERIES {
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[TEXT])
            .execute("", 0)
            .sync();
    }
    wire.run().await;

    // Named statements prepared and run in the same request, portals
    // executed out of order.
    for (i, sql) in QUERIES.iter().enumerate() {
        wire.parse(&format!("n{i}"), sql, &[]);
    }
    for (i, sql) in QUERIES.iter().enumerate() {
        wire.bind(&format!("p{i}"), &format!("n{i}"), params(sql), &[BINARY]);
    }
    for i in (0..QUERIES.len()).rev() {
        wire.execute(&format!("p{i}"), 0);
    }
    for i in 0..QUERIES.len() {
        wire.close_portal(&format!("p{i}"))
            .close_statement(&format!("n{i}"));
    }
    wire.sync().run().await;

    // Sent in pieces ending in Flush, before the results are read.
    for sql in QUERIES {
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[BINARY])
            .execute("", 0)
            .flush()
            .send()
            .await;
    }
    // After an error, the server skips the rest until Sync.
    for _ in QUERIES {
        if !wire.recv_until_any(b"CE").await.errors().is_empty() {
            break;
        }
    }
    wire.sync().run().await;
}

/// Statements PgDog answers or handles itself, pipelined with ones it
/// sends on.
async fn pipelined_transaction_control(wire: &mut Wire) {
    for control in [
        "BEGIN",
        "SET application_name = 'protocol'",
        "SELECT 1",
        "COMMIT",
        "ROLLBACK",
    ] {
        for sql in QUERIES {
            wire.parse("", control, &[])
                .bind("", "", &[], &[])
                .execute("", 0)
                .parse("", sql, &[])
                .bind("", "", params(sql), &[TEXT])
                .execute("", 0)
                .sync()
                .run()
                .await;
        }
        wire.query("ROLLBACK").run().await;
    }
    // In simple protocol transactions.
    for sql in QUERIES {
        wire.query("BEGIN").run().await;
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[BINARY])
            .execute("", 0)
            .sync()
            .run()
            .await;
        wire.query("COMMIT").run().await;
    }
}

/// `Execute` with a row limit, resumed in the same request and in later ones.
async fn portal_suspended(wire: &mut Wire) {
    for (i, sql) in QUERIES.iter().enumerate() {
        wire.query("BEGIN").run().await;
        let name = format!("l{i}");
        wire.parse(&name, sql, &[])
            .bind("cur", &name, params(sql), &[BINARY])
            .execute("cur", 1)
            .execute("cur", 1)
            .flush()
            .send()
            .await;
        // Each Execute ends with PortalSuspended or CommandComplete, unless
        // one fails.
        let mut ended = 0;
        let mut failed = false;
        while ended < 2 && !failed {
            match wire.recv().await.code {
                b's' | b'C' => ended += 1,
                b'E' => failed = true,
                _ => (),
            }
        }
        if !failed {
            wire.execute("cur", 0);
        }
        wire.sync().run().await;
        wire.query("ROLLBACK").run().await;
    }
}

/// Prepared in one request and run in the next, like lib/pq (Sync) and
/// drivers that end the first request with Flush.
async fn split_prepare(wire: &mut Wire) {
    for sql in QUERIES {
        wire.parse("", sql, &[])
            .describe_statement("")
            .sync()
            .run()
            .await;
        wire.bind("", "", params(sql), &[TEXT])
            .execute("", 0)
            .sync()
            .run()
            .await;

        wire.parse("", sql, &[])
            .describe_statement("")
            .flush()
            .send()
            .await;
        wire.recv_until_any(b"TnE").await;
        wire.bind("", "", params(sql), &[BINARY])
            .execute("", 0)
            .sync()
            .run()
            .await;
    }
}

/// A statement the plugin denies, prepared as the unnamed statement in a
/// request of its own, must not run when the next request binds the
/// unnamed statement.
async fn unnamed_after_denied_parse(wire: &mut Wire) {
    for sql in QUERIES {
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[])
            .execute("", 0)
            .sync()
            .run()
            .await;
        wire.parse("", STATS, &[]).sync().run().await;
        wire.bind("", "", params(sql), &[])
            .execute("", 0)
            .sync()
            .run()
            .await;
        wire.parse("", STATS, &[])
            .describe_statement("")
            .sync()
            .run()
            .await;
        wire.bind("", "", params(sql), &[TEXT])
            .describe_portal("")
            .execute("", 0)
            .sync()
            .run()
            .await;
    }
}

async fn sql_prepare_execute(wire: &mut Wire) {
    // Prepared and executed in the same query.
    wire.query(
        "PREPARE p AS SELECT id, ssn, email, phone FROM masking_e2e.users WHERE id = $1; \
         EXECUTE p(1); DEALLOCATE p",
    )
    .run()
    .await;
    wire.query("PREPARE p AS SELECT * FROM masking_e2e.users; EXECUTE p; DEALLOCATE p")
        .run()
        .await;
    wire.query(
        "PREPARE p AS SELECT card, tax_id, balance FROM masking_e2e.users; EXECUTE p; DEALLOCATE p",
    )
    .run()
    .await;

    // Executed later, with SQL and through the protocol. On a server
    // connection, in a session.
    wire.query("BEGIN").run().await;
    for sql in [
        "PREPARE q AS SELECT id, ssn, email, phone FROM masking_e2e.users WHERE id = $1",
        "PREPARE r AS SELECT card, tax_id, balance FROM masking_e2e.users",
        "PREPARE s AS SELECT * FROM masking_e2e.users",
    ] {
        wire.query(sql).run().await;
    }
    for sql in [
        "EXECUTE q(1)",
        "EXECUTE r",
        "EXECUTE s",
        "EXPLAIN ANALYZE EXECUTE s",
    ] {
        wire.query(sql).run().await;
    }
    for (name, params) in [("q", &[Some("1")][..]), ("r", &[]), ("s", &[])] {
        wire.bind("", name, params, &[BINARY])
            .execute("", 0)
            .sync()
            .run()
            .await;
        wire.parse(
            "",
            &format!(
                "EXECUTE {name}{}",
                if params.is_empty() { "" } else { "(1)" }
            ),
            &[],
        )
        .bind("", "", &[], &[TEXT])
        .execute("", 0)
        .sync()
        .run()
        .await;
    }
    wire.query("ROLLBACK").run().await;
    wire.query("DEALLOCATE ALL").run().await;
}

async fn cursors(wire: &mut Wire) {
    for select in QUERIES.iter().map(|sql| inline(sql)) {
        wire.query("BEGIN").run().await;
        wire.query(&format!("DECLARE c SCROLL CURSOR FOR {select}"))
            .run()
            .await;
        wire.query("FETCH 1 FROM c").run().await;
        // The cursor's portal, executed through the protocol.
        wire.describe_portal("c").execute("c", 1).sync().run().await;
        wire.query("MOVE BACKWARD ALL IN c; FETCH ALL FROM c")
            .run()
            .await;
        wire.query("CLOSE c").run().await;
        wire.query(&format!("DECLARE b BINARY CURSOR FOR {select}"))
            .run()
            .await;
        wire.query("FETCH ALL FROM b").run().await;
        // Declared through the protocol.
        wire.parse("", &format!("DECLARE e SCROLL CURSOR FOR {select}"), &[])
            .bind("", "", &[], &[])
            .execute("", 0)
            .execute("e", 0)
            .sync()
            .run()
            .await;
        wire.parse("", "FETCH ABSOLUTE 1 FROM e", &[])
            .bind("", "", &[], &[BINARY])
            .execute("", 0)
            .sync()
            .run()
            .await;
        wire.query("ROLLBACK").run().await;

        // Held past the transaction.
        wire.query(&format!("DECLARE h CURSOR WITH HOLD FOR {select}"))
            .run()
            .await;
        wire.query("FETCH ALL FROM h").run().await;
        wire.query("CLOSE h").run().await;
    }
    // Something for every user to read.
    wire.query("BEGIN; DECLARE ok CURSOR FOR SELECT id, ssn FROM masking_e2e.users; FETCH ALL FROM ok; ROLLBACK")
        .run()
        .await;
}

async fn multi_statement(wire: &mut Wire) {
    let all: Vec<String> = QUERIES.iter().map(|sql| inline(sql)).collect();
    wire.query(&all.join("; ")).run().await;
    for sql in &all {
        for query in [
            format!("SELECT 1; {sql}; SELECT 2"),
            format!("{sql}; {sql}"),
            format!("; {sql};;"),
            format!("SELECT ssn FROM masking_e2e.users; {sql}; SELECT 1 / 0; {sql}"),
            format!("{sql}; COPY (SELECT id, ssn, email FROM masking_e2e.users) TO STDOUT; {sql}"),
            format!("SHOW search_path; {sql}"),
            format!("BEGIN; {sql}; COMMIT"),
        ] {
            wire.query(&query).run().await;
        }
    }
}

async fn copy_formats(wire: &mut Wire) {
    for options in [
        "",
        "(FORMAT text)",
        "(FORMAT csv)",
        "(FORMAT csv, HEADER, FORCE_QUOTE *)",
        "(FORMAT binary)",
        "WITH CSV HEADER",
        "WITH BINARY",
    ] {
        for source in [
            "masking_e2e.users (id, ssn, email, phone, secret_note)",
            "(SELECT id, ssn, email, phone, secret_note FROM masking_e2e.users)",
            "masking_e2e.users",
            "masking_e2e.users (id, card, tax_id, balance)",
            "(SELECT card, tax_id, balance FROM masking_e2e.users)",
            "(SELECT * FROM masking_e2e.user_ssns)",
            "(SELECT masking_e2e.get_ssn(id) FROM masking_e2e.users)",
        ] {
            wire.query(&format!("COPY {source} TO STDOUT {options}"))
                .run()
                .await;
        }
    }
}

/// COPY TO STDOUT through the extended protocol.
async fn copy_extended(wire: &mut Wire) {
    for sql in [
        "COPY masking_e2e.users (id, ssn, email, phone, secret_note) TO STDOUT (FORMAT binary)",
        "COPY (SELECT id, ssn, email FROM masking_e2e.users) TO STDOUT (FORMAT csv)",
        "COPY masking_e2e.users TO STDOUT",
        "COPY (SELECT card, tax_id, balance FROM masking_e2e.users) TO STDOUT (FORMAT binary)",
    ] {
        wire.parse("", sql, &[])
            .bind("", "", &[], &[])
            .execute("", 0)
            .sync()
            .run()
            .await;
    }
}

async fn errors_and_notices(wire: &mut Wire) {
    for sql in [
        "SELECT card::int FROM masking_e2e.users",
        "SELECT ssn::int FROM masking_e2e.users",
        "SELECT tax_id::int FROM masking_e2e.users WHERE id = $1",
        "SELECT 1 / (id - id), card, ssn FROM masking_e2e.users",
        "SELECT id FROM masking_e2e.err_sb",
        "SELECT to_date(card, 'YYYY') FROM masking_e2e.users",
        "SELECT jsonb_build_object('k', ssn)::text::int FROM masking_e2e.users",
    ] {
        wire.query(&inline(sql)).run().await;
        wire.parse("", sql, &[])
            .bind("", "", params(sql), &[BINARY])
            .execute("", 0)
            .sync()
            .run()
            .await;
    }
    for sql in [
        "DO $$ BEGIN RAISE NOTICE '%', (SELECT string_agg(ssn || card, ',') FROM masking_e2e.users); END $$",
        "DO $$ BEGIN RAISE EXCEPTION '%', (SELECT string_agg(ssn || card, ',') FROM masking_e2e.users); END $$",
        "UPDATE masking_e2e.users SET name = 'forbidden' WHERE id = 1",
    ] {
        wire.query(sql).run().await;
    }
    // Results for every user.
    wire.query("SELECT ssn, card FROM masking_e2e.users")
        .run()
        .await;
}

/// tokio-postgres: binary results, and requests pipelined by running them
/// concurrently on one connection. Checks the decoded values.
#[tokio::test]
async fn test_tokio_postgres_pipelined_binary() {
    if !enabled() {
        return;
    }
    for user in USERS {
        let (client, connection) = tokio_postgres::connect(
            &format!("host=127.0.0.1 port=6432 user={user} password=pgdog dbname=pgdog"),
            NoTls,
        )
        .await
        .expect("connect to PgDog");
        tokio::spawn(connection);

        let statement = client
            .prepare("SELECT ssn, email, phone, secret_note, tax_id, card, balance FROM masking_e2e.users WHERE id = $1")
            .await
            .unwrap();
        let queries = (0..20).map(|i| {
            let client = &client;
            let statement = &statement;
            async move {
                let id = 1 + i % 2_i64;
                if i % 3 == 0 {
                    // Unnamed statements, interleaved with the named one.
                    client
                        .query("SELECT ssn, email, phone, secret_note, tax_id, card, balance FROM masking_e2e.users WHERE id = $1", &[&id])
                        .await
                } else {
                    client.query(statement, &[&id]).await
                }
            }
        });
        let results = try_join_all(queries).await.unwrap();

        let mut leaked = Vec::new();
        for row in results.iter().flatten() {
            for i in 0..6 {
                if let Some(value) = row.get::<_, Option<String>>(i) {
                    leaked.extend(leaks(value.as_bytes()));
                }
            }
            if let Some(balance) = row.get::<_, Option<i64>>(6)
                && matches!(balance, 1000 | 2000)
            {
                leaked.push(format!("balance {balance}"));
            }
        }
        assert_eq!(results.iter().flatten().count(), 20, "{user}");
        if user == "admin" {
            assert!(!leaked.is_empty(), "admin must see raw values");
        } else {
            assert!(leaked.is_empty(), "{user}: {leaked:?}");
        }
    }
}

/// Reads raw values of masked columns from the statistics; denied for masked
/// users.
const STATS: &str = "SELECT attname, most_common_vals::text, histogram_bounds::text \
                     FROM pg_stats WHERE schemaname = 'masking_e2e'";

/// The unnamed statement after a Parse the plugin denied: binding it must not
/// run the denied statement. PgDog replays the client's last unnamed Parse
/// before a Bind that comes without one.
#[tokio::test]
async fn test_denied_unnamed_parse_not_replayed() {
    if !enabled() {
        return;
    }
    for user in ["masked", "analyst"] {
        let mut wire = connect(user).await;
        // An unnamed statement the plugin allowed.
        let allowed = wire
            .parse("", "SELECT 1", &[])
            .bind("", "", &[], &[])
            .execute("", 0)
            .sync()
            .run()
            .await;
        assert_eq!(allowed.rows(), vec![vec![Some(b"1".to_vec())]]);
        // Replaced by one it denies, in a request of its own.
        let denied = wire.parse("", STATS, &[]).sync().run().await;
        assert_eq!(denied.errors(), ["42501"], "{user}");
        wire.bind("", "", &[], &[])
            .execute("", 0)
            .sync()
            .run()
            .await;
        wire.describe_statement("")
            .bind("", "", &[], &[])
            .execute("", 0)
            .sync()
            .run()
            .await;
        let leaks = leaks(wire.transcript());
        assert!(leaks.is_empty(), "{user}: {}", leaks.join("\n"));
    }
}

/// Binding the unnamed statement again in a later request runs the statement
/// this client prepared, not whatever unnamed statement the pooled server
/// connection holds. `pooled` has one server connection, shared by both
/// clients.
#[tokio::test]
async fn test_unnamed_statement_rebound_later() {
    if !enabled() {
        return;
    }
    let mut first = connect("pooled").await;
    let mut second = connect("pooled").await;
    // Prepared, described and executed: PgDog no longer replays its Parse.
    first
        .parse(
            "",
            "SELECT id::text FROM masking_e2e.users ORDER BY id",
            &[],
        )
        .describe_statement("")
        .sync()
        .run()
        .await;
    let rows = first
        .bind("", "", &[], &[])
        .execute("", 0)
        .sync()
        .run()
        .await
        .rows();
    assert_eq!(
        rows,
        vec![vec![Some(b"1".to_vec())], vec![Some(b"2".to_vec())]]
    );

    // Another client leaves its unnamed statement on the server connection.
    let other = second
        .parse("", "SELECT card FROM masking_e2e.users ORDER BY id", &[])
        .bind("", "", &[], &[])
        .execute("", 0)
        .sync()
        .run()
        .await;
    assert_eq!(other.rows().len(), 2);

    // Bound again: still the first client's statement, or refused.
    let again = first
        .bind("", "", &[], &[])
        .execute("", 0)
        .sync()
        .run()
        .await;
    let leaks = leaks(first.transcript());
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
    if again.errors().is_empty() {
        assert_eq!(again.rows(), rows, "ran another statement: {again:?}");
    }
}
