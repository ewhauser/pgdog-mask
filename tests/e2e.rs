//! End-to-end tests through PgDog with the plugin loaded.
//!
//! Run with `bash integration/run.sh`; skipped unless `PGDOG_MASK_E2E=1`.
use futures_util::{StreamExt as _, pin_mut};
use tokio_postgres::error::{DbError, SqlState};
use tokio_postgres::types::Type;
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

/// The message PgDog gives errors of statements whose errors are redacted.
const REDACTED: &str = "error message removed: the statement reads values this user can't see";

/// Raw values of `card`, by `id`.
const CARDS: [&str; 2] = ["4111-1111-1111-1111", "5500-0000-0000-0004"];

fn enabled() -> bool {
    std::env::var("PGDOG_MASK_E2E").is_ok_and(|v| v == "1")
}

async fn connect(user: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port=6432 user={user} password=pgdog dbname=pgdog"),
        NoTls,
    )
    .await
    .expect("connect to PgDog");
    tokio::spawn(connection);
    client
}

async fn simple(client: &Client, sql: &str) -> Vec<Vec<Option<String>>> {
    client
        .simple_query(sql)
        .await
        .expect(sql)
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(
                (0..row.len())
                    .map(|i| row.get(i).map(str::to_owned))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// The database error a statement fails with.
async fn simple_err(client: &Client, sql: &str) -> DbError {
    let err = client
        .simple_query(sql)
        .await
        .expect_err(&format!("{sql} must fail"));
    err.as_db_error()
        .unwrap_or_else(|| panic!("{sql}: not a database error: {err:?}"))
        .clone()
}

/// The statement is blocked by the plugin.
async fn assert_blocked(client: &Client, sql: &str) {
    let err = simple_err(client, sql).await;
    assert_eq!(
        err.code(),
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "{sql}: {err:?}"
    );
}

/// The error was redacted: only its SQLSTATE and location are left.
fn assert_redacted(err: &DbError, code: &SqlState) {
    assert_eq!(err.code(), code, "{err:?}");
    assert_eq!(err.message(), REDACTED, "{err:?}");
    assert_eq!(err.detail(), None, "{err:?}");
}

/// An ff1 token for a card: digits in the card's format, not the card.
fn assert_card_token(card: &str, raw: &str) {
    assert_ne!(card, raw);
    assert_eq!(card.len(), 19, "{card}");
    assert!(
        card.split('-')
            .all(|group| group.len() == 4 && group.chars().all(|c| c.is_ascii_digit())),
        "{card}"
    );
}

#[tokio::test]
async fn test_masked_user() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;

    // Simple protocol.
    let rows = simple(
        &client,
        "SELECT ssn, email FROM masking_e2e.users ORDER BY id",
    )
    .await;
    assert_eq!(
        rows,
        vec![
            vec![Some("XXX-XX-1111".into()), Some("****@example.com".into())],
            vec![Some("XXX-XX-2222".into()), Some("****@example.com".into())],
        ]
    );

    // Extended protocol with a named prepared statement, executed twice.
    let statement = client
        .prepare("SELECT * FROM masking_e2e.users WHERE id = $1")
        .await
        .unwrap();
    for _ in 0..2 {
        let row = client.query_one(&statement, &[&1_i64]).await.unwrap();
        let ssn: String = row.get("ssn");
        assert_eq!(ssn, "XXX-XX-1111");
    }

    // Masked predicates don't match raw values.
    let rows = simple(
        &client,
        "SELECT id FROM masking_e2e.users WHERE ssn = 'CANARYSSN-1111'",
    )
    .await;
    assert!(rows.is_empty());

    // search_path set by the client is used to resolve unqualified names.
    client
        .batch_execute("SET search_path TO masking_e2e")
        .await
        .unwrap();
    let rows = simple(&client, "SELECT ssn FROM users WHERE id = 2").await;
    assert_eq!(rows, vec![vec![Some("XXX-XX-2222".into())]]);

    // COPY of columns with SQL masks.
    let stream = client
        .copy_out("COPY masking_e2e.users (id, ssn, email) TO STDOUT")
        .await
        .unwrap();
    pin_mut!(stream);
    let mut copied = String::new();
    while let Some(chunk) = stream.next().await {
        copied.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
    }
    assert!(copied.contains("XXX-XX-1111"), "{copied}");
    assert!(
        !copied.contains("CANARY") && !copied.contains("canary"),
        "{copied}"
    );
    // COPY would send the proxy-masked columns unmasked.
    assert_blocked(&client, "COPY masking_e2e.users TO STDOUT").await;

    // Blocked statements.
    let err = client
        .simple_query("SELECT * FROM pg_stats WHERE schemaname = 'masking_e2e'")
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "{err:?}"
    );

    // The session is still usable.
    assert_eq!(
        simple(&client, "SELECT 1").await,
        vec![vec![Some("1".into())]]
    );
}

#[tokio::test]
async fn test_exempt_user() {
    if !enabled() {
        return;
    }
    let client = connect("admin").await;
    let rows = simple(
        &client,
        "SELECT ssn, phone, secret_note FROM masking_e2e.users WHERE id = 1",
    )
    .await;
    assert_eq!(
        rows,
        vec![vec![
            Some("CANARYSSN-1111".into()),
            Some("CANARYPHONE-11".into()),
            Some("CANARYNOTE-1".into())
        ]]
    );

    // Errors keep their DETAIL for exempt users.
    let err = client
        .simple_query("UPDATE masking_e2e.users SET name = 'forbidden' WHERE id = 1")
        .await
        .unwrap_err();
    let detail = err.as_db_error().and_then(|e| e.detail()).unwrap_or("");
    assert!(detail.contains("CANARYSSN-1111"), "{err:?}");
}

#[tokio::test]
async fn test_views_functions_and_tags() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;

    // Views over masked columns are inlined with masks applied.
    let rows = simple(&client, "SELECT ssn FROM masking_e2e.user_ssns ORDER BY id").await;
    assert_eq!(
        rows,
        vec![
            vec![Some("XXX-XX-1111".into())],
            vec![Some("XXX-XX-2222".into())]
        ]
    );

    // SQL functions that read masked columns are inlined.
    let rows = simple(&client, "SELECT masking_e2e.get_ssn(2)").await;
    assert_eq!(rows, vec![vec![Some("XXX-XX-2222".into())]]);
    let row = client
        .query_one("SELECT masking_e2e.get_ssn($1) AS ssn", &[&1_i64])
        .await
        .unwrap();
    let ssn: String = row.get("ssn");
    assert_eq!(ssn, "XXX-XX-1111");

    // A tag from a column comment, and a classifier match.
    let rows = simple(
        &client,
        "SELECT phone, secret_note FROM masking_e2e.users WHERE id = 1",
    )
    .await;
    assert_eq!(rows, vec![vec![Some("************11".into()), None]]);
}

#[tokio::test]
async fn test_error_detail_scrubbed() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;

    // A CHECK violation's DETAIL lists the whole row, including masked columns.
    let err = client
        .simple_query("UPDATE masking_e2e.users SET name = 'forbidden' WHERE id = 1")
        .await
        .unwrap_err();
    let db = err.as_db_error().expect("database error");
    assert_eq!(db.code(), &SqlState::CHECK_VIOLATION, "{err:?}");
    assert_eq!(db.detail(), None, "{err:?}");
    assert!(!format!("{err:?}").contains("CANARY"), "{err:?}");

    // Extended protocol, executed twice: Bind isn't checked again, errors are
    // redacted for the whole session.
    let statement = client
        .prepare("UPDATE masking_e2e.users SET name = $1 WHERE id = $2")
        .await
        .unwrap();
    for _ in 0..2 {
        let err = client
            .execute(&statement, &[&"forbidden", &2_i64])
            .await
            .unwrap_err();
        let db = err.as_db_error().expect("database error");
        assert_eq!(db.detail(), None, "{err:?}");
        assert!(!format!("{err:?}").contains("CANARY"), "{err:?}");
    }

    // The session is still usable.
    assert_eq!(
        simple(&client, "SELECT 1").await,
        vec![vec![Some("1".into())]]
    );
}

#[tokio::test]
async fn test_raw_search() {
    if !enabled() {
        return;
    }
    let client = connect("support").await;
    let row = client
        .query_one(
            "SELECT id, ssn FROM masking_e2e.users WHERE ssn = $1",
            &[&"CANARYSSN-2222"],
        )
        .await
        .unwrap();
    let id: i64 = row.get(0);
    let ssn: String = row.get(1);
    assert_eq!((id, ssn.as_str()), (2, "****"));
}

#[tokio::test]
async fn test_proxy_masks() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;

    // Simple protocol: text results.
    let rows = simple(
        &client,
        "SELECT tax_id, card, balance FROM masking_e2e.users ORDER BY id",
    )
    .await;
    assert_eq!(rows.len(), 2);
    let tax_ids: Vec<_> = rows.iter().map(|row| row[0].clone().unwrap()).collect();
    for (row, raw_card) in rows.iter().zip(CARDS) {
        let tax_id = row[0].as_deref().unwrap();
        assert_eq!(tax_id.len(), 16, "{row:?}");
        assert!(tax_id.chars().all(|c| c.is_ascii_hexdigit()), "{row:?}");
        assert_card_token(row[1].as_deref().unwrap(), raw_card);
    }
    assert_ne!(tax_ids[0], tax_ids[1]);
    assert_eq!(rows[0][2].as_deref(), Some("1001"));
    assert_eq!(rows[1][2].as_deref(), Some("2001"));

    // Extended protocol: binary results, same masked values.
    let statement = client
        .prepare("SELECT tax_id, card, balance FROM masking_e2e.users WHERE id = $1")
        .await
        .unwrap();
    for _ in 0..2 {
        let row = client.query_one(&statement, &[&1_i64]).await.unwrap();
        let tax_id: String = row.get(0);
        let balance: i64 = row.get(2);
        assert_eq!(tax_id, tax_ids[0], "deterministic in both formats");
        assert_eq!(row.get::<_, String>(1), rows[0][1].clone().unwrap());
        assert_eq!(balance, 1001);
    }

    // Stars are covered too.
    let row = client
        .query_one("SELECT * FROM masking_e2e.users WHERE id = 2", &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>("balance"), 2001);
    assert_eq!(row.get::<_, String>("tax_id"), tax_ids[1]);

    // Conditions, joins and ordering use the real values; only results are
    // masked (I-2).
    let tokens: Vec<String> = rows.iter().map(|row| row[1].clone().unwrap()).collect();
    assert_eq!(
        simple(
            &client,
            "SELECT id, card FROM masking_e2e.users WHERE tax_id = 'TAX-1111'"
        )
        .await,
        vec![vec![Some("1".into()), Some(tokens[0].clone())]]
    );
    // Sorted by the real cards, not by their tokens.
    assert_eq!(
        simple(&client, "SELECT card FROM masking_e2e.users ORDER BY card").await,
        vec![vec![Some(tokens[0].clone())], vec![Some(tokens[1].clone())]]
    );
    // Computed from a proxy-masked column: NULL.
    assert_eq!(
        simple(
            &client,
            "SELECT upper(card) FROM masking_e2e.users WHERE id = 1"
        )
        .await,
        vec![vec![None]]
    );
    assert_eq!(
        simple(
            &client,
            "SELECT count(*) FROM masking_e2e.users WHERE card LIKE '4111%'"
        )
        .await,
        vec![vec![Some("1".into())]]
    );

    // Exempt users see raw values.
    let admin = connect("admin").await;
    let rows = simple(
        &admin,
        "SELECT tax_id, card, balance FROM masking_e2e.users WHERE id = 1",
    )
    .await;
    assert_eq!(
        rows,
        vec![vec![
            Some("TAX-1111".into()),
            Some("4111-1111-1111-1111".into()),
            Some("1000".into())
        ]]
    );
}

/// The card token of user 1, from a query of its own.
async fn card_token(client: &Client) -> String {
    let rows = simple(client, "SELECT card FROM masking_e2e.users WHERE id = 1").await;
    let token = rows[0][0].clone().expect("a card");
    assert_card_token(&token, CARDS[0]);
    token
}

/// Each statement of a query is masked in its own result (I-4).
#[tokio::test]
async fn test_proxy_multi_statement() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;
    let token = card_token(&client).await;

    assert_eq!(
        simple(
            &client,
            "SELECT 1; SELECT card FROM masking_e2e.users WHERE id = 1"
        )
        .await,
        vec![vec![Some("1".into())], vec![Some(token.clone())]]
    );
    // In a transaction. (PgDog answers a query that starts with BEGIN itself,
    // so BEGIN goes on its own.)
    client.batch_execute("BEGIN").await.unwrap();
    assert_eq!(
        simple(
            &client,
            "SELECT card FROM masking_e2e.users WHERE id = 1; COMMIT"
        )
        .await,
        vec![vec![Some(token.clone())]]
    );

    // In transaction mode, before the client holds a server connection:
    // PgDog answers the SET itself and sends only the SELECT.
    let fresh = connect("masked").await;
    assert_eq!(
        simple(
            &fresh,
            "SET application_name = 'x'; SELECT card FROM masking_e2e.users WHERE id = 1"
        )
        .await,
        vec![vec![Some(token.clone())]]
    );

    // PgDog doesn't follow a search_path set_config sets while its query
    // parser is off, as it is here: the plugin would resolve names with the
    // old one. SET is followed, and the plugin resolves names with it.
    let fresh = connect("masked").await;
    assert_blocked(
        &fresh,
        "SELECT set_config('search_path', 'masking_e2e', false)",
    )
    .await;
    fresh
        .batch_execute("SET search_path TO masking_e2e")
        .await
        .unwrap();
    assert_eq!(
        simple(&fresh, "SELECT card FROM users WHERE id = 1").await,
        vec![vec![Some(token)]]
    );
}

/// Errors of statements computing on proxy-masked columns keep only their
/// SQLSTATE and location, through both protocols (I-5).
#[tokio::test]
async fn test_proxy_redacted_errors() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;

    // `invalid input syntax for type integer: "4111-1111-1111-1111"`.
    let sql = "SELECT card::int FROM masking_e2e.users";
    let err = simple_err(&client, sql).await;
    assert_redacted(&err, &SqlState::INVALID_TEXT_REPRESENTATION);
    assert!(!format!("{err:?}").contains("4111"), "{err:?}");
    let err = client.query(sql, &[]).await.unwrap_err();
    let err = err.as_db_error().expect("database error");
    assert_redacted(err, &SqlState::INVALID_TEXT_REPRESENTATION);
    assert!(!format!("{err:?}").contains("4111"), "{err:?}");

    // Parse, Bind and Execute: the bound value is quoted by the error.
    let statement = client
        .prepare_typed(
            "SELECT id FROM masking_e2e.users WHERE tax_id = $1 AND id = $2::bigint",
            &[Type::TEXT, Type::TEXT],
        )
        .await
        .unwrap();
    for _ in 0..2 {
        let err = client
            .query(&statement, &[&"TAX-1111", &"1x"])
            .await
            .unwrap_err();
        let err = err.as_db_error().expect("database error");
        assert_redacted(err, &SqlState::INVALID_TEXT_REPRESENTATION);
        assert!(!format!("{err:?}").contains("1x"), "{err:?}");
    }

    // A cursor's portal gets no masks or redaction: any use of a
    // proxy-masked column is blocked.
    assert_blocked(
        &client,
        "DECLARE c CURSOR FOR SELECT id FROM masking_e2e.users WHERE card::int > 0",
    )
    .await;

    // FETCH runs a statement PgDog didn't see with it: its errors are
    // redacted.
    let fetch = |client: Client| async move {
        client
            .batch_execute(
                "BEGIN; DECLARE c CURSOR FOR SELECT 1 / (id - id) FROM masking_e2e.users",
            )
            .await
            .unwrap();
        let err = simple_err(&client, "FETCH ALL FROM c").await;
        client.batch_execute("ROLLBACK").await.unwrap();
        (client, err)
    };
    let (client, err) = fetch(client).await;
    assert_redacted(&err, &SqlState::DIVISION_BY_ZERO);
    let (_, err) = fetch(connect("admin").await).await;
    assert_eq!(err.message(), "division by zero", "{err:?}");

    // The session is still usable.
    assert_eq!(
        simple(&client, "SELECT 1").await,
        vec![vec![Some("1".into())]]
    );
}

/// A statement's plan, without output lists: star expansion is
/// plan-equivalent, but changes them.
async fn plan(client: &Client, sql: &str) -> Vec<String> {
    simple(client, &format!("EXPLAIN (COSTS OFF) {sql}"))
        .await
        .into_iter()
        .filter_map(|row| row[0].clone())
        .filter(|line| !line.trim_start().starts_with("Output:"))
        .collect()
}

/// Statements run unchanged, so they're planned as for an exempt user (I-1).
#[tokio::test]
async fn test_proxy_plan_identity() {
    if !enabled() {
        return;
    }
    let masked = connect("masked").await;
    let admin = connect("admin").await;
    for sql in [
        "SELECT id FROM masking_e2e.users WHERE tax_id = 'TAX-1111'",
        "SELECT card FROM masking_e2e.users ORDER BY card",
        "SELECT * FROM masking_e2e.users WHERE id = 1",
    ] {
        let expected = plan(&admin, sql).await;
        assert!(!expected.is_empty());
        assert_eq!(plan(&masked, sql).await, expected, "{sql}");
    }
}

/// Statements that would move proxy-masked values where PgDog can't mask
/// them are blocked.
#[tokio::test]
async fn test_proxy_sinks_blocked() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;
    for sql in [
        "INSERT INTO masking_e2e.users (id, name, card) SELECT id + 100, name, card FROM masking_e2e.users",
        "SELECT set_config('masking.leak', card, false) FROM masking_e2e.users",
    ] {
        assert_blocked(&client, sql).await;
    }
    let Err(err) = client
        .copy_out("COPY (SELECT card FROM masking_e2e.users) TO STDOUT")
        .await
    else {
        panic!("COPY of a proxy-masked column must be blocked");
    };
    assert_eq!(
        err.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "{err:?}"
    );
}

/// Statements PgDog runs without attaching what the plugin decided are
/// blocked unless the plugin saw them in the same query (I-8).
#[tokio::test]
async fn test_proxy_unattributed_statements() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;
    // A protocol Bind of `p` would get no plan.
    assert_blocked(
        &client,
        "PREPARE p AS SELECT id FROM masking_e2e.users WHERE card::int > 0",
    )
    .await;
    // Possibly another client's statement, prepared by PgDog.
    assert_blocked(&client, "EXECUTE __pgdog_1").await;
    // Prepared in the same query: checked with it.
    assert_eq!(
        simple(
            &client,
            "PREPARE p AS SELECT id FROM masking_e2e.users WHERE id = $1; EXECUTE p(1); DEALLOCATE p"
        )
        .await,
        vec![vec![Some("1".into())]]
    );
}

/// Tags that can't be resolved to one policy fail closed: the column reads
/// as NULL for masked users.
#[tokio::test]
async fn test_unresolved_tags_fail_closed() {
    if !enabled() {
        return;
    }
    let client = connect("masked").await;
    let rows = simple(
        &client,
        "SELECT nickname, codename FROM masking_e2e.users WHERE id = 1",
    )
    .await;
    assert_eq!(rows, vec![vec![None, None]]);

    let admin = connect("admin").await;
    let rows = simple(
        &admin,
        "SELECT nickname, codename FROM masking_e2e.users WHERE id = 1",
    )
    .await;
    assert_eq!(rows, vec![vec![Some("ally".into()), Some("red".into())]]);
}

/// A tag set with COMMENT ON through PgDog applies without a restart:
/// PgDog reloads the schema after the DDL and sends the plugin the new catalog.
#[tokio::test]
async fn test_tags_apply_live() {
    if !enabled() {
        return;
    }
    let admin = connect("admin").await;
    let masked = connect("masked").await;
    let alias =
        || async { simple(&masked, "SELECT alias FROM masking_e2e.users WHERE id = 1").await };
    assert_eq!(alias().await, vec![vec![Some("al".into())]]);

    admin
        .batch_execute("COMMENT ON COLUMN masking_e2e.users.alias IS 'pgdog:tag=secret'")
        .await
        .unwrap();
    // The schema reloads in the background.
    let mut masked_now = false;
    for _ in 0..50 {
        if alias().await == vec![vec![None]] {
            masked_now = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(masked_now, "the tag didn't apply");

    // Removing the tag unmasks the column, the same way.
    admin
        .batch_execute("COMMENT ON COLUMN masking_e2e.users.alias IS NULL")
        .await
        .unwrap();
    let mut unmasked = false;
    for _ in 0..50 {
        if alias().await == vec![vec![Some("al".into())]] {
            unmasked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(unmasked, "the tag's removal didn't apply");
}
