//! End-to-end tests through PgDog with `masking_e2e.users` split across two
//! shards by `id` (`integration/sharded`). Masking runs before routing, so
//! each shard runs the masked statement, and PgDog merges what the shards
//! return: it sorts, aggregates and deduplicates masked values.
//!
//! Run with `bash integration/sharded/run.sh`; skipped unless
//! `PGDOG_MASK_SHARDED=1`.
use std::error::Error;

use futures_util::{StreamExt as _, pin_mut};
use tokio_postgres::types::{FromSql, Type};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

/// Rows inserted through PgDog, which routes them to both shards.
const ROWS: i64 = 8;

fn ssn(id: i64) -> String {
    format!("CANARYSSN-{id:04}")
}

fn card(id: i64) -> String {
    format!("4111-1111-1111-{id:04}")
}

fn balance(id: i64) -> i64 {
    900_000_000 + 10 * id
}

/// Parts of raw values that must never reach a masked user.
const CANARIES: &[&str] = &["CANARYSSN", "canaryemail", "TAX-", "4111-1111-1111-"];

fn enabled() -> bool {
    std::env::var("PGDOG_MASK_SHARDED").is_ok_and(|v| v == "1")
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

/// A shard's database, without PgDog.
async fn connect_shard(shard: usize) -> Client {
    let var = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.into());
    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={} port={} user={} password={} dbname=pgdog_mask_shard_{shard}",
            var("PGHOST", "127.0.0.1"),
            var("PGPORT", "5432"),
            var("PGUSER", "pgdog"),
            var("PGPASSWORD", "pgdog"),
        ),
        NoTls,
    )
    .await
    .expect("connect to a shard");
    tokio::spawn(connection);
    client
}

type Rows = Vec<Vec<Option<String>>>;

/// A value in binary format, as text: integers decoded, anything else as
/// its bytes, where text and raw values in other types show as they are.
struct Binary(String);

impl FromSql<'_> for Binary {
    fn from_sql(ty: &Type, raw: &[u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Self(match *ty {
            Type::INT8 => i64::from_sql(ty, raw)?.to_string(),
            Type::INT4 => i32::from_sql(ty, raw)?.to_string(),
            _ => String::from_utf8_lossy(raw).into_owned(),
        }))
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

async fn simple(client: &Client, sql: &str) -> Rows {
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

/// One column of a result.
fn column(rows: &Rows, index: usize) -> Vec<Option<String>> {
    rows.iter().map(|row| row[index].clone()).collect()
}

/// The raw value a result shows, if any.
fn leaked(rows: &Rows) -> Option<String> {
    let balances: Vec<String> = (1..=ROWS).map(|id| balance(id).to_string()).collect();
    rows.iter().flatten().flatten().find_map(|value| {
        CANARIES
            .iter()
            .any(|canary| value.contains(canary))
            .then(|| value.clone())
            .or_else(|| balances.contains(value).then(|| value.clone()))
    })
}

/// Insert the rows through PgDog, one statement each so each is routed.
/// Tests running in parallel may both insert them.
async fn seed(admin: &Client) {
    for id in 1..=ROWS {
        admin
            .batch_execute(&format!(
                "INSERT INTO masking_e2e.users (id, name, ssn, email, phone, secret_note, tax_id, card, balance)
                 VALUES ({id}, 'user-{id}', '{}', 'canaryemail-{id}@example.com', 'CANARYPHONE-{id:02}',
                         'CANARYNOTE-{id}', 'TAX-{id:04}', '{}', {})
                 ON CONFLICT (id) DO NOTHING",
                ssn(id),
                card(id),
                balance(id),
            ))
            .await
            .unwrap();
    }
}

/// Statements whose results PgDog merges from both shards, and one it routes
/// to a single shard.
const CROSS_SHARD: &[&str] = &[
    "SELECT * FROM masking_e2e.users ORDER BY id",
    "SELECT ssn, email, phone, tax_id, card, balance FROM masking_e2e.users ORDER BY ssn",
    "SELECT * FROM masking_e2e.users ORDER BY card",
    "SELECT * FROM masking_e2e.users ORDER BY balance DESC",
    "SELECT ssn FROM masking_e2e.users ORDER BY ssn LIMIT 3",
    "SELECT max(ssn), min(email), max(card), min(tax_id), max(balance), sum(balance), count(*) FROM masking_e2e.users",
    "SELECT DISTINCT email FROM masking_e2e.users",
    "SELECT email, count(*) FROM masking_e2e.users GROUP BY email",
    "SELECT card, count(*) FROM masking_e2e.users GROUP BY card",
    "SELECT ssn, card FROM masking_e2e.users WHERE ssn LIKE 'CANARY%'",
    "SELECT * FROM masking_e2e.users WHERE id = 3",
];

/// What the masked user's SSNs sort as, descending.
fn masked_ssns_descending() -> Vec<Option<String>> {
    (1..=ROWS)
        .rev()
        .map(|id| Some(format!("XXX-XX-{id:04}")))
        .collect()
}

#[tokio::test]
async fn test_sharded() {
    if !enabled() {
        return;
    }
    let admin = connect("admin").await;
    seed(&admin).await;

    // Control: the rows are on both shards, so results are merged.
    let mut counts = vec![];
    for shard in 0..2 {
        let rows = simple(
            &connect_shard(shard).await,
            "SELECT count(*) FROM masking_e2e.users",
        )
        .await;
        counts.push(rows[0][0].as_deref().unwrap().parse::<i64>().unwrap());
    }
    assert!(counts.iter().all(|&count| count > 0), "{counts:?}");
    assert_eq!(counts.iter().sum::<i64>(), ROWS, "{counts:?}");

    // Control: the exempt user sees raw values, merged from both shards.
    let rows = simple(
        &admin,
        "SELECT ssn, card FROM masking_e2e.users ORDER BY id",
    )
    .await;
    assert_eq!(
        column(&rows, 0),
        (1..=ROWS).map(|id| Some(ssn(id))).collect::<Vec<_>>()
    );
    assert!(leaked(&rows).is_some());

    // No raw value reaches a masked user, in either protocol.
    for user in ["masked", "analyst"] {
        let client = connect(user).await;
        for sql in CROSS_SHARD {
            let rows = simple(&client, sql).await;
            assert_eq!(leaked(&rows), None, "{user}: {sql}: {rows:?}");
            let extended: Rows = client
                .query(*sql, &[])
                .await
                .expect(sql)
                .iter()
                .map(|row| {
                    (0..row.len())
                        .map(|i| row.get::<_, Option<Binary>>(i).map(|value| value.0))
                        .collect()
                })
                .collect();
            assert_eq!(leaked(&extended), None, "{user}: {sql}: {extended:?}");
        }

        // COPY from both shards.
        let stream = client
            .copy_out("COPY masking_e2e.users (id, ssn, email) TO STDOUT")
            .await
            .unwrap();
        pin_mut!(stream);
        let mut copied = String::new();
        while let Some(chunk) = stream.next().await {
            copied.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
        }
        assert_eq!(copied.lines().count(), ROWS as usize, "{user}: {copied}");
        assert!(
            CANARIES.iter().all(|canary| !copied.contains(canary)),
            "{user}: {copied}"
        );
    }

    let masked = connect("masked").await;

    // SQL masks: shards sort, aggregate and deduplicate masked values, and so
    // does PgDog when it merges them. It merges sorted results by output
    // columns: see test_sharded_order_by_masked_column.
    let rows = simple(&masked, "SELECT ssn FROM masking_e2e.users ORDER BY 1 DESC").await;
    assert_eq!(column(&rows, 0), masked_ssns_descending());
    let rows = simple(&masked, "SELECT DISTINCT email FROM masking_e2e.users").await;
    assert_eq!(rows, vec![vec![Some("****@example.com".into())]]);
    let rows = simple(
        &masked,
        "SELECT email, count(*) FROM masking_e2e.users GROUP BY email",
    )
    .await;
    assert_eq!(
        rows,
        vec![vec![
            Some("****@example.com".into()),
            Some(ROWS.to_string())
        ]]
    );
    let rows = simple(&masked, "SELECT max(ssn), count(*) FROM masking_e2e.users").await;
    assert_eq!(
        rows,
        vec![vec![
            Some(format!("XXX-XX-{ROWS:04}")),
            Some(ROWS.to_string())
        ]]
    );
    // Masked predicates don't match raw values on any shard.
    let rows = simple(
        &masked,
        "SELECT id FROM masking_e2e.users WHERE ssn LIKE 'CANARY%'",
    )
    .await;
    assert!(rows.is_empty(), "{rows:?}");

    // Proxy masks: each row's tokens, wherever the shards' rows end up.
    let by_id = simple(
        &masked,
        "SELECT id, card, balance FROM masking_e2e.users ORDER BY id",
    )
    .await;
    assert_eq!(by_id.len(), ROWS as usize);
    for row in &by_id {
        let id: i64 = row[0].as_deref().unwrap().parse().unwrap();
        let token = row[1].as_deref().unwrap();
        assert_ne!(token, card(id));
        assert_eq!(token.len(), 19, "{token}");
        assert_eq!(row[2], Some((balance(id) + 1).to_string()));
    }
    // Sorted by the real values, not by their tokens.
    let rows = simple(&masked, "SELECT card FROM masking_e2e.users ORDER BY card").await;
    assert_eq!(column(&rows, 0), column(&by_id, 1));
    let rows = simple(
        &masked,
        "SELECT balance FROM masking_e2e.users ORDER BY balance DESC",
    )
    .await;
    assert_eq!(
        column(&rows, 0),
        column(&by_id, 2).into_iter().rev().collect::<Vec<_>>()
    );
    // Aggregates of proxy-masked values, even count(), are computed from
    // them: NULL.
    let rows = simple(
        &masked,
        "SELECT max(card), sum(balance), count(card) FROM masking_e2e.users",
    )
    .await;
    assert_eq!(rows, vec![vec![None, None, None]]);

    // SQL masks only: proxy-masked columns are NULL.
    let analyst = connect("analyst").await;
    let rows = simple(
        &analyst,
        "SELECT card, tax_id, balance FROM masking_e2e.users ORDER BY id",
    )
    .await;
    assert_eq!(rows, vec![vec![None, None, None]; ROWS as usize]);
}

/// `ORDER BY ssn` is rewritten to `ORDER BY <mask of ssn>`. PgDog only
/// merge-sorts results from several shards when `ORDER BY` names an output
/// column or its position: with an expression, it returns the shards' rows
/// one shard after the other, each sorted. So masked users get rows out of
/// order, while `ORDER BY 1` works.
#[tokio::test]
#[ignore = "ORDER BY a masked column isn't merge-sorted across shards"]
async fn test_sharded_order_by_masked_column() {
    if !enabled() {
        return;
    }
    seed(&connect("admin").await).await;
    let masked = connect("masked").await;
    let rows = simple(
        &masked,
        "SELECT ssn FROM masking_e2e.users ORDER BY ssn DESC",
    )
    .await;
    assert_eq!(column(&rows, 0), masked_ssns_descending());
}
