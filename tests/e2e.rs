//! End-to-end tests through PgDog with the plugin loaded.
//!
//! Run with `bash integration/masking/run.sh`; skipped unless `PGDOG_MASKING_E2E=1`.
use futures_util::{StreamExt as _, pin_mut};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage, error::SqlState};

fn enabled() -> bool {
    std::env::var("PGDOG_MASKING_E2E").is_ok_and(|v| v == "1")
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

    // COPY.
    let stream = client
        .copy_out("COPY masking_e2e.users TO STDOUT")
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
    let rows = simple(&client, "SELECT ssn FROM masking_e2e.users WHERE id = 1").await;
    assert_eq!(rows, vec![vec![Some("CANARYSSN-1111".into())]]);
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
