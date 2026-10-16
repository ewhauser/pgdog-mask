//! Per-statement overhead of the masking plugin.
//!
//! `cargo bench -p pgdog-masking --bench overhead`
use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pgdog_masking::config::Config;
use pgdog_masking::engine::Engine;
use pgdog_plugin::{Identity, StatementContext, StatementKind};
use serde_json::{Value, json};

const CONFIG: &str = r#"
[[users]]
name = "admin"
roles = ["pii_admin"]

[[policies]]
name = "balance"
data_type = "integer"
mask = "round"
digits = -2

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
name = "ssn"
data_type = "text"
mask = "partial"
keep_suffix = 4

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[masked_columns]]
name = "pgbench_accounts"
column = "abalance"
policy = "balance"

[[masked_columns]]
name = "customers"
column = "email"
policy = "email"

[[masked_columns]]
name = "customers"
column = "ssn"
policy = "ssn"
"#;

fn relation(name: &str, columns: &[(&str, &str)]) -> Value {
    let columns: serde_json::Map<String, Value> = columns
        .iter()
        .enumerate()
        .map(|(i, (column, data_type))| {
            (
                column.to_string(),
                json!({
                    "column_name": column,
                    "data_type": data_type,
                    "ordinal_position": i as i32 + 1,
                }),
            )
        })
        .collect();
    json!({
        "schema": "public",
        "name": name,
        "type_": "table",
        "parent_table_schema": null,
        "parent_table_name": null,
        "columns": columns,
    })
}

fn snapshot() -> String {
    let mut customers = vec![
        ("id", "bigint"),
        ("email", "text"),
        ("ssn", "text"),
        ("created_at", "timestamp with time zone"),
    ];
    let extra: Vec<String> = (0..30).map(|i| format!("attr_{i}")).collect();
    customers.extend(extra.iter().map(|c| (c.as_str(), "text")));

    json!({"inner": {
        "search_path": ["$user", "public"],
        "full_catalog": true,
        "functions": [],
        "operators": [],
        "system_functions": include_str!("../src/analyzer/test_builtin_functions.txt").lines().collect::<Vec<_>>(),
        "relations": {"public": {
            "pgbench_accounts": relation("pgbench_accounts", &[("aid", "integer"), ("bid", "integer"), ("abalance", "integer"), ("filler", "character")]),
            "pgbench_branches": relation("pgbench_branches", &[("bid", "integer"), ("bbalance", "integer"), ("filler", "character")]),
            "customers": relation("customers", &customers),
            "orders": relation("orders", &[("id", "bigint"), ("customer_id", "bigint"), ("total", "numeric"), ("created_at", "timestamp with time zone")]),
        }},
    }})
    .to_string()
}

const POINT: &str = "SELECT abalance FROM pgbench_accounts WHERE aid = $1";
const UNMASKED: &str = "SELECT bid FROM pgbench_accounts WHERE aid = $1";
const JOIN: &str = "SELECT a.aid, a.bid, a.abalance, b.bbalance FROM pgbench_accounts a JOIN pgbench_branches b ON b.bid = a.bid WHERE a.aid = $1 ORDER BY a.aid LIMIT 10";
const ORM: &str = r#"SELECT "customers".* FROM "customers" INNER JOIN "orders" ON "orders"."customer_id" = "customers"."id" WHERE "customers"."id" IN ($1, $2, $3) AND "orders"."created_at" > $4 AND ("customers"."email" ILIKE $5 OR "customers"."ssn" = $6) ORDER BY "customers"."created_at" DESC LIMIT $7 OFFSET $8"#;

fn context<'a>(user: &'a str, sql: &'a str) -> StatementContext<'a> {
    context_kind(user, sql, StatementKind::Bind)
}

fn context_kind<'a>(user: &'a str, sql: &'a str, kind: StatementKind) -> StatementContext<'a> {
    StatementContext {
        identity: Identity {
            user: user.into(),
            database: "bench".into(),
            ..Default::default()
        },
        kind,
        sql: sql.into(),
        statement_name: "".into(),
        search_path: "".into(),
        in_transaction: false,
    }
}

fn engine() -> Engine {
    let engine = Engine::new(Config::from_toml(CONFIG).unwrap()).unwrap();
    engine.schema("bench", 1, &snapshot());
    engine
}

/// Average time per call.
fn measure(name: &str, mut f: impl FnMut(u64)) {
    let warmup = Instant::now();
    let mut i = 0;
    while warmup.elapsed() < Duration::from_millis(200) {
        f(i);
        i += 1;
    }
    let iterations = (i * 5).max(1000);
    let start = Instant::now();
    for i in 0..iterations {
        f(i + 1_000_000_000);
    }
    let per = start.elapsed() / iterations as u32;
    println!("{name:<48} {:>10.2?}/op", per);
}

fn main() {
    let engine = Arc::new(engine());

    println!("-- cache hits");
    measure("exempt user", |_| {
        black_box(engine.statement(&context("admin", POINT)));
    });
    for (name, sql) in [
        ("point", POINT),
        ("unmasked column", UNMASKED),
        ("join", JOIN),
        ("orm (star over 34 columns)", ORM),
    ] {
        measure(&format!("masked user, {name}"), |_| {
            black_box(engine.statement(&context("masked", sql)));
        });
    }

    println!("-- simple protocol, distinct literals every call");
    for (name, sql) in [
        ("point", POINT),
        ("unmasked column", UNMASKED),
        ("join", JOIN),
        ("orm (star over 34 columns)", ORM),
    ] {
        measure(&format!("masked user, {name}"), |i| {
            let sql = sql.replace("$1", &i.to_string());
            black_box(engine.statement(&context_kind("masked", &sql, StatementKind::Query)));
        });
    }

    println!("-- building blocks");
    for (name, sql) in [("point", POINT), ("orm", ORM)] {
        measure(&format!("parse {name}"), |_| {
            black_box(pg_raw_parse::parse(sql).unwrap());
        });
        measure(&format!("normalize {name}"), |_| {
            black_box(pg_raw_parse::normalize::normalize_str(sql).unwrap());
        });
        let parsed = pg_raw_parse::parse(sql).unwrap().into_inner();
        measure(&format!("deparse {name}"), |_| {
            black_box(pg_raw_parse::deparse_stmts(parsed.iter()).unwrap());
        });
    }

    println!("-- concurrency: cache hits, 8 threads");
    for threads in [1, 8] {
        let per_thread = 200_000;
        let start = Instant::now();
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let engine = engine.clone();
                thread::spawn(move || {
                    for _ in 0..per_thread {
                        black_box(engine.statement(&context("masked", JOIN)));
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let elapsed = start.elapsed();
        let ops = (threads * per_thread) as f64 / elapsed.as_secs_f64();
        println!("{threads} thread(s): {:>12.0} statements/s", ops);
    }
}
