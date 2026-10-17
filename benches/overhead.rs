//! Per-statement overhead of the masking plugin.
//!
//! `cargo bench -p pgdog-mask --bench overhead`
use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pgdog_mask::config::Config;
use pgdog_mask::engine::Engine;
use pgdog_plugin::{
    Catalog, CatalogParts, MaskBatch, MaskColumn, MaskOutput, Session, Value, Verdict,
    catalog::{Column, Relation, RelationKind},
    types::Format,
};

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

[[policies]]
name = "tax_id"
data_type = "text"
mask = "proxy"
proxy = "hmac_sha256"
options = { key_env = "PGDOG_MASK_BENCH_HMAC_KEY" }

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[masked_columns]]
name = "payments"
column = "tax_id"
policy = "tax_id"
"#;

fn relation(name: &str, columns: &[(&str, &str)]) -> Relation {
    let mut relation = Relation::new("public", name, RelationKind::Table);
    relation.columns = columns
        .iter()
        .map(|(column, data_type)| Column::new(*column, *data_type))
        .collect();
    relation
}

fn catalog() -> Catalog {
    let mut customers = vec![
        ("id", "bigint"),
        ("email", "text"),
        ("ssn", "text"),
        ("created_at", "timestamp with time zone"),
    ];
    let extra: Vec<String> = (0..30).map(|i| format!("attr_{i}")).collect();
    customers.extend(extra.iter().map(|c| (c.as_str(), "text")));
    // Proxy masks need the column's type OID.
    let mut payments = relation("payments", &[("id", "bigint"), ("tax_id", "text")]);
    payments.columns[1].type_oid = 25;

    let mut catalog = Catalog::new(CatalogParts::ALL);
    catalog.search_path = vec!["$user".into(), "public".into()];
    catalog.relations = vec![
        relation(
            "pgbench_accounts",
            &[
                ("aid", "integer"),
                ("bid", "integer"),
                ("abalance", "integer"),
                ("filler", "character"),
            ],
        ),
        relation(
            "pgbench_branches",
            &[
                ("bid", "integer"),
                ("bbalance", "integer"),
                ("filler", "character"),
            ],
        ),
        relation("customers", &customers),
        payments,
        relation(
            "orders",
            &[
                ("id", "bigint"),
                ("customer_id", "bigint"),
                ("total", "numeric"),
                ("created_at", "timestamp with time zone"),
            ],
        ),
    ];
    catalog.system_functions = include_str!("../src/analyzer/test_builtin_functions.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    catalog
}

const POINT: &str = "SELECT abalance FROM pgbench_accounts WHERE aid = $1";
const UNMASKED: &str = "SELECT bid FROM pgbench_accounts WHERE aid = $1";
const JOIN: &str = "SELECT a.aid, a.bid, a.abalance, b.bbalance FROM pgbench_accounts a JOIN pgbench_branches b ON b.bid = a.bid WHERE a.aid = $1 ORDER BY a.aid LIMIT 10";
const PROXY: &str = "SELECT id, tax_id FROM payments";
const ORM: &str = r#"SELECT "customers".* FROM "customers" INNER JOIN "orders" ON "orders"."customer_id" = "customers"."id" WHERE "customers"."id" IN ($1, $2, $3) AND "orders"."created_at" > $4 AND ("customers"."email" ILIKE $5 OR "customers"."ssn" = $6) ORDER BY "customers"."created_at" DESC LIMIT $7 OFFSET $8"#;

fn session(user: &str) -> Session<'_> {
    Session::new(user.into(), "bench".into())
}

fn engine() -> Engine {
    let engine = Engine::new(Config::from_toml(CONFIG).unwrap()).unwrap();
    engine.catalog("bench", &catalog());
    engine
}

/// Average time per call.
fn measure(name: &str, mut f: impl FnMut(u64)) -> Duration {
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
    per
}

fn main() {
    // SAFETY: set before the engine reads it, and before any other thread starts.
    unsafe { std::env::set_var("PGDOG_MASK_BENCH_HMAC_KEY", "bench-hmac-key") };
    let engine = Arc::new(engine());

    println!("-- cache hits");
    measure("exempt user", |_| {
        black_box(engine.statement(&session("admin"), POINT));
    });
    for (name, sql) in [
        ("point", POINT),
        ("unmasked column", UNMASKED),
        ("join", JOIN),
        ("orm (star over 34 columns)", ORM),
    ] {
        measure(&format!("masked user, {name}"), |_| {
            black_box(engine.statement(&session("masked"), sql));
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
            black_box(engine.statement(&session("masked"), &sql));
        });
    }

    println!("-- proxy masks");
    let Verdict::Rewrite { columns, .. } = engine.statement(&session("masked"), PROXY) else {
        panic!("{PROXY} should have a proxy mask");
    };
    let tax_ids: Vec<String> = (0..500).map(|i| format!("TAX-{i:08}")).collect();
    let values: Vec<Value<'_>> = tax_ids
        .iter()
        .map(|tax_id| Value::new(Some(tax_id.as_bytes())))
        .collect();
    let batch_columns = [MaskColumn::new(&columns[0], Format::Text, &values)];
    let batch = MaskBatch::new(values.len() as u32, &batch_columns);
    let per = measure("hmac_sha256, a batch of 500 values", |_| {
        let mut out = MaskOutput::default();
        engine.mask_rows(&batch, &mut out).unwrap();
        black_box(out);
    });
    println!("{:<48} {:>10.2?}/value", "", per / values.len() as u32);

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
                        black_box(engine.statement(&session("masked"), JOIN));
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
