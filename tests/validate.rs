//! `pgdog-mask validate` against Postgres.
//!
//! Requires Postgres; set `PGDOG_MASK_TEST_URL` to override the default
//! `host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog`.
use std::path::PathBuf;
use std::process::{Command, Output};

use tokio_postgres::NoTls;

const SCHEMA: &str = "masking_validate";

fn url() -> String {
    std::env::var("PGDOG_MASK_TEST_URL")
        .unwrap_or_else(|_| "host=127.0.0.1 user=pgdog password=pgdog dbname=pgdog".into())
}

async fn setup() -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(&url(), NoTls)
        .await
        .expect("connect to Postgres (set PGDOG_MASK_TEST_URL)");
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {SCHEMA} CASCADE;
             CREATE SCHEMA {SCHEMA};
             CREATE TYPE {SCHEMA}.tier AS ENUM ('free', 'pro');
             CREATE TABLE {SCHEMA}.users (
                 id BIGINT PRIMARY KEY,
                 ssn TEXT,
                 email TEXT,
                 opted_in BOOLEAN,
                 dob DATE,
                 tier {SCHEMA}.tier,
                 card VARCHAR(19)
             );"
        ))
        .await
        .unwrap();
    client
}

/// Run `pgdog-mask` with a configuration file and arguments.
fn run(name: &str, config: &str, args: &[&str]) -> (Output, String) {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("validate-{name}.toml"));
    std::fs::write(&path, config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pgdog-mask"))
        .arg("validate")
        .arg(&path)
        .args(["--url", &url()])
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output, stdout)
}

const VALID: &str = r#"
[[policies]]
name = "ssn"
data_type = "text"
mask = "partial"
keep_suffix = 4

[[policies.rules]]
roles = ["support"]
mask = "sql"
expression = "'XXX-XX-' || right(val, 4)"
search = "raw"

[[policies]]
name = "email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val ELSE regexp_replace(val, '^[^@]*', '****') END"

[[policies]]
name = "card"
data_type = "character varying"
mask = "default"

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "ssn"
policy = "ssn"

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "email"
policy = "email"
arguments = ["opted_in"]

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "card"
policy = "card"
"#;

#[tokio::test]
async fn test_validate() {
    let client = setup().await;

    let (output, stdout) = run("valid", VALID, &["--deny-warnings"]);
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.ends_with(
            "validate-valid.toml: 0 errors, 0 warnings (4 mask checks prepared against database \"pgdog\")\n"
        ),
        "{stdout}"
    );

    // Type errors only show up when the mask is prepared: for the policy's
    // data_type, and for a column of another type.
    let (output, stdout) = run(
        "types",
        &format!(
            r#"{VALID}
[[policies]]
name = "plus"
data_type = "text"
mask = "sql"
expression = "val + 1"

[[policies]]
name = "upper"
data_type = "text"
mask = "sql"
expression = "upper(val)"

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "id"
policy = "upper"
"#
        ),
        &[],
    );
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    let errors: Vec<_> = stdout.lines().filter(|l| l.starts_with("error:")).collect();
    assert_eq!(errors.len(), 2, "{stdout}");
    assert!(
        errors[0].starts_with(
            "error: policy \"plus\", default mask on data_type text: operator does not exist: text + integer (in SELECT (val + 1)::text"
        ),
        "{stdout}"
    );
    assert!(
        errors[1].starts_with(
            "error: policy \"upper\", default mask on masking_validate.users.id: function upper(bigint) does not exist"
        ),
        "{stdout}"
    );

    // Catalog and raw search warnings fail only with --deny-warnings.
    let warnings = format!(
        r#"{VALID}
[[policies]]
name = "dob"
data_type = "date"
mask = "null"
search = "raw"
search_operators = ["=", "<"]

[[policies]]
name = "tier"
data_type = "text"
mask = "null"
search = "raw"

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "dob"
policy = "dob"

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "tier"
policy = "tier"

[[masked_columns]]
schema = "masking_validate"
name = "users"
column = "phone"
policy = "ssn"

[[masked_columns]]
schema = "masking_validate"
name = "accounts"
column = "ssn"
policy = "ssn"
"#
    );
    let (output, stdout) = run("warnings", &warnings, &[]);
    assert!(output.status.success(), "{stdout}");
    let found: Vec<_> = stdout
        .lines()
        .filter(|l| l.starts_with("warning:"))
        .collect();
    assert_eq!(
        found,
        [
            "warning: policy \"dob\", default mask: search = \"raw\" with range operators (<, >, BETWEEN) lets these users recover a value by binary search, in a few dozen statements",
            "warning: policy \"dob\", default mask: search = \"raw\" on date values lets these users find any value by trying each possible one with =",
            "warning: [[masked_columns]] masking_validate.users.phone: masking_validate.users has no column \"phone\" in database \"pgdog\", so it masks nothing",
            "warning: [[masked_columns]] masking_validate.accounts.ssn: table masking_validate.accounts doesn't exist in database \"pgdog\", so it masks nothing",
            "warning: policy \"tier\", default mask on masking_validate.users.tier: search = \"raw\" on enum masking_validate.tier lets these users find any value by trying each of its 2 labels with =",
        ],
        "{stdout}"
    );
    let (output, _) = run("warnings", &warnings, &["--deny-warnings"]);
    assert_eq!(output.status.code(), Some(1));

    // Assignments are matched against another PgDog database's name.
    let (output, stdout) = run(
        "database",
        &VALID.replace("schema = ", "database = \"other\"\nschema = "),
        &["--database", "pgdog", "--deny-warnings"],
    );
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("(3 mask checks prepared"), "{stdout}");

    // Configuration errors, as the plugin reports them.
    let (output, stdout) = run("invalid", "[general]\nbogus = 1\n", &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout.starts_with("error: failed to parse config"),
        "{stdout}"
    );

    // Usage errors.
    let output = Command::new(env!("CARGO_BIN_EXE_pgdog-mask"))
        .args(["validate", "masking.toml", "--bogus"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // Other tests' unqualified names must not resolve here.
    client
        .batch_execute(&format!("DROP SCHEMA {SCHEMA} CASCADE"))
        .await
        .unwrap();
}
