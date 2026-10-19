//! `pgdog-mask`: check a masking configuration against a database.
//!
//! ```text
//! pgdog-mask validate masking.toml [--url URL] [--database NAME] [--skip-proxy-masks] [--deny-warnings]
//! ```
//!
//! Exits with 1 when the configuration has errors (or warnings, with
//! `--deny-warnings`), and 2 when it can't run the checks.
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use pgdog_mask::catalog::parse_search_path;
use pgdog_mask::config::Config;
use pgdog_mask::proxy::Registry;
use pgdog_mask::schema::load_catalog;
use pgdog_mask::validate::{self, Finding, Severity, Validation};
use tokio_postgres::{Client, NoTls, SimpleQueryMessage};

const USAGE: &str = "\
Usage: pgdog-mask validate <CONFIG> [OPTIONS]

Check a masking configuration against a database: prepare every SQL mask for
the types it's applied to, check [[masked_columns]] and [[classifiers]]
against the catalog, and warn about risky raw searches.

Options:
  --url <URL>          Postgres to check against, as a URL or key=value
                       string. Defaults to the PGHOST, PGPORT, PGUSER,
                       PGPASSWORD and PGDATABASE variables.
  --database <NAME>    PgDog database whose [[masked_columns]] and
                       [[classifiers]] apply. Defaults to the Postgres
                       database's name.
  --skip-proxy-masks   Don't build proxy masks, which needs their keys.
  --deny-warnings      Exit with 1 on warnings too.
  -h, --help           Print this help.
  -V, --version        Print the version.";

struct Args {
    config: PathBuf,
    url: Option<String>,
    database: Option<String>,
    skip_proxy_masks: bool,
    deny_warnings: bool,
}

enum Command {
    Validate(Args),
    Help,
    Version,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut config = None;
    let mut url = None;
    let mut database = None;
    let mut skip_proxy_masks = false;
    let mut deny_warnings = false;

    match args.next().as_deref() {
        Some("validate") => (),
        Some("-h" | "--help" | "help") => return Ok(Command::Help),
        Some("-V" | "--version") => return Ok(Command::Version),
        Some(other) => return Err(format!("unknown command \"{other}\"")),
        None => return Err("missing command".into()),
    }
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--url" => url = Some(value("--url")?),
            "--database" => database = Some(value("--database")?),
            "--skip-proxy-masks" => skip_proxy_masks = true,
            "--deny-warnings" => deny_warnings = true,
            "-h" | "--help" => return Ok(Command::Help),
            flag if flag.starts_with('-') => return Err(format!("unknown option \"{flag}\"")),
            path if config.is_none() => config = Some(PathBuf::from(path)),
            extra => return Err(format!("unexpected argument \"{extra}\"")),
        }
    }
    Ok(Command::Validate(Args {
        config: config.ok_or("missing the configuration file")?,
        url,
        database,
        skip_proxy_masks,
        deny_warnings,
    }))
}

/// Connection settings from `--url`, or from the libpq variables.
fn connection(url: Option<&str>) -> Result<tokio_postgres::Config, String> {
    if let Some(url) = url {
        return url.parse().map_err(|err| format!("invalid --url: {err}"));
    }
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let user = var("PGUSER")
        .or_else(|| var("USER"))
        .unwrap_or_else(|| "postgres".into());
    let mut config = tokio_postgres::Config::new();
    config
        .host(var("PGHOST").as_deref().unwrap_or("localhost"))
        .port(match var("PGPORT") {
            Some(port) => port
                .parse()
                .map_err(|_| format!("invalid PGPORT \"{port}\""))?,
            None => 5432,
        })
        .dbname(var("PGDATABASE").as_deref().unwrap_or(&user))
        .user(&user);
    if let Some(password) = var("PGPASSWORD") {
        config.password(password);
    }
    Ok(config)
}

async fn rows(client: &Client, sql: &str) -> Result<Vec<Vec<String>>, tokio_postgres::Error> {
    Ok(client
        .simple_query(sql)
        .await?
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(
                (0..row.len())
                    .map(|i| row.get(i).unwrap_or_default().to_owned())
                    .collect(),
            ),
            _ => None,
        })
        .collect())
}

/// Validate, or the reason the checks couldn't run.
async fn run(args: &Args, config: &Config) -> Result<(String, Validation), String> {
    let (client, connection) = connection(args.url.as_deref())?
        .connect(NoTls)
        .await
        .map_err(|err| format!("failed to connect to Postgres: {err}"))?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("error: connection to Postgres failed: {err}");
        }
    });
    let failed = |err: tokio_postgres::Error| format!("failed to read the catalog: {err}");

    let session = rows(
        &client,
        "SELECT current_database(), current_user, current_setting('search_path')",
    )
    .await
    .map_err(failed)?;
    let [postgres_database, user, search_path] = session[0].as_slice() else {
        return Err("failed to read the session settings".into());
    };
    let database = args.database.clone().unwrap_or(postgres_database.clone());
    let search_path = parse_search_path(search_path, user);
    let search_path: Vec<&str> = search_path.iter().map(String::as_str).collect();
    let catalog = load_catalog(&client, None, &search_path)
        .await
        .map_err(|err| err.to_string())?;
    let enums: HashMap<u32, usize> = rows(
        &client,
        "SELECT enumtypid::int8, count(*) FROM pg_catalog.pg_enum GROUP BY 1",
    )
    .await
    .map_err(failed)?
    .into_iter()
    .filter_map(|row| Some((row[0].parse().ok()?, row[1].parse().ok()?)))
    .collect();

    let options = validate::Options {
        proxy_masks: !args.skip_proxy_masks,
    };
    let mut validation = validate::validate(
        config,
        &Registry::default(),
        &options,
        &database,
        &catalog,
        &enums,
    );

    // Parse and analyze each mask, without running it.
    for probe in &validation.probes {
        if let Err(err) = client.prepare(&probe.sql).await {
            let message = match err.as_db_error() {
                Some(db) => db.message().to_owned(),
                None => return Err(format!("failed to prepare a mask: {err}")),
            };
            validation.findings.push(probe.failed(&message));
        }
    }
    Ok((database, validation))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Command::Validate(args)) => args,
        Ok(Command::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Command::Version) => {
            println!("pgdog-mask {}", pgdog_mask::VERSION);
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("error: {err}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let path = args.config.display();

    // The checks the plugin makes when it loads the file.
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(err) => {
            println!("{}", Finding::error(err.to_string()));
            println!("{path}: invalid");
            return ExitCode::FAILURE;
        }
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let (database, validation) = match runtime.block_on(run(&args, &config)) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    for finding in &validation.findings {
        println!("{finding}");
    }
    let errors = validation.count(Severity::Error);
    let warnings = validation.count(Severity::Warning);
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    println!(
        "{path}: {}, {} ({} prepared against database \"{database}\")",
        plural(errors, "error"),
        plural(warnings, "warning"),
        plural(validation.probes.len(), "mask check"),
    );
    if errors > 0 || (args.deny_warnings && warnings > 0) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
