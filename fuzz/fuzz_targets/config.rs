//! Configuration: arbitrary TOML, loaded the way the config hook loads the
//! file, then every other hook run with it. `{dir}` in the input is the
//! directory holding the fuzzer's proxy mask keys.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use pgdog_mask::config::Config;
use pgdog_mask::engine::Engine;
use pgdog_mask::pgdog_plugin::redact::field;
use pgdog_mask::pgdog_plugin::{
    Catalog, ErrorField, ErrorFields, MaskBatch, MaskColumn, MaskOutput, Value, Verdict,
    types::Format,
};
use pgdog_mask_fuzz::fixture::{
    DATABASE, PROXY_STATEMENT, catalog, key_dir, registry, with_key_dir,
};
use pgdog_mask_fuzz::session::{Owned, check_rewrite, standard_sessions};

static CATALOG: LazyLock<Catalog> = LazyLock::new(catalog);
static SESSIONS: LazyLock<Vec<Owned>> = LazyLock::new(standard_sessions);

const STATEMENTS: &[&str] = &[
    "SELECT * FROM users",
    "SELECT ssn, email FROM users WHERE ssn = '123-45-6789' ORDER BY salary",
    "SELECT * FROM user_ssns JOIN ssn_barrier USING (id)",
    "SELECT user_ssn(1), last4(ssn) FROM users",
    "COPY users TO STDOUT",
    "UPDATE users SET name = ssn RETURNING *",
    PROXY_STATEMENT,
];

/// Proxy mask keys come from files: only the fuzzer's own, so a config can't
/// make the fuzzer read `/dev/zero`.
fn reads_other_files(config: &Config) -> bool {
    let dir = key_dir();
    config
        .policies
        .iter()
        .flat_map(|policy| {
            std::iter::once(&policy.options).chain(policy.rules.iter().map(|rule| &rule.options))
        })
        .flatten()
        .filter_map(|options| options.get("key_file"))
        .any(|path| {
            !path
                .as_str()
                .is_some_and(|path| path.starts_with(&*dir.to_string_lossy()))
        })
}

fuzz_target!(|data: &[u8]| {
    let Ok(toml) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(config) = Config::from_toml(&with_key_dir(toml)) else {
        return;
    };
    if reads_other_files(&config) {
        return;
    }
    let Ok(engine) = Engine::with_registry(config, registry()) else {
        return;
    };
    engine.catalog(DATABASE, &CATALOG);

    let fields = [
        ErrorField::new(field::SQLSTATE, "23514".into()),
        ErrorField::new(
            field::DETAIL,
            "Failing row contains (1, 123-45-6789).".into(),
        ),
    ];
    let error = ErrorFields::new(false, &fields);

    for owned in SESSIONS.iter() {
        let session = owned.session();
        for sql in STATEMENTS {
            let verdict = engine.statement(&session, sql);
            check_rewrite(sql, &verdict);

            // Mask a row for every proxy column the statement got.
            if let Verdict::Rewrite { columns, .. } = &verdict {
                let values = [
                    Value::new(Some(b"123-45-6789")),
                    Value::new(Some(b"42")),
                    Value::new(None),
                ];
                for format in [Format::Text, Format::Binary] {
                    let batch_columns: Vec<_> = columns
                        .iter()
                        .map(|mask| MaskColumn::new(mask, format, &values))
                        .collect();
                    let batch = MaskBatch::new(values.len() as u32, &batch_columns);
                    let mut out = MaskOutput::default();
                    if engine.mask_rows(&batch, &mut out).is_ok() {
                        assert_eq!(out.len(), batch_columns.len() * values.len());
                    }
                }
            }
        }
        let _ = engine.function_call(&session, 1);
        let _ = engine.redact_error(&session, &error);
    }
    assert!(engine.reload(), "nothing to reload without a file");
});
