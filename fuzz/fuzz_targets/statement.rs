//! The statement hook, with raw SQL: every statement runs in each of the
//! standard sessions. Seeded with the statements of the analyzer's tests.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use pgdog_mask_fuzz::plugin;
use pgdog_mask_fuzz::session::{Owned, check_verdict, standard_sessions};

static SESSIONS: LazyLock<Vec<Owned>> = LazyLock::new(standard_sessions);

fuzz_target!(|data: &[u8]| {
    // PgDog passes SQL from protocol strings: UTF-8, without NUL.
    let Ok(sql) = std::str::from_utf8(data) else {
        return;
    };
    if sql.contains('\0') {
        return;
    }

    let plugin = plugin();
    for owned in SESSIONS.iter() {
        let session = owned.session();
        let verdict = plugin
            .statement(&session, sql)
            .unwrap_or_else(|err| panic!("statement hook failed: {err}"));
        check_verdict(owned, sql, &verdict);

        // Prepared statements depend on the same statement getting the same
        // verdict; the second call is served from the caches.
        let again = plugin
            .statement(&session, sql)
            .unwrap_or_else(|err| panic!("statement hook failed: {err}"));
        assert_eq!(verdict, again, "verdicts must be deterministic");
    }
});
