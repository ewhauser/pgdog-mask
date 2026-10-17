//! The statement hook, with statements generated over the fixture schema (see
//! `pgdog_mask_fuzz::grammar`), in the standard sessions and a fuzzed one.
//!
//! Leak oracle: a statement that reads a masked column is never allowed as is
//! for the masked user.
#![no_main]

use std::sync::LazyLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use pgdog_mask::pgdog_plugin::{Access, Verdict};
use pgdog_mask_fuzz::fixture::{DATABASE, MASKED_USER};
use pgdog_mask_fuzz::session::{Owned, SessionInput, check_verdict, standard_sessions};
use pgdog_mask_fuzz::{grammar, plugin};

static SESSIONS: LazyLock<Vec<Owned>> = LazyLock::new(standard_sessions);

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(fuzzed) = SessionInput::arbitrary(&mut u) else {
        return;
    };
    let Ok(function) = u32::arbitrary(&mut u) else {
        return;
    };
    let Ok(generated) = grammar::statement(&mut u) else {
        return;
    };
    let sql = &generated.sql;

    let plugin = plugin();
    let fuzzed = fuzzed.owned();
    for owned in SESSIONS.iter().chain([&fuzzed]) {
        let session = owned.session();
        let verdict = plugin
            .statement(&session, sql)
            .unwrap_or_else(|err| panic!("statement hook failed: {err}"));
        check_verdict(owned, sql, &verdict);

        if generated.reads_masked
            && owned.user == MASKED_USER
            && owned.database == DATABASE
            && verdict == Verdict::Allow
        {
            panic!(
                "masked user allowed to read masked columns\n  session: {owned:?}\n  statement: {sql}"
            );
        }
    }

    // Fast-path calls carry no SQL to analyze: only exempt users may make them.
    let session = fuzzed.session();
    let access = plugin
        .function_call(&session, function)
        .unwrap_or_else(|err| panic!("function call hook failed: {err}"));
    if fuzzed.exempt() {
        assert_eq!(access, Access::Allow);
    } else if fuzzed.user == MASKED_USER {
        assert!(matches!(access, Access::Deny(_)), "{access:?}");
    }
});
