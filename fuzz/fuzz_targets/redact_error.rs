//! The error redaction hook: errors and notices with arbitrary fields, in
//! fuzzed sessions. Masked users lose `DETAIL`, and nothing else.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pgdog_mask::pgdog_plugin::redact::field;
use pgdog_mask::pgdog_plugin::{ErrorField, ErrorFields};
use pgdog_mask_fuzz::plugin;
use pgdog_mask_fuzz::session::SessionInput;

const MAX_FIELDS: usize = 16;

/// Field codes Postgres sends.
const CODES: &[u8] = b"SVCMDHPpqWstcdnFLR";

#[derive(Debug, Arbitrary)]
struct Input {
    session: SessionInput,
    notice: bool,
    fields: Vec<(Code, String)>,
}

#[derive(Debug, Arbitrary)]
enum Code {
    Known(u8),
    Other(u8),
}

fuzz_target!(|input: Input| {
    let owned = input.session.owned();
    // Fields as PgDog parses them from the wire: non-zero codes, no NUL.
    let fields: Vec<(u8, String)> = input
        .fields
        .iter()
        .take(MAX_FIELDS)
        .map(|(code, value)| {
            let code = match code {
                Code::Known(i) => CODES[*i as usize % CODES.len()],
                Code::Other(code) => (*code).max(1),
            };
            (code, value.replace('\0', ""))
        })
        .collect();
    let error_fields: Vec<ErrorField<'_>> = fields
        .iter()
        .map(|(code, value)| ErrorField {
            code: *code,
            value: value.as_str().into(),
        })
        .collect();
    let error = ErrorFields::new(input.notice, &error_fields);

    let redacted = plugin()
        .redact_error(&owned.session(), &error)
        .unwrap_or_else(|err| panic!("redact hook failed: {err}"));

    // Every user but the exempt one is masked, unknown users included.
    let has_detail = fields.iter().any(|(code, _)| *code == field::DETAIL);
    if owned.exempt() || !has_detail {
        assert_eq!(redacted, None, "nothing to redact for {owned:?}");
    } else {
        let expected: Vec<(u8, String)> = fields
            .into_iter()
            .filter(|(code, _)| *code != field::DETAIL)
            .collect();
        assert_eq!(redacted, Some(expected), "only DETAIL is removed");
    }
});
