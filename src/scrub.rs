//! Error and notice scrubbing.
//!
//! Some errors carry row values in their `DETAIL`, e.g. a `CHECK` violation's
//! `Failing row contains (1, 123-45-6789, ...)` or a unique violation's
//! `Key (ssn)=(123-45-6789) already exists`. For statements that touch relations
//! with masked columns, the plugin removes `DETAIL` from `ErrorResponse` and
//! `NoticeResponse` messages before they reach the client.

/// Field code of `DETAIL` in `ErrorResponse` and `NoticeResponse`.
const DETAIL: u8 = b'D';

/// Remove `DETAIL` from the body of an `ErrorResponse` or `NoticeResponse`.
/// Returns `None` if there is nothing to remove.
///
/// The body is a list of fields, each a one-byte code and a null-terminated
/// string, ended by a zero byte. A body that doesn't parse is replaced by a
/// generic error, so nothing unchecked reaches the client.
pub fn scrub_detail(body: &[u8]) -> Option<Vec<u8>> {
    let mut fields = vec![];
    let mut rest = body;
    let mut found = false;

    loop {
        match rest.split_first() {
            Some((0, _)) => break,
            Some((&code, tail)) => {
                let Some(end) = tail.iter().position(|b| *b == 0) else {
                    return Some(malformed());
                };
                if code == DETAIL {
                    found = true;
                } else {
                    fields.push((code, &tail[..end]));
                }
                rest = &tail[end + 1..];
            }
            None => return Some(malformed()),
        }
    }

    if !found {
        return None;
    }

    let mut scrubbed = Vec::with_capacity(body.len());
    for (code, value) in fields {
        scrubbed.push(code);
        scrubbed.extend_from_slice(value);
        scrubbed.push(0);
    }
    scrubbed.push(0);
    Some(scrubbed)
}

/// Replacement for a message that couldn't be parsed.
fn malformed() -> Vec<u8> {
    b"SERROR\0VERROR\0CXX000\0Merror details removed by pgdog_masking\0\0".to_vec()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_scrub_detail() {
        let body = b"SERROR\0VERROR\0C23514\0Mnew row violates check constraint \"c\"\0DFailing row contains (1, CANARY).\0nc\0\0";
        let scrubbed = scrub_detail(body).unwrap();
        assert_eq!(
            scrubbed,
            b"SERROR\0VERROR\0C23514\0Mnew row violates check constraint \"c\"\0nc\0\0"
        );
        // Nothing to remove.
        assert!(scrub_detail(&scrubbed).is_none());
        // Malformed bodies are replaced.
        let replaced = scrub_detail(b"SERROR\0DCANARY").unwrap();
        assert!(!String::from_utf8_lossy(&replaced).contains("CANARY"));
        assert!(scrub_detail(b"").is_some());
    }
}
