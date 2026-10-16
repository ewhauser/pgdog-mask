//! Statement analysis: resolve column references against masking policies
//! and rewrite the statement to read masks instead of masked columns.
pub mod lineage;
mod masker;
mod rules;
mod scope;

use std::collections::BTreeSet;

use pg_raw_parse::make;

use crate::catalog::Catalog;
use crate::profile::{Assignments, Policies, Profile};
use masker::Masker;

/// Everything the analyzer needs to know about the user and the database.
pub struct Context<'a> {
    pub catalog: &'a Catalog,
    pub assignments: &'a Assignments,
    pub policies: &'a Policies,
    pub profile: &'a Profile,
    /// Effective `search_path`.
    pub search_path: Vec<String>,
}

/// Analysis result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to mask; send the statement as-is.
    Unchanged {
        /// Masked columns searched by raw value.
        raw: BTreeSet<String>,
        /// Reads or writes relations with masked columns, so errors can carry
        /// masked values.
        touches_masked: bool,
    },
    /// Send this SQL instead.
    Rewritten {
        sql: String,
        /// Masked columns, as `schema.table.column`.
        masked: BTreeSet<String>,
        raw: BTreeSet<String>,
        touches_masked: bool,
    },
    /// The statement can't be run safely.
    Blocked { reason: String },
}

/// Analyze a statement (or several) for a masked user.
pub fn analyze(sql: &str, ctx: &Context<'_>) -> Outcome {
    let mut result = None;

    let parsed = make::try_owned(|mem| {
        let mut stmts = mem.parse(sql)?;
        let mut masker = Masker::new(mem, ctx);
        for stmt in stmts.as_mut() {
            masker.statement(stmt);
        }
        result = Some((
            masker.blocked,
            masker.changed,
            masker.masked,
            masker.raw,
            masker.touched,
        ));
        Ok::<_, pg_raw_parse::Error>(stmts)
    });

    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(err) => {
            return Outcome::Blocked {
                reason: format!("statement could not be parsed: {err}"),
            };
        }
    };

    let Some((blocked, changed, masked, raw, touches_masked)) = result else {
        return Outcome::Blocked {
            reason: "statement could not be analyzed".into(),
        };
    };

    if let Some(reason) = blocked {
        return Outcome::Blocked { reason };
    }

    if !changed {
        return Outcome::Unchanged {
            raw,
            touches_masked,
        };
    }

    match pg_raw_parse::deparse_stmts(parsed.iter()) {
        Ok(rewritten) => Outcome::Rewritten {
            sql: format!("{}{rewritten}", leading_comments(sql)),
            masked,
            raw,
            touches_masked,
        },
        Err(err) => Outcome::Blocked {
            reason: format!("failed to build the masked statement: {err}"),
        },
    }
}

/// Comments at the start of the statement, which carry PgDog routing hints
/// and are lost when the statement is rebuilt.
fn leading_comments(sql: &str) -> String {
    let mut rest = sql;
    let mut comments = String::new();
    loop {
        let trimmed = rest.trim_start();
        if let Some(body) = trimmed.strip_prefix("/*") {
            let Some(end) = body.find("*/") else { break };
            comments.push_str(&trimmed[..end + 4]);
            comments.push(' ');
            rest = &body[end + 2..];
        } else if trimmed.starts_with("--") {
            let end = trimmed.find('\n').unwrap_or(trimmed.len());
            comments.push_str(&trimmed[..end]);
            comments.push('\n');
            rest = &trimmed[end..];
        } else {
            break;
        }
    }
    comments
}

#[cfg(test)]
pub(crate) mod test;
