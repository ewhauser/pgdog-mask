//! Statement analysis: resolve column references against masking policies,
//! rewrite the statement to read SQL masks instead of masked columns, and
//! decide how PgDog masks the results for proxy masks.
pub mod lineage;
mod masker;
mod rules;
mod scope;
pub mod shape;
mod taint;

use std::collections::BTreeSet;

use pg_raw_parse::{Node, make};

use crate::catalog::Catalog;
use crate::profile::{Assignments, Policies, Profile};
use masker::Masker;
pub(crate) use rules::deparsable;

/// Everything the analyzer needs to know about the user and the database.
pub struct Context<'a> {
    pub catalog: &'a Catalog,
    pub assignments: &'a Assignments,
    pub policies: &'a Policies,
    pub profile: &'a Profile,
    /// Effective `search_path`.
    pub search_path: Vec<String>,
}

/// How PgDog masks a result column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultMask {
    /// The column passes a proxy-masked column through: mask its values with
    /// [`crate::profile::Policies::proxies`]`[proxy]`. The column has type
    /// `type_oid`.
    Proxy { proxy: usize, type_oid: u32 },
    /// The column is computed from proxy-masked values: NULL.
    Null,
}

/// A masked result column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultColumn {
    /// Position of the statement in the query, counting every statement.
    pub result: u16,
    /// Position of the column in the statement's result.
    pub column: u16,
    pub mask: ResultMask,
}

/// What PgDog does with a query's results.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Results {
    pub columns: Vec<ResultColumn>,
    /// Errors may quote values of proxy-masked columns: keep only their
    /// severity, SQLSTATE and position.
    pub redact_errors: bool,
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
        /// Result masks for proxy masks.
        results: Results,
    },
    /// Send this SQL instead.
    Rewritten {
        sql: String,
        /// SQL-masked columns rewritten in the statement, as
        /// `schema.table.column`. Proxy-masked columns aren't rewritten.
        masked: BTreeSet<String>,
        raw: BTreeSet<String>,
        touches_masked: bool,
        /// Result masks for proxy masks.
        results: Results,
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
        let nodes: Vec<_> = stmts.as_ref().iter().map(|stmt| stmt.stmt()).collect();
        if let Err(reason) = rules::check_resolution_settings(sql, &nodes) {
            masker.blocked = Some(reason.to_owned());
        }
        // Each statement gets the result masks of its position, and may
        // change name resolution for the ones after it.
        for (index, stmt) in stmts.as_mut().into_iter().enumerate() {
            masker.statement(stmt);
            masker.finish_statement(index);
        }
        result = Some((
            masker.blocked,
            masker.changed,
            masker.masked,
            masker.raw,
            masker.touched,
            masker.results,
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

    let Some((blocked, changed, masked, raw, touches_masked, results)) = result else {
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
            results,
        };
    }

    match pg_raw_parse::deparse_stmts(parsed.iter()) {
        Ok(rewritten) => Outcome::Rewritten {
            sql: format!("{}{rewritten}", leading_comments(sql)),
            masked,
            raw,
            touches_masked,
            results,
        },
        Err(err) => Outcome::Blocked {
            reason: format!("failed to build the masked statement: {err}"),
        },
    }
}

/// Analyze a statement through its shape: analyze the statement with literals
/// replaced by placeholders, then put this statement's literals back.
/// `None` if the statement has no shape (see [`shape::literals`]).
pub fn analyze_shape(sql: &str, ctx: &Context<'_>) -> Option<Outcome> {
    let literals = shape::literals(sql)?;
    Some(match analyze(&literals.shape, ctx) {
        Outcome::Rewritten {
            sql: shape_sql,
            masked,
            raw,
            touches_masked,
            results,
        } => Outcome::Rewritten {
            sql: shape::Template::new(&shape_sql, literals.values.len())?
                .render(&literals.values)?,
            masked,
            raw,
            touches_masked,
            results,
        },
        other => other,
    })
}

/// Does a statement return rows that get result masks: a SELECT without INTO
/// (on a set operation, its leftmost leaf's), or INSERT, UPDATE or DELETE with
/// RETURNING?
pub(crate) fn returns_rows(node: Node<'_>) -> bool {
    let returning = |clause: Option<&pg_raw_parse::nodes::ReturningClause>| {
        clause.is_some_and(|clause| !clause.exprs().is_empty())
    };
    match node {
        Node::SelectStmt(select) => rules::into_clause(select).is_none(),
        Node::InsertStmt(insert) => returning(insert.returning_clause()),
        Node::UpdateStmt(update) => returning(update.returning_clause()),
        Node::DeleteStmt(delete) => returning(delete.returning_clause()),
        _ => false,
    }
}

/// Comments at the start of the statement, which carry PgDog routing hints
/// and are lost when the statement is rebuilt.
pub(crate) fn leading_comments(sql: &str) -> String {
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
