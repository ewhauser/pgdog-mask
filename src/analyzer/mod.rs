//! Statement analysis: resolve column references against masking policies,
//! rewrite the statement to read SQL masks instead of masked columns, and
//! decide how PgDog masks the results for proxy masks.
pub mod lineage;
mod masker;
mod rules;
mod scope;
pub mod shape;
mod taint;

use std::collections::{BTreeSet, HashSet};

use pg_raw_parse::{Node, make};

use crate::catalog::{Catalog, Relation};
use crate::mask::Mask;
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
    /// Errors and notices may quote real values of masked columns, such as
    /// those of proxy-masked columns, or of any masked column a table-like
    /// view's definition reads: PgDog replaces their message, and keeps their severity, SQLSTATE, position
    /// and the fields naming where they come from (file, line, routine,
    /// schema, table, column, data type and constraint).
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

/// For each table-like view, by column, the policies whose columns' values
/// its definition, run on real values, may put there: through the body of a
/// function, a function in FROM, a column of another table-like view
/// computed from them, or anything else lineage doesn't follow. A view whose
/// definition can't be analyzed for a policy may hold that policy's values
/// in any column. Views in `view_allowlist` aren't analyzed.
///
/// A definition is analyzed with only one policy's columns masked at a
/// time, so a column is attributed to exactly the policies whose values
/// reach it, whoever the user is. Taint only grows with what's masked, so
/// one analysis with every policy masked first rules out views whose
/// columns hold no such values, or only have policies of their own, which
/// mask them whatever they hold.
pub(crate) fn view_outputs(
    catalog: &Catalog,
    assignments: &Assignments,
    policies: &Policies,
    views: &[&Relation],
) -> Vec<Vec<BTreeSet<usize>>> {
    let mut found: Vec<Vec<BTreeSet<usize>>> = views
        .iter()
        .map(|view| vec![BTreeSet::new(); view.columns.len()])
        .collect();
    let used = assignments.policies();
    let general = &policies.config.general;
    let candidates: Vec<usize> = (0..views.len())
        .filter(|&i| !masker::view_allowlisted(general, views[i]))
        .collect();
    if used.is_empty() || candidates.is_empty() {
        return found;
    }

    // Views with a column that may hold masked values and has no policy.
    let unexplained = |view: &Relation, outputs: &Option<Vec<bool>>| match outputs {
        None => true,
        Some(tainted) => view.columns.iter().zip(tainted).any(|(column, tainted)| {
            *tainted
                && assignments
                    .column(&view.schema, &view.name, &column.name)
                    .is_none()
        }),
    };
    let screened = analyze_views(catalog, assignments, policies, &used, views, &candidates);
    let (suspects, screened): (Vec<usize>, Vec<_>) = candidates
        .into_iter()
        .zip(screened)
        .filter(|(i, outputs)| unexplained(views[*i], outputs))
        .unzip();

    for &policy in &used {
        let outputs = match used.len() {
            1 => screened.clone(),
            _ => analyze_views(
                catalog,
                assignments,
                policies,
                &BTreeSet::from([policy]),
                views,
                &suspects,
            ),
        };
        for (&i, outputs) in suspects.iter().zip(&outputs) {
            for (column, policies) in found[i].iter_mut().enumerate() {
                if outputs.as_ref().is_none_or(|tainted| tainted[column]) {
                    policies.insert(policy);
                }
            }
        }
    }
    found
}

/// `masker::view_outputs` for `views[i]` of each `i` in `which`, with the
/// columns of `masked` policies masked.
fn analyze_views(
    catalog: &Catalog,
    assignments: &Assignments,
    policies: &Policies,
    masked: &BTreeSet<usize>,
    views: &[&Relation],
    which: &[usize],
) -> Vec<Option<Vec<bool>>> {
    // In what runs on real values, any mask carries the column's values.
    let masks = (0..policies.policies.len())
        .map(|i| {
            if masked.contains(&i) {
                Mask::Sql {
                    template: "NULL".into(),
                    raw_search: HashSet::new(),
                }
            } else {
                Mask::Unmasked
            }
        })
        .collect();
    let profile = Profile {
        masks,
        hash: 0,
        exempt: false,
        proxies: true,
    };
    let ctx = Context {
        catalog,
        assignments,
        policies,
        profile: &profile,
        search_path: vec![],
    };
    let relations: Vec<&Relation> = which.iter().map(|&i| views[i]).collect();
    let mut outputs = vec![];
    make::owned(|mem| {
        outputs = masker::view_outputs(mem, &ctx, &relations);
        mem.empty()
    });
    outputs
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
