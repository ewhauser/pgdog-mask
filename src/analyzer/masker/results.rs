//! Results-only proxy masks: what each value carries from proxy-masked
//! columns, the masks PgDog applies to the results of row-returning
//! statements, the places values can't go (sinks), and error redaction.
//!
//! References to proxy-masked columns are never rewritten. Instead, each
//! expression's taint is the join of its inputs' (`note`, `scoped`), output
//! lists become [`Outputs`], and a top-level statement's outputs become result
//! masks: a column that passes a proxy-masked column through is masked by its
//! proxy mask, and one computed from proxy-masked values is NULL.
use std::collections::BTreeSet;

use pg_raw_parse::{Node, make::Unique, nodes, transform::Transform};

use super::{Masker, address, fields};
use crate::analyzer::scope::{Item, ItemKind, find_item};
use crate::analyzer::taint::{OutputColumn, Outputs, Taint};
use crate::analyzer::{ResultColumn, ResultMask};
use crate::catalog::Relation;

/// Why a statement whose result columns can't be told apart is blocked.
const CANT_PLACE: &str = "can't place masks on the results: a * of unknown width (a function, a catalog relation, an aliased join over one, (row).* or a join with USING/NATURAL) precedes or covers columns computed from proxy-masked columns; list the columns";

/// What the statement being analyzed does with proxy-masked columns.
#[derive(Debug, Default)]
pub(super) struct StatementState {
    /// Reads proxy-masked columns, directly or through a function or view.
    pub reads_proxies: bool,
    /// Names a relation with proxy-masked columns.
    pub touches_proxies: bool,
    /// Writes, maintains, alters or commits, or runs a function or view body
    /// that does: triggers, constraints, defaults, rules, policies and index
    /// expressions run on real values, of any relation, and may quote them
    /// in messages.
    pub writes: bool,
    /// Join of every non-Clean taint used other than as a whole output column.
    pub computes: Taint,
    /// A sink that received `Unknown`: blocks if the statement turns out to be
    /// proxy-relevant.
    pub deferred: Option<String>,
    /// FETCH, MOVE or EXECUTE: rows of a statement analyzed earlier, or never.
    pub runs_earlier: bool,
    /// Later statements may resolve names differently.
    pub changes_resolution: bool,
    /// DDL whose expressions are stored or evaluated over rows.
    pub stores_expressions: bool,
    /// The statement returns rows, so its top level gets result masks.
    pub returns_rows: bool,
    /// `SELECT ... INTO`: the table receives the outputs.
    pub select_into: bool,
    /// DECLARE CURSOR or PREPARE, and the prepared name.
    pub portal: Option<(&'static str, Option<String>)>,
    /// Proxy-masked columns read, for sink messages.
    pub proxy_labels: BTreeSet<String>,
    /// A type that isn't built in that values are converted to outside a
    /// cast, e.g. by `RETURNING` of a JSON function.
    pub user_type: Option<String>,
}

impl StatementState {
    /// `Unknown` taints are `Computed` in a statement that reads or names
    /// proxy-masked columns, and `Clean` otherwise.
    fn relevant(&self) -> bool {
        self.reads_proxies || self.touches_proxies
    }
}

/// An ORDER BY, DISTINCT ON or GROUP BY name that matches an output column.
#[derive(Debug, Clone, Copy)]
pub(super) enum OutputRef {
    /// ORDER BY and DISTINCT ON: Postgres prefers the output.
    Prefer(Taint),
    /// GROUP BY: Postgres prefers the input column, if there's one.
    Fallback(Taint),
    /// A set operation's ORDER BY: only outputs are visible.
    Only(Taint),
}

/// One entry of an output list.
pub(super) enum Slot {
    Column(OutputColumn),
    /// `*`, `q.*` or `(expr).*`: one part per item it covers.
    Star(Vec<Part>),
}

/// What a star covers of one item.
pub(super) enum Part {
    /// An unmasked catalog relation at the top level, expanded into its
    /// columns when the outputs need masks.
    Relation { refname: String, names: Vec<String> },
    /// Columns from our own analysis: positions are exact.
    Derived { refname: String, outputs: Outputs },
    /// Columns of unknown number, carrying at most `taint`.
    Unknown { refname: String, taint: Taint },
}

impl Part {
    /// The most any of its columns carries.
    fn bound(&self) -> Taint {
        match self {
            Part::Relation { .. } => Taint::Clean,
            Part::Derived { outputs, .. } => outputs.bound(),
            Part::Unknown { taint, .. } => *taint,
        }
    }
}

impl<'c, 'mem> Masker<'c, 'mem> {
    /// Record a reference's or call's taint in the expression being
    /// transformed, and as a computing use unless it's a whole output column.
    pub(super) fn note(&mut self, taint: Taint, passthrough: bool) {
        self.note_from(taint, passthrough, true);
    }

    /// `note`, saying whether the taint comes from a source (anything but the
    /// recursive CTE being analyzed, or a value noted before).
    pub(super) fn note_from(&mut self, taint: Taint, passthrough: bool, source: bool) {
        if taint.is_clean() {
            return;
        }
        self.taint = self.taint.join(taint);
        if !passthrough {
            self.state.computes = self.state.computes.join(taint);
        }
        if source {
            self.sources += 1;
        }
    }

    /// Transform with a fresh accumulator. Returns the taint, which also
    /// joins the enclosing expression's.
    pub(super) fn scoped(&mut self, f: impl FnOnce(&mut Self)) -> Taint {
        let saved = std::mem::take(&mut self.taint);
        f(self);
        let taint = std::mem::replace(&mut self.taint, saved);
        self.taint = self.taint.join(taint);
        taint
    }

    /// A proxy-masked column is read. References to it aren't rewritten, so
    /// it isn't one of the `masked` columns.
    pub(super) fn read_proxy(&mut self, label: String) {
        self.state.reads_proxies = true;
        self.state.proxy_labels.insert(label);
    }

    /// Every proxy-masked column of a relation is read, e.g. as a whole row.
    pub(super) fn read_proxies_of(&mut self, relation: &'c Relation) {
        for column in &relation.columns {
            if let Some(target) = self.mask_target(relation, &column.name, "")
                && target.proxy().is_some()
            {
                self.read_proxy(target.label);
            }
        }
    }

    /// Is this the top level of a statement that returns rows, whose outputs
    /// become result masks?
    pub(super) fn result_level(&self) -> bool {
        self.state.returns_rows && self.frames.len() == 1 && self.depth == 0
    }

    /// Transform a SELECT or RETURNING list, one slot per target. Stars aren't
    /// transformed; `(expr).*` is, and has unknown width. A bare column
    /// reference passes its taint through; anything else is computed from it.
    pub(super) fn output_slots<'r>(
        &mut self,
        targets: impl IntoIterator<Item = nodes::ResTargetMut<'mem, 'r>>,
        top: bool,
    ) -> Vec<Slot> {
        let mut slots = vec![];
        for target in targets {
            let star = match target.val() {
                Node::ColumnRef(column) if fields(column).1 => Some(self.star_parts(column, top)),
                Node::A_Indirection(indirection)
                    if matches!(
                        indirection.indirection().iter().next_back(),
                        Some(Node::A_Star(_))
                    ) =>
                {
                    Some(
                        self.indirection_star(indirection)
                            .and_then(|name| find_item(&self.frames, name))
                            .map(|item| vec![self.item_part(item, top)])
                            .unwrap_or_default(),
                    )
                }
                _ => None,
            };
            match star {
                Some(parts) if !parts.is_empty() => {
                    self.count_sources(&parts);
                    slots.push(Slot::Star(parts));
                    continue;
                }
                // `(expr).*`: the expression's columns, of unknown number.
                Some(_) => {
                    let taint = self.scoped(|masker| masker.transform_res_target(target));
                    slots.push(Slot::Star(vec![Part::Unknown {
                        refname: String::new(),
                        taint: taint.computed(),
                    }]));
                    continue;
                }
                None => (),
            }

            let passthrough = match target.val() {
                Node::ColumnRef(column) => {
                    self.passthrough.insert(address(column));
                    true
                }
                _ => false,
            };
            let name = target
                .name()
                .map(str::to_owned)
                .or_else(|| self.pinned_name(target.val()));
            let taint = self.scoped(|masker| masker.transform_res_target(target));
            slots.push(Slot::Column(OutputColumn {
                name,
                taint: if passthrough { taint } else { taint.computed() },
            }));
        }
        slots
    }

    /// The parts of `*` or `q.*`.
    fn star_parts(&self, column: &nodes::ColumnRef, top: bool) -> Vec<Part> {
        let (names, _) = fields(column);
        if let Some(qualifier) = names.last() {
            return vec![find_item(&self.frames, qualifier).map_or_else(
                || Part::Unknown {
                    refname: (*qualifier).to_owned(),
                    taint: Taint::Unknown,
                },
                |item| self.item_part(item, top),
            )];
        }
        let Some(frame) = self.frames.last() else {
            return vec![];
        };
        let items = frame.items.iter().filter(|item| !item.qualified_only);
        if frame.merging_join {
            // USING/NATURAL columns come first, once: positions are unknown.
            let taint = items
                .map(|item| self.item_part(item, false).bound())
                .reduce(Taint::union)
                .unwrap_or_default();
            return vec![Part::Unknown {
                refname: String::new(),
                taint,
            }];
        }
        items.map(|item| self.item_part(item, top)).collect()
    }

    /// What a star covers of an item.
    fn item_part(&self, item: &Item<'c>, top: bool) -> Part {
        let refname = item.refname.clone();
        match &item.kind {
            // Only left as a star when it can't be expanded: blocked elsewhere.
            ItemKind::Relation { relation, .. } if self.is_masked_relation(relation) => {
                Part::Unknown {
                    refname,
                    taint: if self.has_proxy_masks(relation) {
                        Taint::Computed
                    } else {
                        Taint::Clean
                    },
                }
            }
            ItemKind::Relation { names, .. } if top && self.expands_catalog_stars() => {
                Part::Relation {
                    refname,
                    names: names.clone(),
                }
            }
            // The catalog may be stale: its width can't be trusted.
            ItemKind::Relation { .. } => Part::Unknown {
                refname,
                taint: Taint::Clean,
            },
            ItemKind::Derived(outputs) if item.unknown_width => Part::Unknown {
                refname,
                taint: outputs.bound(),
            },
            ItemKind::Derived(outputs) => Part::Derived {
                refname,
                outputs: outputs.clone(),
            },
        }
    }

    /// Stars carry their items' taints without noting them; count them as
    /// sources unless they come from the recursive CTE being analyzed.
    fn count_sources(&mut self, parts: &[Part]) {
        let current = self.ctes.last().map(String::as_str);
        let pending = |refname: &str| {
            find_item(&self.frames, refname).is_some_and(|item| item.pending_in(current))
        };
        let sources = parts
            .iter()
            .filter(|part| {
                let refname = match part {
                    Part::Relation { refname, .. }
                    | Part::Derived { refname, .. }
                    | Part::Unknown { refname, .. } => refname,
                };
                !part.bound().is_clean() && !pending(refname)
            })
            .count();
        self.sources += sources as u64;
    }

    /// Stars over catalog relations can be expanded into exact columns.
    pub(super) fn expands_catalog_stars(&self) -> bool {
        self.ctx.profile.proxies && self.ctx.catalog.full
    }

    /// A level's outputs from its slots, and whether its catalog relation
    /// stars must be expanded so masks land on the right columns.
    pub(super) fn level_outputs(&self, slots: &[Slot], top: bool) -> (Outputs, bool) {
        let tainted = slots.iter().any(|slot| match slot {
            Slot::Column(column) => !column.taint.is_clean(),
            Slot::Star(parts) => parts.iter().any(|part| !part.bound().is_clean()),
        });
        let expand = top
            && tainted
            && slots.iter().any(|slot| {
                matches!(slot, Slot::Star(parts) if parts.iter().any(|part| matches!(part, Part::Relation { .. })))
            });

        let mut outputs = Outputs::default();
        for slot in slots {
            match slot {
                Slot::Column(column) => outputs.push(column.clone()),
                Slot::Star(parts) => {
                    for part in parts {
                        match part {
                            Part::Relation { names, .. } => {
                                for name in names {
                                    outputs.push(OutputColumn {
                                        name: Some(name.clone()),
                                        taint: Taint::Clean,
                                    });
                                }
                            }
                            Part::Derived {
                                outputs: derived, ..
                            } => {
                                for column in &derived.columns {
                                    outputs.push(column.clone());
                                }
                                if let Some(rest) = derived.rest {
                                    outputs.open(rest);
                                }
                            }
                            Part::Unknown { taint, .. } => outputs.open(*taint),
                        }
                    }
                }
            }
        }
        (outputs, expand)
    }

    /// The output list with catalog relation stars expanded into
    /// `refname.column`. `targets` is the list `output_slots` transformed.
    pub(super) fn expand_slots(
        &mut self,
        targets: &[&nodes::ResTarget],
        slots: &[Slot],
    ) -> Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>> {
        let mut expanded = vec![];
        for (target, slot) in targets.iter().zip(slots) {
            let parts = match slot {
                Slot::Star(parts)
                    if parts
                        .iter()
                        .any(|part| matches!(part, Part::Relation { .. })) =>
                {
                    parts
                }
                _ => {
                    expanded.push(self.mem.make_unique(*target));
                    continue;
                }
            };
            for part in parts {
                match part {
                    Part::Relation { refname, names } => expanded.extend(
                        names
                            .iter()
                            .map(|name| self.star_target(refname, Some(name))),
                    ),
                    Part::Derived { refname, .. } | Part::Unknown { refname, .. }
                        if !refname.is_empty() =>
                    {
                        expanded.push(self.star_target(refname, None))
                    }
                    Part::Derived { .. } | Part::Unknown { .. } => {
                        self.block("can't expand * over a subquery without an alias");
                        return None;
                    }
                }
            }
        }
        self.changed = true;
        Some(expanded)
    }

    /// Start transforming a query level whose outputs the caller takes.
    pub(super) fn expect_outputs(&mut self) {
        self.check_unclaimed();
        self.outputs = None;
    }

    /// The outputs of the query level that finished last.
    pub(super) fn take_outputs(&mut self) -> Option<Outputs> {
        self.unclaimed = false;
        self.outputs.take()
    }

    /// Set the outputs of the query level being finished.
    pub(super) fn set_outputs(&mut self, outputs: Option<Outputs>) {
        self.check_unclaimed();
        self.outputs = outputs;
    }

    /// A nested query level whose outputs nobody took is embedded in a node
    /// this doesn't follow: what its values flow into is unknown.
    fn check_unclaimed(&mut self) {
        if std::mem::take(&mut self.unclaimed) {
            self.block("a subquery is used in a way the plugin can't analyze");
        }
    }

    /// Record ORDER BY, DISTINCT ON and GROUP BY items that name output
    /// columns: they read the output, not an input column.
    pub(super) fn record_output_refs<'n>(
        &mut self,
        outputs: &Outputs,
        items: impl IntoIterator<Item = Node<'n>>,
        kind: fn(Taint) -> OutputRef,
    ) {
        for item in items {
            let Node::ColumnRef(column) = item else {
                continue;
            };
            let (names, star) = fields(column);
            let [name] = names.as_slice() else {
                continue;
            };
            if star {
                continue;
            }
            let taint = outputs
                .columns
                .iter()
                .filter(|output| output.name.as_deref() == Some(*name))
                .map(|output| output.taint)
                .reduce(Taint::union);
            if let Some(taint) = taint {
                self.output_refs.insert(address(column), kind(taint));
            }
        }
    }

    /// Block if a value with this taint would reach a place PgDog can't mask.
    /// `Unknown` blocks only if the statement turns out to be proxy-relevant.
    pub(super) fn check_taint(&mut self, taint: Taint, reason: impl FnOnce(&Self) -> String) {
        match taint {
            Taint::Clean => (),
            Taint::Unknown => {
                if self.state.deferred.is_none() {
                    self.state.deferred = Some(reason(self));
                }
            }
            Taint::Proxy { .. } | Taint::Computed => {
                let reason = reason(self);
                self.block(reason);
            }
        }
    }

    /// Values would move where PgDog can't mask them, if the statement runs:
    /// a plain EXPLAIN only plans it.
    pub(super) fn sink(&mut self, taint: Taint, what: &str) {
        if self.executing {
            self.sink_when_planned(taint, what);
        }
    }

    /// Values would move where PgDog can't mask them, even if the statement
    /// is only planned. In a function body analyzed for where its
    /// parameters go, records that they can reach a sink instead: any
    /// non-Clean value may carry them.
    pub(super) fn sink_when_planned(&mut self, taint: Taint, what: &str) {
        self.sink_with(taint, |masker| {
            let (columns, labels) = (masker.sink_columns(), &masker.state.proxy_labels);
            if labels.is_empty() {
                format!("{what} would move values of {columns} where PgDog can't mask them")
            } else {
                format!(
                    "{what} would move values of {columns} ({}) where PgDog can't mask them",
                    labels.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            }
        });
    }

    /// `sink_when_planned`, saying why with `reason`.
    pub(super) fn sink_with(&mut self, taint: Taint, reason: impl FnOnce(&Self) -> String) {
        if let Some(params) = &mut self.params {
            params.sinks |= !taint.is_clean();
            return;
        }
        if self.outputs_only {
            return;
        }
        self.check_taint(taint, reason);
    }

    /// The outputs of the query level that finished last would move where
    /// PgDog can't mask them.
    pub(super) fn sink_outputs(&mut self, what: &str) {
        let taint = self.take_outputs().map_or(Taint::Unknown, |o| o.bound());
        self.sink(taint, what);
    }

    /// End a top-level statement: deferred sinks, statement rules, result
    /// masks at position `result` and error redaction.
    pub(in crate::analyzer) fn finish_statement(&mut self, result: usize) {
        if self.state.select_into {
            // On a set operation, the table receives the whole result.
            let taint = self.outputs.as_ref().map_or(Taint::Unknown, Outputs::bound);
            self.sink(taint, "SELECT INTO");
        }

        let state = std::mem::take(&mut self.state);
        let outputs = self.take_outputs();
        let relevant = state.relevant();
        let computes = state.computes.resolve(relevant);

        if state.stores_expressions && (state.reads_proxies || !computes.is_clean()) {
            self.block("DDL expressions would store values computed from proxy-masked columns");
        }
        if let Some(data_type) = &state.user_type
            && (state.reads_proxies || !computes.is_clean())
        {
            self.block(format!(
                "{data_type} isn't a built-in type: converting values to it can run a user-defined cast function or domain check, so statements that read {} can only use it in casts of other values",
                self.sink_columns()
            ));
        }
        if relevant && let Some(reason) = state.deferred {
            self.block(reason);
        }
        if let Some((what, name)) = state.portal {
            let tainted = outputs
                .as_ref()
                .is_some_and(|outputs| !outputs.bound().resolve(relevant).is_clean());
            // PgDog attaches masks to statements it saw prepared: rows read
            // later through the cursor or the prepared name get none.
            if self.ctx.profile.proxies && (tainted || !computes.is_clean()) {
                self.block(format!(
                    "{what} can't use proxy-masked columns: rows read through it later can't be masked; run the statement directly"
                ));
            } else if let Some(name) = name {
                self.prepared.insert(name);
            }
        }
        // Statements of view and function bodies return no rows to PgDog.
        if state.returns_rows && self.depth == 0 {
            self.result_masks(result, outputs.unwrap_or_else(Outputs::unknown), relevant);
        }

        self.results.redact_errors |= !computes.is_clean()
            || (state.writes && self.ctx.profile.proxies)
            || (state.runs_earlier && self.ctx.profile.proxies);
        self.reads_proxies |= state.reads_proxies;
        // Only the statements after it resolve names differently.
        self.path_changed |= state.changes_resolution;
    }

    /// Result masks for a row-returning statement's outputs.
    fn result_masks(&mut self, result: usize, outputs: Outputs, relevant: bool) {
        if outputs
            .rest
            .is_some_and(|rest| !rest.resolve(relevant).is_clean())
        {
            self.block(CANT_PLACE);
            return;
        }
        let Ok(result) = u16::try_from(result) else {
            self.block("too many statements to mask their results");
            return;
        };
        for (position, column) in outputs.columns.iter().enumerate() {
            let mask = match column.taint.resolve(relevant) {
                Taint::Clean => continue,
                Taint::Proxy {
                    proxy,
                    type_oid: type_oid @ 1..,
                } => ResultMask::Proxy { proxy, type_oid },
                // Computed, or a proxy column of unknown type: fail closed.
                _ => ResultMask::Null,
            };
            let Ok(column) = u16::try_from(position) else {
                self.block("too many result columns to mask");
                return;
            };
            self.results.columns.push(ResultColumn {
                result,
                column,
                mask,
            });
        }
    }
}

#[cfg(test)]
mod test {
    use pg_raw_parse::make;

    use super::*;
    use crate::analyzer::Context;
    use crate::analyzer::test::{CONFIG, catalog};
    use crate::config::Config;
    use crate::profile::{Assignments, Policies};

    /// A nested query level whose outputs no caller takes sits in a node the
    /// masker doesn't follow: what its values flow into is unknown.
    #[test]
    fn test_unclaimed_outputs_block() {
        let policies = Policies::new(Config::from_toml(CONFIG).unwrap()).unwrap();
        let catalog = catalog();
        let assignments = Assignments::new(&policies, "db", &catalog);
        let profile = policies.profile("anonymous", "db");
        let ctx = Context {
            catalog: &catalog,
            assignments: &assignments,
            policies: &policies,
            profile: &profile,
            search_path: vec!["public".into()],
        };
        make::try_owned(|mem| {
            let mut masker = Masker::new(mem, &ctx);
            masker.with_frame(|masker| {
                masker.with_frame(|masker| masker.set_outputs(Some(Outputs::default())));
                masker.set_outputs(Some(Outputs::default()));
            });
            assert!(
                masker
                    .blocked
                    .is_some_and(|reason| reason.contains("subquery"))
            );

            let mut masker = Masker::new(mem, &ctx);
            masker.with_frame(|masker| {
                masker.expect_outputs();
                masker.with_frame(|masker| masker.set_outputs(Some(Outputs::default())));
                masker.take_outputs();
                masker.set_outputs(Some(Outputs::default()));
            });
            assert!(masker.blocked.is_none());
            mem.parse("SELECT 1")
        })
        .unwrap();
    }
}
