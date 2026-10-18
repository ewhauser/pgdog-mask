//! FROM items: relations resolved against the catalog, aliased joins,
//! table functions and DML targets, and the scope rules of FROM lists.
use pg_raw_parse::{nodes, transform::Transform};

use super::{Masker, RESOLUTION_CHANGED, Verdict, names};
use crate::analyzer::rules;
use crate::analyzer::scope::{Item, ItemKind, find_cte, unknown_columns};
use crate::analyzer::taint::{Lookup, OutputColumn, Outputs, Taint};
use crate::catalog::Relation;
use crate::config::OnUnresolved;

impl<'c, 'mem> Masker<'c, 'mem> {
    /// The relation a name refers to. Postgres resolves an unqualified name
    /// with the session's search_path, which may not be the one PgDog
    /// follows: PgDog misses some changes to it (a `SET` inside a
    /// multi-statement query, a pooled connection another client changed),
    /// and `$user` follows the role. So every relation of that name, in any
    /// schema, must read like the one it resolves to here; otherwise the name
    /// must be qualified.
    pub(super) fn resolve_relation(
        &mut self,
        schema: Option<&str>,
        name: &str,
    ) -> Option<&'c Relation> {
        let catalog = self.ctx.catalog;
        if schema.is_some() {
            return catalog.resolve(schema, name, &[]);
        }
        let named = catalog.relations_named(name);
        let resolved = catalog
            .resolve(None, name, &self.ctx.search_path)
            .or(named.first())?;
        if named.len() < 2 {
            return Some(resolved);
        }
        let key = (resolved.schema.clone(), resolved.name.clone());
        let memoized = self.memo.borrow().namesakes.get(&key).cloned();
        let different = match memoized {
            Some(different) => different,
            None => {
                let different = named
                    .iter()
                    .find(|other| !self.reads_like(resolved, other))
                    .map(Relation::qualified_name);
                self.memo
                    .borrow_mut()
                    .namesakes
                    .insert(key, different.clone());
                different
            }
        };
        if let Some(other) = different {
            self.block(format!(
                "\"{name}\" may refer to {} or to {other}, which read differently for masked users; qualify it with its schema",
                resolved.qualified_name(),
            ));
        }
        Some(resolved)
    }

    /// A FROM item naming a relation.
    pub(super) fn add_range_var(&mut self, range_var: &nodes::RangeVar) {
        let Some(name) = range_var.relname() else {
            return;
        };
        let schema = range_var.schemaname();
        let alias = range_var.alias();
        let refname = alias.and_then(|a| a.aliasname()).unwrap_or(name).to_owned();
        let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();

        let item = if let Some(cte) = schema
            .is_none()
            .then(|| find_cte(&self.frames, name))
            .flatten()
        {
            let mut item = Item::derived(refname, cte.outputs.clone().renamed(&aliases));
            item.pending = cte.pending.then(|| cte.name.clone());
            item
        } else if self.path_changed {
            self.block(RESOLUTION_CHANGED);
            Item::derived(refname, unknown_columns())
        } else if let Some(relation) = self.resolve_relation(schema, name) {
            match self.view_verdict(relation) {
                Verdict::Safe => (),
                // Views are inlined in FROM lists; anywhere else they can't be.
                Verdict::Inline => self.block(format!(
                    "view {} reads masked columns and can only be read in a FROM list",
                    relation.qualified_name()
                )),
                Verdict::Blocked(reason) => self.block(reason),
            }
            if self.is_masked_relation(relation) {
                self.touched = true;
            }
            if self.has_proxy_masks(relation) {
                self.state.touches_proxies = true;
            }
            // Aliases map to columns by position, which a stale catalog can
            // get wrong; names can't be.
            if !aliases.is_empty()
                && let Some(first) = self.first_masked_column(relation)
                && aliases.len() > first
            {
                self.block(format!(
                    "the column aliases of {refname} cover masked column {}.{}; alias columns in the select list instead",
                    relation.qualified_name(),
                    relation.columns[first].name
                ));
            }
            Item::relation(refname, relation, &aliases)
        } else if let Some(result) = rules::check_catalog_relation(schema, name) {
            if let Err(reason) = result {
                self.block(reason);
            }
            Item::derived(refname, unknown_columns())
        } else {
            if self.ctx.policies.config.general.on_unresolved == OnUnresolved::Block {
                self.block(format!(
                    "relation \"{name}\" is not in the catalog, so its columns can't be checked"
                ));
            }
            // Nothing is known about its columns.
            Item::derived(refname, Outputs::unknown())
        };

        if let Some(frame) = self.frames.last_mut() {
            frame.items.push(item);
        }
    }

    /// Transform a FROM list, where views are inlined.
    pub(super) fn transform_from_list<'mutref>(
        &mut self,
        list: pg_raw_parse::list_mut::NodeListMut<'mem, 'mutref, pg_raw_parse::list::NodeList>,
    ) {
        let from = std::mem::replace(&mut self.from, true);
        self.transform_list(list);
        self.from = from;
    }

    /// Add a DML target relation to the current frame. Returns its item's
    /// position. A write anywhere in the statement (a data-modifying CTE, a
    /// function body), to any relation, runs triggers and constraints.
    pub(super) fn add_target(&mut self, relation: Option<&nodes::RangeVar>) -> Option<usize> {
        let range_var = relation?;
        self.state.writes = true;
        self.check_view_write(range_var);
        let position = self.frames.last()?.items.len();
        self.add_range_var(range_var);
        Some(position)
    }

    /// Transform the FROM list of UPDATE or DELETE, which can't see the
    /// target, not even from LATERAL items.
    pub(super) fn transform_dml_from_list<'mutref>(
        &mut self,
        list: pg_raw_parse::list_mut::NodeListMut<'mem, 'mutref, pg_raw_parse::list::NodeList>,
        target: Option<usize>,
    ) {
        let start = target.map_or(0, |target| target + 1);
        let saved = self
            .frames
            .last_mut()
            .map(|frame| frame.visible.replace(start..usize::MAX));
        self.transform_from_list(list);
        if let (Some(frame), Some(saved)) = (self.frames.last_mut(), saved) {
            frame.visible = saved;
        }
    }

    /// What the merged columns of a USING or NATURAL join over `items` of
    /// this level carry.
    pub(super) fn merged_taint(
        &self,
        items: std::ops::Range<usize>,
        using: &[String],
        natural: bool,
    ) -> Taint {
        let Some(items) = self.frames.last().and_then(|frame| frame.items.get(items)) else {
            return Taint::Clean;
        };
        let mut taint = Taint::Clean;
        for item in items {
            let column = |name: &str| match &item.kind {
                ItemKind::Relation { .. } => item
                    .relation_column(name)
                    .and_then(|(relation, column)| self.mask_target(relation, column, ""))
                    .and_then(|target| target.proxy())
                    .unwrap_or_default(),
                ItemKind::Derived(outputs) => match outputs.lookup(name) {
                    Lookup::Certain(taint) | Lookup::Possible(taint) => taint,
                    Lookup::Absent => Taint::Clean,
                },
            };
            if natural {
                // Every column with a matching name: any of them.
                taint = taint.join(match &item.kind {
                    ItemKind::Relation { relation, .. } if self.has_proxy_masks(relation) => {
                        Taint::Computed
                    }
                    ItemKind::Relation { .. } => Taint::Clean,
                    ItemKind::Derived(outputs) => outputs.bound().computed(),
                });
            }
            for name in using {
                taint = taint.join(column(name));
            }
        }
        taint
    }

    /// `(...) AS j (cols)`: the join's `items` of this level are only
    /// reachable through `j`. Its columns are the merged ones, then each
    /// item's others, renamed by `cols`. Positions are unknown when merged
    /// columns may come first in an order this can't tell (`reordered`: a
    /// NATURAL join, or a merging join inside), or when a merged name may be
    /// an item's column whose name isn't certain.
    pub(super) fn alias_join(
        &mut self,
        items: std::ops::Range<usize>,
        refname: String,
        aliases: &[String],
        using: &[String],
        reordered: bool,
    ) {
        let Some(inner) = self
            .frames
            .last()
            .and_then(|frame| frame.items.get(items.clone()))
        else {
            return;
        };
        let inner: Vec<&Item<'c>> = inner.iter().filter(|item| !item.qualified_only).collect();
        let uncertain = !using.is_empty()
            && inner.iter().any(|item| {
                matches!(&item.kind, ItemKind::Derived(outputs)
                    if outputs.rest.is_some() || outputs.columns.iter().any(|c| c.name.is_none()))
            });
        let mut outputs = Outputs::default();
        if reordered || uncertain {
            let bound = inner
                .iter()
                .map(|item| match &item.kind {
                    ItemKind::Relation { .. } => Taint::Clean,
                    ItemKind::Derived(outputs) => outputs.bound(),
                })
                .fold(Taint::Clean, Taint::union);
            outputs.open(bound);
        } else {
            for name in using {
                outputs.push(OutputColumn {
                    name: Some(name.clone()),
                    taint: self.merged_taint(items.clone(), std::slice::from_ref(name), false),
                });
            }
            let merged = |name: &Option<String>| name.as_ref().is_some_and(|n| using.contains(n));
            for item in &inner {
                match &item.kind {
                    ItemKind::Relation { names, .. } => {
                        for name in names.iter().map(|name| Some(name.clone())) {
                            if !merged(&name) {
                                outputs.push(OutputColumn {
                                    name,
                                    taint: Taint::Clean,
                                });
                            }
                        }
                    }
                    ItemKind::Derived(derived) => {
                        for column in &derived.columns {
                            if !merged(&column.name) {
                                outputs.push(column.clone());
                            }
                        }
                        if let Some(rest) = derived.rest {
                            outputs.open(rest);
                        }
                    }
                }
            }
        }
        // Catalog relations' and functions' widths can't be trusted for `j.*`.
        let unknown_width = inner
            .iter()
            .any(|item| item.unknown_width || matches!(item.kind, ItemKind::Relation { .. }));
        let pending = inner.iter().find_map(|item| item.pending.clone());

        let mut item = Item::derived(refname, outputs.renamed(aliases));
        item.unknown_width = unknown_width;
        item.pending = pending;
        if let Some(frame) = self.frames.last_mut() {
            frame.items.truncate(items.start);
            frame.items.push(item);
        }
    }

    /// Push an item for a table function (XMLTABLE, JSON_TABLE) whose columns
    /// are defined in the call: names, and whether they're FOR ORDINALITY.
    /// Every other column is computed from the arguments.
    pub(super) fn add_table_function(
        &mut self,
        refname: String,
        columns: Option<Vec<(String, bool)>>,
        aliases: &[String],
        args: Taint,
    ) {
        let taint = args.computed();
        let outputs = match columns {
            Some(columns) => Outputs {
                columns: columns
                    .into_iter()
                    .map(|(name, ordinality)| OutputColumn {
                        name: Some(name),
                        taint: if ordinality { Taint::Clean } else { taint },
                    })
                    .collect(),
                rest: None,
            },
            None => Outputs {
                columns: vec![],
                rest: Some(taint),
            },
        };
        if let Some(frame) = self.frames.last_mut() {
            frame
                .items
                .push(Item::derived(refname, outputs.renamed(aliases)));
        }
    }
}
