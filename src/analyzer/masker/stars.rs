//! Stars over relations with masked columns are expanded into their columns
//! before the target list is transformed, so each column can be masked.
use pg_raw_parse::{Node, make::Unique, nodes};

use super::{Expansion, Masker, fields};
use crate::analyzer::scope::{Item, ItemKind, find_item, resolve};

impl<'c, 'mem> Masker<'c, 'mem> {
    /// `qualifier.column`, or `qualifier.*`, as a target list entry.
    pub(super) fn star_target(
        &self,
        qualifier: &str,
        column: Option<&str>,
    ) -> Unique<'mem, &'mem nodes::ResTarget> {
        let mem = self.mem;
        let last = match column {
            Some(column) => mem.make_string(Some(column)).uncast(),
            None => mem.make_node::<nodes::A_Star>().uncast(),
        };
        let fields = [mem.make_string(Some(qualifier)).uncast(), last];
        let column = mem.make_column_ref(mem.make_list(&fields));
        mem.make_res_target(None, mem.empty(), column.uncast())
    }

    /// How `*` covers an item. With `all`, relations without masked columns
    /// are expanded too.
    fn expansion(&self, item: &Item<'_>, all: bool) -> Expansion {
        match &item.kind {
            ItemKind::Relation { relation, names } if all || self.is_masked_relation(relation) => {
                Expansion::Columns {
                    refname: item.refname.clone(),
                    names: names.clone(),
                }
            }
            _ => Expansion::Star(item.refname.clone()),
        }
    }

    /// Expand stars over every catalog relation: in nested levels, for users
    /// with proxy masks, so the width of every derived item is a function of
    /// the SQL text rather than of a catalog that may be stale.
    fn expands_all_stars(&self) -> bool {
        self.expands_catalog_stars() && (self.frames.len() > 1 || self.depth > 0)
    }

    /// The targets replacing `*` for one item.
    fn expand(
        &mut self,
        expansion: Expansion,
    ) -> Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>> {
        match expansion {
            Expansion::Columns { refname, names } => Some(
                names
                    .iter()
                    .map(|name| self.star_target(&refname, Some(name)))
                    .collect(),
            ),
            Expansion::Star(refname) if !refname.is_empty() => {
                Some(vec![self.star_target(&refname, None)])
            }
            Expansion::Star(_) => {
                self.block("can't expand * over a subquery without an alias");
                None
            }
        }
    }

    pub(super) fn item_is_masked(&self, item: &Item<'_>) -> bool {
        matches!(&item.kind, ItemKind::Relation { relation, .. } if self.is_masked_relation(relation))
    }

    /// The columns replacing `qualifier.*`, if it covers masked columns. The
    /// item can be in an outer query level.
    fn expand_qualified(
        &mut self,
        qualifier: &str,
        all: bool,
    ) -> Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>> {
        match self.expansion(find_item(&self.frames, qualifier)?, all) {
            expansion @ Expansion::Columns { .. } => self.expand(expansion),
            Expansion::Star(_) => None,
        }
    }

    /// The item `(name).*` or `(name.*).*` expands, if `name` is an item and
    /// not a column. Postgres reads `(name)` as a column first.
    pub(super) fn indirection_star<'n>(
        &self,
        indirection: &'n nodes::A_Indirection,
    ) -> Option<&'n str> {
        let mut path = indirection.indirection().iter();
        let (Some(Node::A_Star(_)), None) = (path.next(), path.next()) else {
            return None;
        };
        let Node::ColumnRef(column) = indirection.arg() else {
            return None;
        };
        match fields(column) {
            (names, false) => match names.as_slice() {
                [name] if !resolve(&self.frames, &[name], None).certain => Some(name),
                _ => None,
            },
            (names, true) => match names.as_slice() {
                [name] => Some(name),
                _ => None,
            },
        }
    }

    /// Target list with `*` and `alias.*` replaced by explicit columns, if they
    /// cover masked columns.
    pub(super) fn expand_stars(
        &mut self,
        targets: &[&nodes::ResTarget],
    ) -> Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>> {
        let star = |target: &&nodes::ResTarget| match target.val() {
            Node::ColumnRef(column) => fields(column).1,
            Node::A_Indirection(_) => true,
            _ => false,
        };
        if !targets.iter().any(star) {
            return None;
        }
        let all = self.expands_all_stars();
        let frame = self.frames.last()?;
        // A bare `*` covers every item of this level, but not RETURNING `old`
        // and `new`.
        let visible = frame.items.iter().filter(|item| !item.qualified_only);
        let masked = visible.clone().any(|item| self.item_is_masked(item));
        let items: Vec<Expansion> = visible.map(|item| self.expansion(item, all)).collect();
        let expands = items
            .iter()
            .any(|item| matches!(item, Expansion::Columns { .. }));
        let merging = frame.merging_join;

        let mut plans: Vec<Option<Vec<Unique<'mem, &'mem nodes::ResTarget>>>> = vec![];
        let mut needed = false;

        for target in targets {
            let plan = match target.val() {
                Node::ColumnRef(column) => match fields(column) {
                    (names, true) if names.is_empty() => {
                        // USING/NATURAL columns come first, once: a bare `*`
                        // can't be expanded item by item.
                        if merging && masked {
                            self.block("can't expand * across a JOIN with USING or NATURAL over masked columns; list the columns");
                            return None;
                        }
                        if expands && !merging {
                            let parts: Option<Vec<_>> = items
                                .iter()
                                .cloned()
                                .map(|item| self.expand(item))
                                .collect();
                            parts.map(|p| p.into_iter().flatten().collect())
                        } else {
                            None
                        }
                    }
                    (names, true) => {
                        self.expand_qualified(names.last().copied().unwrap_or(""), all)
                    }
                    _ => None,
                },
                Node::A_Indirection(indirection) => self
                    .indirection_star(indirection)
                    .and_then(|qualifier| self.expand_qualified(qualifier, all)),
                _ => None,
            };
            needed |= plan.is_some();
            plans.push(plan);
        }

        if !needed {
            return None;
        }

        let mut expanded: Vec<Unique<'mem, &'mem nodes::ResTarget>> = vec![];
        for (target, plan) in targets.iter().zip(plans) {
            match plan {
                None => expanded.push(self.mem.make_unique(*target)),
                Some(columns) => expanded.extend(columns),
            }
        }

        self.changed = true;
        Some(expanded)
    }
}
