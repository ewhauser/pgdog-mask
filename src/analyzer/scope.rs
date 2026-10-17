//! Name resolution scopes.
use std::collections::HashMap;
use std::ops::Range;

use pg_raw_parse::{Node, raw::SetOperation};

use super::shape::is_placeholder;
use super::taint::{Lookup, OutputColumn, Outputs, Taint};
use crate::catalog::Relation;

/// Columns every table has besides its own, which qualified names can read.
const SYSTEM_COLUMNS: &[&str] = &["ctid", "xmin", "xmax", "cmin", "cmax", "tableoid"];

/// A FROM item.
#[derive(Debug, Clone)]
pub(super) struct Item<'c> {
    /// Alias, or relation name.
    pub refname: String,
    pub kind: ItemKind<'c>,
    /// Only visible to qualified references, qualified stars and whole-row
    /// references: PG18 RETURNING `old` and `new`.
    pub qualified_only: bool,
    /// The recursive CTE this item reads while that CTE is still being
    /// analyzed.
    pub pending: Option<String>,
    /// `*` over it has unknown width, even when its column names are known:
    /// a function in FROM, whose result type can change, or an aliased join
    /// over catalog relations, whose catalog may be stale.
    pub unknown_width: bool,
}

#[derive(Debug, Clone)]
pub(super) enum ItemKind<'c> {
    /// A relation from the catalog. `names` are the visible column names,
    /// in the same order as `relation.columns` (aliases can rename them).
    Relation {
        relation: &'c Relation,
        names: Vec<String>,
    },
    /// A subquery, CTE, VALUES, function, table function, catalog or
    /// unresolved relation, or `excluded`. Its output columns are never masked:
    /// masks are applied where the data is read.
    Derived(Outputs),
}

impl<'c> Item<'c> {
    pub fn relation(refname: String, relation: &'c Relation, aliases: &[String]) -> Self {
        let names = relation
            .columns
            .iter()
            .enumerate()
            .map(|(i, column)| {
                aliases
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| column.name.clone())
            })
            .collect();
        Self {
            refname,
            kind: ItemKind::Relation { relation, names },
            qualified_only: false,
            pending: None,
            unknown_width: false,
        }
    }

    pub fn derived(refname: String, outputs: Outputs) -> Self {
        Self {
            refname,
            kind: ItemKind::Derived(outputs),
            qualified_only: false,
            pending: None,
            unknown_width: false,
        }
    }

    /// Does this item belong to the recursive CTE being analyzed? Its
    /// columns aren't known yet, and reading them isn't a taint source.
    pub(super) fn pending_in(&self, current_cte: Option<&str>) -> bool {
        self.pending.is_some() && self.pending.as_deref() == current_cte
    }

    /// The relation column behind a visible column name.
    pub fn relation_column(&self, name: &str) -> Option<(&'c Relation, &'c str)> {
        match &self.kind {
            ItemKind::Relation { relation, names } => names
                .iter()
                .position(|n| n == name)
                .map(|i| (*relation, relation.columns[i].name.as_str())),
            ItemKind::Derived(_) => None,
        }
    }
}

/// A common table expression visible in a frame.
#[derive(Debug)]
pub(super) struct Cte {
    pub name: String,
    pub outputs: Outputs,
    /// A recursive CTE still being analyzed: its outputs are placeholders.
    pub pending: bool,
}

/// Names visible in one query level.
#[derive(Debug, Default)]
pub(super) struct Frame<'c> {
    pub items: Vec<Item<'c>>,
    pub ctes: Vec<Cte>,
    /// A join with USING or NATURAL merges columns, so `*` can't be
    /// expanded item by item.
    pub merging_join: bool,
    /// A non-LATERAL subquery in this level's FROM list is being analyzed:
    /// this level's items are invisible to it.
    pub lateral_only: bool,
    /// Only these items of this level are visible: a JOIN's ON clause, or the
    /// FROM list of UPDATE and DELETE, which can't see the target.
    pub visible: Option<Range<usize>>,
    /// Named windows of this level, and the taint of their definitions.
    pub windows: HashMap<String, Taint>,
}

/// A relation column providing a name.
#[derive(Debug, Clone)]
pub(super) struct ResolvedColumn<'c> {
    pub relation: &'c Relation,
    pub column: &'c str,
    /// Range table name to qualify sibling columns with.
    pub refname: String,
}

/// What a qualified reference that misses a visible item's columns calls
/// `N()` on: Postgres reads `q.N` as `N(q)`.
#[derive(Debug, Clone, Copy)]
pub(super) enum WholeRowOf<'c> {
    Relation(&'c Relation),
    Derived {
        /// The most any of the item's columns carries.
        taint: Taint,
        /// The item is a recursive CTE still being analyzed.
        pending: bool,
    },
}

/// A column reference, resolved the way Postgres does.
#[derive(Debug, Default)]
pub(super) struct Resolution<'c> {
    /// Relation columns providing the name at the binding level, first one
    /// first. `columns[0]` drives SQL masks; all of them contribute taint
    /// (USING/NATURAL merges).
    pub columns: Vec<ResolvedColumn<'c>>,
    /// Union of the taints of derived columns providing the name at the
    /// binding level, and of the non-Clean columns with uncertain names at
    /// levels passed on the way out; `None` if there are none.
    pub derived: Option<Taint>,
    /// Some item certainly provides the name. If none does, the name may be a
    /// whole-row reference, a placeholder, a parameter, a column of an item
    /// with unknown columns, or an error.
    pub certain: bool,
    /// Every contribution comes from the recursive CTE being analyzed, so
    /// reading it isn't a taint source.
    pub pending_only: bool,
    /// `q.N` / `s.q.N` where `q` is a visible item and `N` isn't certainly
    /// one of its columns.
    pub attribute_of: Option<WholeRowOf<'c>>,
}

/// Contributions to a resolution's derived taint.
#[derive(Default)]
struct Contributions {
    taint: Option<Taint>,
    /// Some contribution comes from the recursive CTE being analyzed.
    pending: bool,
    /// Some contribution comes from anything else.
    other: bool,
}

impl Contributions {
    fn add(&mut self, taint: Taint, pending: bool) {
        self.taint = Some(self.taint.map_or(taint, |t| t.union(taint)));
        if pending {
            self.pending = true;
        } else {
            self.other = true;
        }
    }

    fn merge(&mut self, other: Contributions) {
        if let Some(taint) = other.taint {
            self.taint = Some(self.taint.map_or(taint, |t| t.union(taint)));
        }
        self.pending |= other.pending;
        self.other |= other.other;
    }

    fn pending_only(&self) -> bool {
        self.pending && !self.other
    }
}

/// Items of `frames[level]` visible from the innermost frame, with their
/// positions in the frame.
pub(super) fn visible_items<'c, 'f>(
    frames: &'f [Frame<'c>],
    level: usize,
) -> impl Iterator<Item = (usize, &'f Item<'c>)> {
    let frame = frames.get(level);
    // A non-LATERAL subquery in FROM sees outer levels, not its siblings.
    let hidden = frame.is_some_and(|frame| frame.lateral_only) && level + 1 < frames.len();
    frame.filter(|_| !hidden).into_iter().flat_map(|frame| {
        frame
            .items
            .iter()
            .enumerate()
            .filter(|(i, _)| frame.visible.as_ref().is_none_or(|range| range.contains(i)))
    })
}

/// Resolve a column reference the way Postgres does: innermost query level
/// first. `current_cte` is the CTE being analyzed, whose pending columns
/// aren't taint sources.
pub(super) fn resolve<'c>(
    frames: &[Frame<'c>],
    fields: &[&str],
    current_cte: Option<&str>,
) -> Resolution<'c> {
    match fields {
        [name] => {
            // Columns that may provide the name at levels passed on the way out.
            let mut passed = Contributions::default();
            for level in (0..frames.len()).rev() {
                let mut columns = vec![];
                let mut found = Contributions::default();
                let mut possible = Contributions::default();
                for (_, item) in
                    visible_items(frames, level).filter(|(_, item)| !item.qualified_only)
                {
                    match &item.kind {
                        ItemKind::Relation { .. } => {
                            if let Some((relation, column)) = item.relation_column(name) {
                                columns.push(ResolvedColumn {
                                    relation,
                                    column,
                                    refname: item.refname.clone(),
                                });
                                found.other = true;
                            }
                        }
                        ItemKind::Derived(outputs) => match outputs.lookup(name) {
                            Lookup::Certain(taint) => {
                                found.add(taint, item.pending_in(current_cte))
                            }
                            // Clean possibilities only over-mask if ignored.
                            Lookup::Possible(taint) if !taint.is_clean() => {
                                possible.add(taint, item.pending_in(current_cte))
                            }
                            Lookup::Possible(_) | Lookup::Absent => (),
                        },
                    }
                }
                if !columns.is_empty() || found.taint.is_some() {
                    // Items that only may provide the name at this level would
                    // make Postgres report an ambiguity if they did.
                    found.merge(passed);
                    return Resolution {
                        columns,
                        derived: found.taint,
                        certain: true,
                        pending_only: found.pending_only(),
                        attribute_of: None,
                    };
                }
                // Not found at this level, or only possibly provided by an item
                // with uncertain columns. Postgres would look in outer levels
                // next; so do we, conservatively.
                passed.merge(possible);
            }
            Resolution {
                derived: passed.taint,
                pending_only: passed.pending_only(),
                ..Default::default()
            }
        }
        [qualifier, name] => find_item(frames, qualifier)
            .map(|item| item_column(item, name, current_cte))
            .unwrap_or_default(),
        [.., schema, table, name] => (0..frames.len())
            .rev()
            .find_map(|level| {
                visible_items(frames, level).find_map(|(_, item)| match &item.kind {
                    ItemKind::Relation { relation, .. }
                        if relation.schema == *schema
                            && relation.name == *table
                            && item.refname == *table =>
                    {
                        Some(item_column(item, name, current_cte))
                    }
                    _ => None,
                })
            })
            .unwrap_or_default(),
        [] => Resolution::default(),
    }
}

/// A column of a known item, by name.
fn item_column<'c>(item: &Item<'c>, name: &str, current_cte: Option<&str>) -> Resolution<'c> {
    if let Some((relation, column)) = item.relation_column(name) {
        return Resolution {
            columns: vec![ResolvedColumn {
                relation,
                column,
                refname: item.refname.clone(),
            }],
            certain: true,
            ..Default::default()
        };
    }
    let pending_only = item.pending_in(current_cte);
    match &item.kind {
        ItemKind::Relation { .. } if SYSTEM_COLUMNS.contains(&name) => Resolution {
            certain: true,
            ..Default::default()
        },
        ItemKind::Relation { relation, .. } => Resolution {
            attribute_of: Some(WholeRowOf::Relation(relation)),
            ..Default::default()
        },
        ItemKind::Derived(outputs) => match outputs.lookup(name) {
            Lookup::Certain(taint) => Resolution {
                derived: Some(taint),
                certain: true,
                pending_only,
                ..Default::default()
            },
            // A name the item may not have: Postgres would call `N(q)`.
            Lookup::Possible(_) | Lookup::Absent => Resolution {
                pending_only,
                attribute_of: Some(WholeRowOf::Derived {
                    taint: outputs.bound(),
                    pending: item.pending.is_some(),
                }),
                ..Default::default()
            },
        },
    }
}

/// The relation column a reference reads, if any.
pub(super) fn resolve_column<'c>(
    frames: &[Frame<'c>],
    fields: &[&str],
) -> Option<ResolvedColumn<'c>> {
    resolve(frames, fields, None).columns.into_iter().next()
}

/// Find a visible FROM item by name, innermost query level first.
pub(super) fn find_item<'c, 'f>(frames: &'f [Frame<'c>], refname: &str) -> Option<&'f Item<'c>> {
    (0..frames.len()).rev().find_map(|level| {
        visible_items(frames, level)
            .map(|(_, item)| item)
            .find(|item| item.refname == refname)
    })
}

/// Find a CTE by name, innermost query level first. CTEs stay visible where
/// FROM items are hidden.
pub(super) fn find_cte<'f>(frames: &'f [Frame<'_>], name: &str) -> Option<&'f Cte> {
    frames
        .iter()
        .rev()
        .find_map(|frame| frame.ctes.iter().find(|cte| cte.name == name))
}

/// Columns of unknown number and names.
pub(super) fn unknown_columns() -> Outputs {
    Outputs {
        columns: vec![],
        rest: Some(Taint::Clean),
    }
}

/// The name Postgres gives an output column, when certain: a column
/// reference's last field (also under casts), or a function call's name.
pub(super) fn exact_name(node: Node<'_>) -> Option<String> {
    match node {
        Node::ColumnRef(column) => {
            let mut last = None;
            for field in column.fields().iter() {
                match field {
                    Node::A_Star(_) => return None,
                    field => last = field.as_str(),
                }
            }
            last.filter(|name| !is_placeholder(name)).map(str::to_owned)
        }
        Node::TypeCast(cast) => exact_name(cast.arg()),
        Node::FuncCall(call) => call
            .funcname()
            .iter()
            .next_back()
            .and_then(|name| name.as_str())
            .map(str::to_owned),
        _ => None,
    }
}

/// Output columns of a subquery or CTE, before it's analyzed.
pub(super) fn derived_outputs(node: Node<'_>) -> Outputs {
    let Node::SelectStmt(select) = node else {
        return unknown_columns();
    };
    if select.op != SetOperation::SETOP_NONE {
        // Set operations take their names from the leftmost branch.
        return select
            .larg()
            .map(|larg| derived_outputs(Node::SelectStmt(larg)))
            .unwrap_or_else(unknown_columns);
    }
    if let Some(row) = select.values_lists().iter().next() {
        let width = row.as_node_list().map_or(0, |row| row.iter().count());
        return Outputs {
            columns: (1..=width)
                .map(|i| OutputColumn {
                    name: Some(format!("column{i}")),
                    taint: Taint::Clean,
                })
                .collect(),
            rest: None,
        };
    }

    let mut outputs = Outputs::default();
    for target in select.target_list().iter() {
        match (target.name(), target.val()) {
            (Some(name), _) => outputs.push(OutputColumn {
                name: Some(name.to_owned()),
                taint: Taint::Clean,
            }),
            (None, Node::ColumnRef(column))
                if column
                    .fields()
                    .iter()
                    .any(|field| matches!(field, Node::A_Star(_))) =>
            {
                outputs.open(Taint::Clean)
            }
            (None, val) => outputs.push(OutputColumn {
                name: exact_name(val),
                taint: Taint::Clean,
            }),
        }
    }
    outputs
}
