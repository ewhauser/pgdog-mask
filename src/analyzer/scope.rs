//! Name resolution scopes.
use std::ops::Range;

use pg_raw_parse::{Node, raw::SetOperation};

use super::shape::is_placeholder;
use super::taint::{OutputColumn, Outputs, Taint};
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
        }
    }

    pub fn derived(refname: String, outputs: Outputs) -> Self {
        Self {
            refname,
            kind: ItemKind::Derived(outputs),
            qualified_only: false,
        }
    }

    /// Is the column visible in this item? `None` if unknown.
    fn has_column(&self, name: &str) -> Option<bool> {
        match &self.kind {
            ItemKind::Relation { names, .. } => Some(names.iter().any(|n| n == name)),
            ItemKind::Derived(outputs) => outputs.has_column(name),
        }
    }

    /// The relation column behind a visible column name.
    fn relation_column(&self, name: &str) -> Option<(&'c Relation, &'c str)> {
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
    Derived(Taint),
}

/// A column reference, resolved the way Postgres does.
#[derive(Debug, Default)]
pub(super) struct Resolution<'c> {
    /// Relation columns providing the name at the binding level, first one
    /// first. `columns[0]` drives SQL masks.
    pub columns: Vec<ResolvedColumn<'c>>,
    /// Some item certainly provides the name. If none does, the name may be a
    /// whole-row reference, a placeholder, a parameter, a column of an item
    /// with unknown columns, or an error.
    pub certain: bool,
    /// `q.N` / `s.q.N` where `q` is a visible item and `N` isn't certainly
    /// one of its columns.
    pub attribute_of: Option<WholeRowOf<'c>>,
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

/// Resolve a column reference the way Postgres does: innermost query level first.
pub(super) fn resolve<'c>(frames: &[Frame<'c>], fields: &[&str]) -> Resolution<'c> {
    match fields {
        [name] => {
            for level in (0..frames.len()).rev() {
                let mut resolution = Resolution::default();
                for (_, item) in
                    visible_items(frames, level).filter(|(_, item)| !item.qualified_only)
                {
                    if item.has_column(name) == Some(true) {
                        resolution.certain = true;
                        resolution.columns.extend(item.relation_column(name).map(
                            |(relation, column)| ResolvedColumn {
                                relation,
                                column,
                                refname: item.refname.clone(),
                            },
                        ));
                    }
                }
                if resolution.certain {
                    return resolution;
                }
                // Not found at this level, or only possibly provided by an item
                // with unknown columns. Postgres would look in outer levels next;
                // so do we, conservatively.
            }
            Resolution::default()
        }
        [qualifier, name] => find_item(frames, qualifier)
            .map(|item| item_column(item, name))
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
                        Some(item_column(item, name))
                    }
                    _ => None,
                })
            })
            .unwrap_or_default(),
        [] => Resolution::default(),
    }
}

/// A column of a known item, by name.
fn item_column<'c>(item: &Item<'c>, name: &str) -> Resolution<'c> {
    if let Some((relation, column)) = item.relation_column(name) {
        return Resolution {
            columns: vec![ResolvedColumn {
                relation,
                column,
                refname: item.refname.clone(),
            }],
            certain: true,
            attribute_of: None,
        };
    }
    let certain = Resolution {
        certain: true,
        ..Default::default()
    };
    match &item.kind {
        ItemKind::Relation { .. } if SYSTEM_COLUMNS.contains(&name) => certain,
        ItemKind::Relation { relation, .. } => Resolution {
            attribute_of: Some(WholeRowOf::Relation(relation)),
            ..Default::default()
        },
        ItemKind::Derived(outputs) if outputs.has_column(name) == Some(true) => certain,
        ItemKind::Derived(outputs) => Resolution {
            attribute_of: Some(WholeRowOf::Derived(outputs.bound())),
            ..Default::default()
        },
    }
}

/// The relation column a reference reads, if any.
pub(super) fn resolve_column<'c>(
    frames: &[Frame<'c>],
    fields: &[&str],
) -> Option<ResolvedColumn<'c>> {
    resolve(frames, fields).columns.into_iter().next()
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
