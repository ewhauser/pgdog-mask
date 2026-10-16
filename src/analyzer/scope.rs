//! Name resolution scopes.
use crate::catalog::Relation;

/// A FROM item.
#[derive(Debug)]
pub(super) struct Item<'c> {
    /// Alias, or relation name.
    pub refname: String,
    pub kind: ItemKind<'c>,
}

#[derive(Debug)]
pub(super) enum ItemKind<'c> {
    /// A relation from the catalog. `names` are the visible column names,
    /// in the same order as `relation.columns` (aliases can rename them).
    Relation {
        relation: &'c Relation,
        names: Vec<String>,
    },
    /// A subquery, CTE, function or catalog relation. Its output columns,
    /// if known, are never masked: masks are applied where the data is read.
    Derived(Option<Vec<String>>),
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
        }
    }

    /// Is the column visible in this item? `None` if unknown.
    fn has_column(&self, name: &str) -> Option<bool> {
        match &self.kind {
            ItemKind::Relation { names, .. } => Some(names.iter().any(|n| n == name)),
            ItemKind::Derived(Some(names)) => Some(names.iter().any(|n| n == name)),
            ItemKind::Derived(None) => None,
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
    pub columns: Option<Vec<String>>,
}

/// Names visible in one query level.
#[derive(Debug, Default)]
pub(super) struct Frame<'c> {
    pub items: Vec<Item<'c>>,
    pub ctes: Vec<Cte>,
    /// A join with USING or NATURAL merges columns, so `*` can't be
    /// expanded item by item.
    pub merging_join: bool,
}

/// A column reference resolved to a relation column.
#[derive(Debug, Clone, Copy)]
pub(super) struct ResolvedColumn<'c, 'f> {
    pub relation: &'c Relation,
    pub column: &'c str,
    /// Range table name to qualify sibling columns with.
    pub refname: &'f str,
}

/// Resolve a column reference the way Postgres does: innermost query level first.
pub(super) fn resolve_column<'c, 'f>(
    frames: &'f [Frame<'c>],
    fields: &[&str],
) -> Option<ResolvedColumn<'c, 'f>> {
    match fields {
        [name] => {
            for frame in frames.iter().rev() {
                let mut found = None;
                for item in &frame.items {
                    if item.has_column(name) == Some(true) {
                        found = Some(item);
                        break;
                    }
                }
                if let Some(item) = found {
                    return item
                        .relation_column(name)
                        .map(|(relation, column)| ResolvedColumn {
                            relation,
                            column,
                            refname: &item.refname,
                        });
                }
                // Not found at this level, or only possibly provided by an item
                // with unknown columns. Postgres would look in outer levels next;
                // so do we, conservatively.
            }
            None
        }
        [qualifier, name] => {
            let item = find_item(frames, qualifier)?;
            item.relation_column(name)
                .map(|(relation, column)| ResolvedColumn {
                    relation,
                    column,
                    refname: &item.refname,
                })
        }
        [.., schema, table, name] => {
            for frame in frames.iter().rev() {
                for item in &frame.items {
                    if let ItemKind::Relation { relation, .. } = &item.kind
                        && relation.schema == *schema
                        && relation.name == *table
                        && item.refname == *table
                    {
                        return item.relation_column(name).map(|(relation, column)| {
                            ResolvedColumn {
                                relation,
                                column,
                                refname: &item.refname,
                            }
                        });
                    }
                }
            }
            None
        }
        [] => None,
    }
}

/// Find a FROM item by name, innermost query level first.
pub(super) fn find_item<'c, 'f>(frames: &'f [Frame<'c>], refname: &str) -> Option<&'f Item<'c>> {
    frames
        .iter()
        .rev()
        .find_map(|frame| frame.items.iter().find(|item| item.refname == refname))
}

/// Find a CTE by name, innermost query level first.
pub(super) fn find_cte<'f>(frames: &'f [Frame<'_>], name: &str) -> Option<&'f Cte> {
    frames
        .iter()
        .rev()
        .find_map(|frame| frame.ctes.iter().find(|cte| cte.name == name))
}
