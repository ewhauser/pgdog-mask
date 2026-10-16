//! Column lineage of views and materialized views that are treated like tables:
//! which base column each output column passes through, or which columns it's
//! computed from.
//!
//! View definitions come from `pg_get_viewdef` with every name schema-qualified,
//! so relations are resolved without a `search_path`.
use std::collections::BTreeSet;
use std::ops::ControlFlow;

use pg_raw_parse::{
    Node, nodes,
    raw::SetOperation,
    walk::{Recurse, walk_manual},
};

use crate::catalog::{Catalog, Relation, RelationKind};

/// A column of a table or materialized view.
pub type BaseColumn = (String, String, String);

/// Views nested deeper than this are treated as unknown.
const MAX_DEPTH: usize = 16;

/// Where an output column's values come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lineage {
    /// The value of a base column, unchanged.
    Column(BaseColumn),
    /// Computed from these base columns.
    Derived(BTreeSet<BaseColumn>),
    /// Computed from columns that couldn't be determined.
    Unknown,
}

impl Lineage {
    /// Combine the lineage of values that end up in the same column.
    fn merge(self, other: Lineage) -> Lineage {
        match (self, other) {
            (Lineage::Unknown, _) | (_, Lineage::Unknown) => Lineage::Unknown,
            (Lineage::Column(a), Lineage::Column(b)) if a == b => Lineage::Column(a),
            (a, b) => {
                let mut inputs = a.inputs();
                inputs.extend(b.inputs());
                Lineage::Derived(inputs)
            }
        }
    }

    fn inputs(self) -> BTreeSet<BaseColumn> {
        match self {
            Lineage::Column(column) => BTreeSet::from([column]),
            Lineage::Derived(inputs) => inputs,
            Lineage::Unknown => BTreeSet::new(),
        }
    }
}

/// Lineage of each column of a view or materialized view, in column order.
/// `None` if the definition is missing or can't be analyzed.
pub fn view_lineage(catalog: &Catalog, relation: &Relation) -> Option<Vec<Lineage>> {
    lineage(catalog, relation, 0)
}

fn lineage(catalog: &Catalog, relation: &Relation, depth: usize) -> Option<Vec<Lineage>> {
    if depth > MAX_DEPTH {
        return None;
    }
    let definition = relation.definition.as_deref()?;
    let parsed = pg_raw_parse::parse(definition).ok()?.into_inner();
    let mut stmts = parsed.iter();
    let (Some(stmt), None) = (stmts.next(), stmts.next()) else {
        return None;
    };
    let Node::SelectStmt(select) = stmt.stmt() else {
        return None;
    };
    let resolver = Resolver { catalog, depth };
    let outputs = resolver.select(select, &[])?;
    (outputs.len() == relation.columns.len()).then_some(outputs)
}

/// Relations a view reads, directly or through other views.
pub fn view_relations(catalog: &Catalog, relation: &Relation) -> Vec<(String, String)> {
    let mut found = vec![];
    collect_relations(catalog, relation, 0, &mut found);
    found
}

fn collect_relations(
    catalog: &Catalog,
    relation: &Relation,
    depth: usize,
    found: &mut Vec<(String, String)>,
) {
    let Some(definition) = relation.definition.as_deref() else {
        return;
    };
    let Ok(parsed) = pg_raw_parse::parse(definition) else {
        return;
    };
    let parsed = parsed.into_inner();
    for stmt in parsed.iter() {
        walk_manual(stmt.into(), |node| {
            if let Node::RangeVar(range_var) = node
                && let (Some(schema), Some(name)) = (range_var.schemaname(), range_var.relname())
                && let Some(base) = catalog.get(schema, name)
            {
                let key = (base.schema.clone(), base.name.clone());
                if !found.contains(&key) {
                    found.push(key);
                    if base.kind == RelationKind::View && depth < MAX_DEPTH {
                        collect_relations(catalog, base, depth + 1, found);
                    }
                }
            }
            Recurse::yes::<()>()
        });
    }
}

/// A FROM item.
struct Item {
    refname: String,
    /// Visible column names and their lineage; `None` if unknown.
    columns: Option<Vec<(String, Lineage)>>,
}

/// A CTE visible in a query.
struct Cte {
    name: String,
    columns: Option<Vec<(String, Lineage)>>,
}

struct Resolver<'a> {
    catalog: &'a Catalog,
    depth: usize,
}

impl Resolver<'_> {
    /// Lineage of a query's output columns.
    fn select(&self, select: &nodes::SelectStmt, outer_ctes: &[Cte]) -> Option<Vec<Lineage>> {
        let mut ctes: Vec<Cte> = vec![];
        if let Some(with) = select.with_clause() {
            for cte in with.ctes().iter() {
                let columns = match cte.ctequery() {
                    Node::SelectStmt(query) if !with.recursive => {
                        let visible: Vec<_> = ctes.iter().chain(outer_ctes).collect();
                        self.select_with(query, &visible)
                            .map(|lineage| named(query, &names(cte.aliascolnames()), lineage))
                    }
                    _ => None,
                };
                ctes.push(Cte {
                    name: cte.ctename().unwrap_or("").to_owned(),
                    columns: columns.flatten(),
                });
            }
        }
        let visible: Vec<&Cte> = ctes.iter().chain(outer_ctes).collect();
        self.select_with(select, &visible)
    }

    fn select_with(&self, select: &nodes::SelectStmt, ctes: &[&Cte]) -> Option<Vec<Lineage>> {
        if select.op != SetOperation::SETOP_NONE {
            let left = self.select_with(select.larg()?, ctes)?;
            let right = self.select_with(select.rarg()?, ctes)?;
            if left.len() != right.len() {
                return None;
            }
            return Some(
                left.into_iter()
                    .zip(right)
                    .map(|(l, r)| l.merge(r))
                    .collect(),
            );
        }

        if !select.values_lists().is_empty() {
            let first = select.values_lists().iter().next()?.as_node_list()?;
            return Some(
                first
                    .iter()
                    .map(|_| Lineage::Derived(BTreeSet::new()))
                    .collect(),
            );
        }

        let mut items = vec![];
        for from in select.from_clause().iter() {
            self.add_from_item(from, ctes, &mut items);
        }

        select
            .target_list()
            .iter()
            .map(|target| match target.val() {
                Node::ColumnRef(column) if is_star(column) => None,
                val => Some(self.expr(val, &items)),
            })
            .collect()
    }

    fn add_from_item(&self, node: Node<'_>, ctes: &[&Cte], items: &mut Vec<Item>) {
        match node {
            Node::RangeVar(range_var) => {
                let Some(name) = range_var.relname() else {
                    return;
                };
                let alias = range_var.alias();
                let refname = alias.and_then(|a| a.aliasname()).unwrap_or(name).to_owned();
                let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();

                let columns = match range_var.schemaname() {
                    None => ctes
                        .iter()
                        .find(|cte| cte.name == name)
                        .and_then(|cte| cte.columns.clone()),
                    Some(schema) => self
                        .catalog
                        .get(schema, name)
                        .and_then(|relation| self.relation_columns(relation)),
                };
                items.push(Item {
                    refname,
                    columns: columns.map(|columns| rename(columns, &aliases)),
                });
            }
            Node::JoinExpr(join) => {
                // Joins with an alias hide their inputs; their columns are unknown.
                if join.alias().is_some() || join.join_using_alias().is_some() {
                    items.push(Item {
                        refname: join
                            .alias()
                            .and_then(|a| a.aliasname())
                            .unwrap_or("")
                            .to_owned(),
                        columns: None,
                    });
                    return;
                }
                self.add_from_item(join.larg(), ctes, items);
                self.add_from_item(join.rarg(), ctes, items);
            }
            Node::RangeSubselect(subselect) => {
                let alias = subselect.alias();
                let aliases = alias.map(|a| names(a.colnames())).unwrap_or_default();
                let columns = match subselect.subquery() {
                    Node::SelectStmt(query) => self
                        .select_with(query, ctes)
                        .and_then(|lineage| named(query, &aliases, lineage)),
                    _ => None,
                };
                items.push(Item {
                    refname: alias.and_then(|a| a.aliasname()).unwrap_or("").to_owned(),
                    columns,
                });
            }
            Node::RangeFunction(function) => items.push(Item {
                refname: function
                    .alias()
                    .and_then(|a| a.aliasname())
                    .unwrap_or("")
                    .to_owned(),
                columns: None,
            }),
            _ => items.push(Item {
                refname: String::new(),
                columns: None,
            }),
        }
    }

    /// Columns of a relation with their lineage. Tables and materialized views
    /// are sources; views are followed to their sources.
    fn relation_columns(&self, relation: &Relation) -> Option<Vec<(String, Lineage)>> {
        let lineage = match relation.kind {
            RelationKind::View => lineage(self.catalog, relation, self.depth + 1)?,
            _ => relation
                .columns
                .iter()
                .map(|column| {
                    Lineage::Column((
                        relation.schema.clone(),
                        relation.name.clone(),
                        column.name.clone(),
                    ))
                })
                .collect(),
        };
        Some(
            relation
                .columns
                .iter()
                .map(|column| column.name.clone())
                .zip(lineage)
                .collect(),
        )
    }

    /// Lineage of an expression.
    fn expr(&self, node: Node<'_>, items: &[Item]) -> Lineage {
        if let Node::ColumnRef(column) = node {
            return self.column_ref(column, items);
        }

        let mut lineage = Lineage::Derived(BTreeSet::new());
        let unknown = walk_manual(node, |node| match node {
            // Subqueries have their own scope.
            Node::SubLink(_) | Node::SelectStmt(_) => ControlFlow::Break(()),
            Node::ColumnRef(column) => {
                lineage = std::mem::replace(&mut lineage, Lineage::Unknown)
                    .merge(self.column_ref(column, items));
                Recurse::no()
            }
            _ => Recurse::yes(),
        });
        match (unknown, lineage) {
            (Some(()), _) => Lineage::Unknown,
            // A single input that went through an expression is derived, not passed through.
            (None, Lineage::Column(column)) => Lineage::Derived(BTreeSet::from([column])),
            (None, lineage) => lineage,
        }
    }

    fn column_ref(&self, column: &nodes::ColumnRef, items: &[Item]) -> Lineage {
        if is_star(column) {
            return Lineage::Unknown;
        }
        let fields: Vec<&str> = column.fields().iter().filter_map(|f| f.as_str()).collect();
        let (qualifier, name) = match fields.as_slice() {
            [name] => (None, *name),
            [.., qualifier, name] => (Some(*qualifier), *name),
            [] => return Lineage::Unknown,
        };

        let mut candidates = items
            .iter()
            .filter(|item| qualifier.is_none_or(|q| item.refname == q));
        let found = candidates.find_map(|item| match &item.columns {
            Some(columns) => columns
                .iter()
                .find(|(column, _)| column == name)
                .map(|(_, lineage)| Some(lineage.clone())),
            // An item with unknown columns may provide this one.
            None => Some(None),
        });
        found.flatten().unwrap_or(Lineage::Unknown)
    }
}

/// Name a query's output columns: column aliases first, then target names.
fn named(
    query: &nodes::SelectStmt,
    aliases: &[String],
    lineage: Vec<Lineage>,
) -> Option<Vec<(String, Lineage)>> {
    let mut select = query;
    while select.op != SetOperation::SETOP_NONE {
        select = select.larg()?;
    }
    let targets: Vec<Option<String>> = select
        .target_list()
        .iter()
        .map(|target| {
            target
                .name()
                .map(str::to_owned)
                .or_else(|| match target.val() {
                    Node::ColumnRef(column) => column
                        .fields()
                        .iter()
                        .next_back()
                        .and_then(|f| f.as_str())
                        .map(str::to_owned),
                    _ => None,
                })
        })
        .collect();
    Some(
        lineage
            .into_iter()
            .enumerate()
            .map(|(i, lineage)| {
                let name = aliases
                    .get(i)
                    .cloned()
                    .or_else(|| targets.get(i).cloned().flatten())
                    .unwrap_or_else(|| "?column?".into());
                (name, lineage)
            })
            .collect(),
    )
}

fn rename(columns: Vec<(String, Lineage)>, aliases: &[String]) -> Vec<(String, Lineage)> {
    columns
        .into_iter()
        .enumerate()
        .map(|(i, (name, lineage))| (aliases.get(i).cloned().unwrap_or(name), lineage))
        .collect()
}

fn names(list: &pg_raw_parse::list::NodeList) -> Vec<String> {
    list.iter()
        .filter_map(|node| node.as_str().map(str::to_owned))
        .collect()
}

fn is_star(column: &nodes::ColumnRef) -> bool {
    column
        .fields()
        .iter()
        .any(|field| matches!(field, Node::A_Star(_)))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::catalog::Column;

    fn base(table: &str, column: &str) -> BaseColumn {
        ("public".into(), table.into(), column.into())
    }

    fn view(name: &str, columns: &[&str], definition: &str) -> Relation {
        let mut relation = Relation::new(
            "public",
            name,
            RelationKind::View,
            columns.iter().map(|c| Column::new(c, "text")).collect(),
        );
        relation.definition = Some(definition.into());
        relation
    }

    fn catalog(views: Vec<Relation>) -> Catalog {
        let mut relations = vec![Relation::new(
            "public",
            "users",
            RelationKind::Table,
            vec![
                Column::new("id", "bigint"),
                Column::new("ssn", "text"),
                Column::new("name", "text"),
            ],
        )];
        relations.extend(views);
        Catalog::new(vec![], relations)
    }

    #[test]
    fn test_view_lineage() {
        let v = view(
            "v",
            &["id", "ssn", "masked", "n"],
            " SELECT u.id, u.ssn, upper(u.ssn) AS masked, length(u.name) AS n FROM public.users u WHERE u.id > 0;",
        );
        let catalog = catalog(vec![v.clone()]);
        assert_eq!(
            view_lineage(&catalog, &v).unwrap(),
            [
                Lineage::Column(base("users", "id")),
                Lineage::Column(base("users", "ssn")),
                Lineage::Derived(BTreeSet::from([base("users", "ssn")])),
                Lineage::Derived(BTreeSet::from([base("users", "name")])),
            ]
        );
    }

    #[test]
    fn test_nested_views_and_subqueries() {
        let inner = view(
            "inner_v",
            &["key", "secret"],
            " SELECT users.id AS key, users.ssn AS secret FROM public.users;",
        );
        let outer = view(
            "outer_v",
            &["secret", "both", "sub"],
            " SELECT s.secret, s.secret || s.key AS both, (SELECT 1) AS sub FROM (SELECT inner_v.key, inner_v.secret FROM public.inner_v) s;",
        );
        let catalog = catalog(vec![inner, outer.clone()]);
        assert_eq!(
            view_lineage(&catalog, &outer).unwrap(),
            [
                Lineage::Column(base("users", "ssn")),
                Lineage::Derived(BTreeSet::from([base("users", "id"), base("users", "ssn")])),
                Lineage::Unknown,
            ]
        );
        let relations = view_relations(&catalog, &outer);
        assert!(relations.contains(&("public".into(), "users".into())));
        assert!(relations.contains(&("public".into(), "inner_v".into())));
    }

    #[test]
    fn test_set_operations_and_ctes() {
        let v = view(
            "v",
            &["a", "b"],
            " WITH c AS (SELECT users.ssn, users.name FROM public.users) SELECT c.ssn AS a, c.ssn AS b FROM c UNION ALL SELECT users.ssn, users.name FROM public.users;",
        );
        let catalog = catalog(vec![v.clone()]);
        assert_eq!(
            view_lineage(&catalog, &v).unwrap(),
            [
                Lineage::Column(base("users", "ssn")),
                Lineage::Derived(BTreeSet::from([
                    base("users", "name"),
                    base("users", "ssn")
                ])),
            ]
        );
    }

    #[test]
    fn test_unknown() {
        let v = view("v", &["x"], " SELECT f.x FROM public.some_function() f(x);");
        let catalog = catalog(vec![v.clone()]);
        assert_eq!(view_lineage(&catalog, &v).unwrap(), [Lineage::Unknown]);

        let mut missing = v.clone();
        missing.definition = None;
        assert!(view_lineage(&catalog, &missing).is_none());
    }
}
