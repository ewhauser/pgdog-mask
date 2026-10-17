//! Column references: SQL masks rewrite them, proxy masks never do, and
//! what each reference carries is noted for the results.
use std::collections::HashSet;
use std::sync::LazyLock;

use pg_raw_parse::{
    Node, NodeMut,
    make::Unique,
    nodes,
    raw::A_Expr_Kind,
    transform::{self, Assignable, Transform},
};

use super::{
    DerivedPolicy, MaskTarget, Masker, OutputRef, TargetKind, Verdict, address, fields, ident,
};
use crate::analyzer::Context;
use crate::analyzer::scope::{
    ItemKind, Resolution, ResolvedColumn, WholeRowOf, find_item, resolve, resolve_column,
};
use crate::analyzer::shape::is_placeholder;
use crate::analyzer::taint::Taint;
use crate::catalog::Relation;
use crate::mask::{SearchOp, VALUE, castable};

/// A column's policy and argument columns, and the masked policies it's
/// computed from.
type ColumnMasking<'c> = (Option<(usize, &'c [String])>, Vec<usize>);

/// Raw searches of a mask without a SQL part.
static NO_RAW_SEARCH: LazyLock<HashSet<SearchOp>> = LazyLock::new(HashSet::new);

/// Functions that only normalize a value, allowed around a column in raw searches.
const NORMALIZERS: &[&str] = &["lower", "upper", "btrim", "ltrim", "rtrim"];

impl<'c, 'mem> Masker<'c, 'mem> {
    /// The mask for a relation column, if it's masked for this user.
    pub(super) fn mask_target(
        &self,
        relation: &'c Relation,
        column: &str,
        refname: &str,
    ) -> Option<MaskTarget<'c>> {
        let ctx: &'c Context<'c> = self.ctx;
        let assignment = ctx
            .assignments
            .column(&relation.schema, &relation.name, column)?;
        let mask = &ctx.profile.masks[assignment.policy];
        if !mask.is_masked() {
            return None;
        }
        let policy = &ctx.policies.policies[assignment.policy].policy;
        let catalog_column = relation.column(column);
        // A masked column has either a proxy mask or a SQL mask.
        let kind = match (mask.proxy(), mask.sql()) {
            (Some(proxy), _) => TargetKind::Proxy {
                proxy,
                type_oid: catalog_column.map(|c| c.type_oid).unwrap_or(0),
            },
            (None, sql) => TargetKind::Sql {
                // Fail closed: a mask with neither reads NULL wherever it's
                // rewritten.
                template: sql.map_or("NULL", |sql| sql.template),
                raw_search: sql.map_or(&*NO_RAW_SEARCH, |sql| sql.raw_search),
                cast: catalog_column
                    .map(|c| c.data_type.as_str())
                    .filter(|t| castable(t))
                    .unwrap_or(&policy.data_type),
                arguments: &assignment.arguments,
            },
        };

        Some(MaskTarget {
            policy: assignment.policy,
            qualifier: refname.to_owned(),
            label: format!("{}.{}.{}", relation.schema, relation.name, column),
            kind,
        })
    }

    /// The position of a relation's first column that is masked for this
    /// user, or computed from columns that are.
    pub(super) fn first_masked_column(&self, relation: &Relation) -> Option<usize> {
        let (assignments, masks) = (self.ctx.assignments, &self.ctx.profile.masks);
        let (schema, name) = (&relation.schema, &relation.name);
        relation.columns.iter().position(|column| {
            assignments
                .column(schema, name, &column.name)
                .is_some_and(|assignment| masks[assignment.policy].is_masked())
                || assignments
                    .derived(schema, name, &column.name)
                    .is_some_and(|policies| policies.iter().any(|p| masks[*p].is_masked()))
        })
    }

    /// How a relation column is masked for this user: its policy and the
    /// columns bound to its arguments, and the masked policies it's computed
    /// from.
    fn column_masking(&self, relation: &Relation, column: &str) -> ColumnMasking<'c> {
        let (assignments, masks) = (self.ctx.assignments, &self.ctx.profile.masks);
        let (schema, name) = (&relation.schema, &relation.name);
        let policy = assignments
            .column(schema, name, column)
            .filter(|assignment| masks[assignment.policy].is_masked())
            .map(|assignment| (assignment.policy, assignment.arguments.as_slice()));
        let derived = assignments
            .derived(schema, name, column)
            .into_iter()
            .flatten()
            .copied()
            .filter(|policy| masks[*policy].is_masked())
            .collect();
        (policy, derived)
    }

    /// Does reading `b` instead of `a` read the same columns, masked the
    /// same way, for this user? Views read as they are (`Safe`) only.
    pub(super) fn reads_like(&mut self, a: &'c Relation, b: &'c Relation) -> bool {
        std::ptr::eq(a, b)
            || (a.columns.len() == b.columns.len()
                && a.columns.iter().zip(&b.columns).all(|(x, y)| {
                    x.name == y.name
                        && self.column_masking(a, &x.name) == self.column_masking(b, &y.name)
                })
                && self.view_verdict(a) == Verdict::Safe
                && self.view_verdict(b) == Verdict::Safe)
    }

    pub(super) fn is_masked_relation(&self, relation: &Relation) -> bool {
        self.ctx
            .assignments
            .relation_policies(&relation.schema, &relation.name)
            .any(|policy| self.ctx.profile.masks[policy].is_masked())
    }

    /// Does a relation have columns masked, or computed from columns masked,
    /// by a proxy mask for this user?
    pub(super) fn has_proxy_masks(&self, relation: &Relation) -> bool {
        self.ctx
            .assignments
            .relation_policies(&relation.schema, &relation.name)
            .any(|policy| self.ctx.profile.masks[policy].proxy().is_some())
    }

    /// Does a relation have columns masked, or computed from columns masked,
    /// by a SQL mask for this user?
    fn has_sql_masks(&self, relation: &Relation) -> bool {
        self.ctx
            .assignments
            .relation_policies(&relation.schema, &relation.name)
            .any(|policy| {
                let mask = &self.ctx.profile.masks[policy];
                mask.is_masked() && mask.proxy().is_none()
            })
    }

    /// Operators the raw value of the column a reference points to may be
    /// searched with.
    fn raw_search(&self, fields: &[&str]) -> Option<&'c HashSet<SearchOp>> {
        let resolved = resolve_column(&self.frames, fields)?;
        match self
            .mask_target(resolved.relation, resolved.column, &resolved.refname)?
            .kind
        {
            TargetKind::Sql { raw_search, .. } => Some(raw_search),
            TargetKind::Proxy { .. } => None,
        }
    }

    /// The taint of `q.N` where Postgres would call `N(q)` on the whole row.
    /// Blocks if that row carries masked values: the implicit call is never
    /// checked. `Ok(None)` if the reference isn't attribute notation.
    fn attribute_taint(
        &mut self,
        fields: &[&str],
        resolution: &Resolution<'_>,
    ) -> Result<Option<Taint>, ()> {
        let (masked, taint) = match resolution.attribute_of {
            None => return Ok(None),
            Some(WholeRowOf::Relation(relation)) => {
                (self.is_masked_relation(relation), Taint::Clean)
            }
            Some(WholeRowOf::Derived { taint, pending }) => match taint {
                Taint::Proxy { .. } | Taint::Computed => (true, taint),
                // A recursive CTE's rows aren't known while it's analyzed.
                Taint::Unknown => (pending && self.ctx.profile.proxies, taint),
                Taint::Clean => (false, taint),
            },
        };
        if !masked {
            return Ok(Some(taint));
        }
        if let [qualifier @ .., name] = fields {
            let qualifier = qualifier.join(".");
            self.block(format!(
                "{qualifier}.{name} calls {name}() on the whole row of {qualifier}, which carries masked columns; write {name}({qualifier})"
            ));
        }
        Err(())
    }

    /// Parse a SQL expression into this statement's memory.
    pub(super) fn parse_expr(&mut self, expr: &str) -> Option<Unique<'mem, Node<'mem>>> {
        let parsed = match self.mem.parse(&format!("SELECT {expr}")) {
            Ok(parsed) => parsed,
            Err(err) => {
                self.block(format!("failed to build mask expression: {err}"));
                return None;
            }
        };
        let stmt = parsed.as_ref().iter().next()?;
        let Node::SelectStmt(select) = stmt.stmt() else {
            return None;
        };
        let target = select.target_list().iter().next()?;
        Some(self.mem.make_unique(target.val()))
    }

    /// Build the masked expression replacing `original`.
    fn masked_expr(
        &mut self,
        original: &nodes::ColumnRef,
        target: &MaskTarget<'c>,
    ) -> Option<Unique<'mem, Node<'mem>>> {
        let TargetKind::Sql {
            template,
            cast,
            arguments,
            ..
        } = target.kind
        else {
            return None;
        };
        let template = match self.ctx.policies.template(&format!("({template})::{cast}")) {
            Ok(template) => template,
            Err(err) => {
                self.block(format!("failed to build mask expression: {err}"));
                return None;
            }
        };
        let val = template.iter().next().and_then(|stmt| match stmt.stmt() {
            Node::SelectStmt(select) => select.target_list().iter().next().map(|t| t.val()),
            _ => None,
        })?;
        let mut expr = self.mem.make_unique(val);
        let mem = self.mem;
        let policy_arguments: &[String] =
            &self.ctx.policies.policies[target.policy].policy.arguments;

        transform::transform(&mut expr, |node| {
            let replacement = match &*node {
                NodeMut::ColumnRef(column) => {
                    let (names, _) = fields(column);
                    match names.as_slice() {
                        [name] if *name == VALUE => Some(mem.make_unique(original).uncast()),
                        [name] => policy_arguments
                            .iter()
                            .position(|arg| arg == name)
                            .and_then(|i| arguments.get(i))
                            .map(|column| {
                                let mut fields = vec![];
                                if !target.qualifier.is_empty() {
                                    fields.push(mem.make_string(Some(&target.qualifier)).uncast());
                                }
                                fields.push(mem.make_string(Some(column)).uncast());
                                mem.make_column_ref(mem.make_list(&fields)).uncast()
                            }),
                        _ => None,
                    }
                }
                _ => None,
            };
            match replacement {
                Some(replacement) => {
                    node.replace(replacement);
                    None
                }
                None => Some(node),
            }
        });

        Some(expr)
    }

    /// SQL-masked columns used directly as a clause, e.g. `WHERE flag`, can't
    /// be replaced in place, and columns computed from them can't be masked
    /// at all. Clause roots never reach `column_ref`, so their taint is
    /// noted here.
    pub(super) fn guard_bare(&mut self, node: Node<'_>) {
        let Node::ColumnRef(column) = node else {
            return;
        };
        let (names, star) = fields(column);
        if star {
            if let [.., qualifier] = names.as_slice() {
                let (_, taint) = self.whole_row(qualifier, false);
                self.note(taint, false);
            }
            return;
        }
        if let [name] = names.as_slice()
            && is_placeholder(name)
        {
            return;
        }
        let resolution = resolve(&self.frames, &names, self.current_cte());
        let Ok(attribute) = self.attribute_taint(&names, &resolution) else {
            return;
        };
        if let Some(resolved) = resolution.columns.first() {
            if let Some(target) =
                self.mask_target(resolved.relation, resolved.column, &resolved.refname)
                && target.proxy().is_none()
            {
                self.block(format!(
                    "masked column {} can't be used directly as a condition",
                    target.label
                ));
                return;
            }
            if self.guard_derived(resolved) == DerivedPolicy::Sql {
                return;
            }
        }
        let (_, taint, _) = self.reference_taint(&names, &resolution, attribute, false);
        self.note_from(taint, false, !resolution.pending_only);
    }

    /// How a table-like view's column computed from masked columns is masked.
    fn derived_policy(&self, resolved: &ResolvedColumn<'_>) -> DerivedPolicy {
        let Some(policies) = self.ctx.assignments.derived(
            &resolved.relation.schema,
            &resolved.relation.name,
            resolved.column,
        ) else {
            return DerivedPolicy::None;
        };
        let masks = &self.ctx.profile.masks;
        let mut masked = policies
            .iter()
            .map(|policy| &masks[*policy])
            .filter(|mask| mask.is_masked())
            .peekable();
        if masked.peek().is_none() {
            DerivedPolicy::None
        } else if masked.all(|mask| mask.proxy().is_some()) {
            DerivedPolicy::Proxy
        } else {
            DerivedPolicy::Sql
        }
    }

    /// Block a column computed from SQL-masked columns, e.g. a column of a
    /// materialized view.
    fn guard_derived(&mut self, resolved: &ResolvedColumn<'_>) -> DerivedPolicy {
        let policy = self.derived_policy(resolved);
        if policy == DerivedPolicy::Sql {
            self.block(format!(
                "column {}.{} is computed from masked columns and can't be masked; assign it a policy",
                resolved.relation.qualified_name(),
                resolved.column
            ));
        }
        policy
    }

    /// Record raw-search references in a comparison.
    fn mark_raw(&mut self, op: Option<SearchOp>, sides: &[(Node<'_>, Node<'_>)]) {
        let Some(op) = op else {
            return;
        };
        for (column_side, other_side) in sides {
            let Some(column) = raw_column(*column_side) else {
                continue;
            };
            if !operand_ok(*other_side) {
                continue;
            }
            let (names, star) = fields(column);
            if star {
                continue;
            }
            if self
                .raw_search(&names)
                .is_some_and(|search| search.contains(&op))
            {
                self.raw_refs.insert(address(column));
            }
        }
    }

    /// Record a raw-search reference with no other operand, e.g. `IS NULL`.
    pub(super) fn mark_raw_column(&mut self, op: SearchOp, node: Node<'_>) {
        if let Some(column) = raw_column(node) {
            let (names, star) = fields(column);
            if !star
                && self
                    .raw_search(&names)
                    .is_some_and(|search| search.contains(&op))
            {
                self.raw_refs.insert(address(column));
            }
        }
    }

    pub(super) fn mark_raw_a_expr(&mut self, expr: &nodes::A_Expr) {
        let op = search_op(expr);
        let (l, r) = (expr.lexpr(), expr.rexpr());
        self.mark_raw(op, &[(l, r), (r, l)]);
    }

    /// A whole-row reference, `t` or `t.*` in an expression: its taint, and
    /// with `build`, the masked row replacing it if `t` has SQL-masked
    /// columns. It's always a computing use.
    fn whole_row(
        &mut self,
        refname: &str,
        build: bool,
    ) -> (Option<Unique<'mem, Node<'mem>>>, Taint) {
        let Some(item) = find_item(&self.frames, refname) else {
            // Not a column, nor a FROM item: e.g. a function parameter.
            return (None, self.unresolved_taint(&[refname]));
        };
        let (relation, names) = match &item.kind {
            ItemKind::Relation { relation, names } => (*relation, names.clone()),
            ItemKind::Derived(outputs) => return (None, outputs.bound().computed()),
        };
        let qualifier = ident(&item.refname);
        let taint = if self.has_proxy_masks(relation) {
            self.read_proxies_of(relation);
            Taint::Computed
        } else {
            Taint::Clean
        };
        if !build || !self.has_sql_masks(relation) {
            return (None, taint);
        }
        let columns = names
            .iter()
            .map(|name| format!("{qualifier}.{}", ident(name)))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "ROW({columns})::{}.{}",
            ident(&relation.schema),
            ident(&relation.name)
        );
        let Some(mut expr) = self.parse_expr(&sql) else {
            return (None, taint);
        };
        // Mask the columns inside the row.
        self.transform_node(Assignable::new(&mut expr));
        (Some(expr), taint)
    }

    /// What a name that resolves to no column or FROM item carries: in a
    /// function body analyzed for where its parameters go, a parameter
    /// carries values of proxy-masked columns.
    fn unresolved_taint(&self, names: &[&str]) -> Taint {
        if self
            .params
            .as_ref()
            .is_some_and(|params| params.is_param(names))
        {
            Taint::Computed
        } else {
            Taint::Unknown
        }
    }

    /// The CTE being analyzed, whose pending columns aren't taint sources.
    fn current_cte(&self) -> Option<&str> {
        self.ctes.last().map(String::as_str)
    }

    pub(super) fn column_ref(
        &mut self,
        column: &nodes::ColumnRef,
    ) -> Option<Unique<'mem, Node<'mem>>> {
        let (names, star) = fields(column);
        let address = address(column);

        if star {
            let [.., qualifier] = names.as_slice() else {
                return None;
            };
            let (row, taint) = self.whole_row(qualifier, true);
            self.note(taint, false);
            return row;
        }
        if let [name] = names.as_slice()
            && is_placeholder(name)
        {
            return None;
        }

        let resolution = resolve(&self.frames, &names, self.current_cte());
        let Ok(attribute) = self.attribute_taint(&names, &resolution) else {
            return None;
        };

        // SQL masks: the first column providing the name is rewritten.
        let mut replacement = None;
        if let Some(resolved) = resolution.columns.first() {
            if self.guard_derived(resolved) == DerivedPolicy::Sql {
                return None;
            }
            if let Some(target) =
                self.mask_target(resolved.relation, resolved.column, &resolved.refname)
                && target.proxy().is_none()
            {
                if self.raw_refs.contains(&address) {
                    self.raw.insert(target.label);
                } else {
                    replacement = Some(self.masked_expr(column, &target)?);
                    self.masked_sql = true;
                    self.masked.insert(target.label);
                }
            }
        }

        // Output names: their taint was noted when the outputs were.
        let source = !resolution.pending_only;
        match self.output_refs.get(&address).copied() {
            Some(OutputRef::Only(taint)) => {
                self.note_from(taint, false, false);
                return replacement;
            }
            // Postgres rejects anything but output names here.
            None if self.setop_sort => {
                self.note(Taint::Unknown, false);
                return replacement;
            }
            Some(OutputRef::Prefer(taint) | OutputRef::Fallback(taint)) if !resolution.certain => {
                self.note_from(taint, false, false);
                if let Some(possible) = resolution.derived {
                    self.note_from(possible, false, source);
                }
                return replacement;
            }
            Some(OutputRef::Prefer(taint)) => self.note_from(taint, false, false),
            Some(OutputRef::Fallback(_)) | None => (),
        }

        let passthrough = self.passthrough.contains(&address);
        let (row, taint, forced) = self.reference_taint(&names, &resolution, attribute, true);
        self.note_from(taint, passthrough && !forced, source);
        replacement.or(row)
    }

    /// The taint of a resolved reference: proxy-masked columns pass their
    /// values, other relation columns are clean, derived items' columns carry
    /// what their outputs do. Also returns the masked row replacing a
    /// whole-row reference (with `build`), and whether the reference is
    /// always a computing use.
    fn reference_taint(
        &mut self,
        names: &[&str],
        resolution: &Resolution<'c>,
        attribute: Option<Taint>,
        build: bool,
    ) -> (Option<Unique<'mem, Node<'mem>>>, Taint, bool) {
        let mut taint: Option<Taint> = None;
        let mut add = |t: Taint| taint = Some(taint.map_or(t, |taint| taint.union(t)));
        let mut forced = false;

        for resolved in &resolution.columns {
            match self.mask_target(resolved.relation, resolved.column, &resolved.refname) {
                Some(target) => match target.proxy() {
                    Some(proxy) => {
                        add(proxy);
                        self.read_proxy(target.label);
                    }
                    // Reads the mask.
                    None => add(Taint::Clean),
                },
                None if self.derived_policy(resolved) == DerivedPolicy::Proxy => {
                    add(Taint::Computed);
                    forced = true;
                    self.state.reads_proxies = true;
                }
                None => add(Taint::Clean),
            }
        }
        if let Some(derived) = resolution.derived {
            add(derived);
        }

        let mut row = None;
        if !resolution.certain {
            match (attribute, names) {
                (Some(attribute), _) => add(attribute),
                // `SELECT t FROM t` is a whole-row reference if no column is
                // named `t`.
                (None, [name]) => {
                    let (whole, whole_taint) = self.whole_row(name, build);
                    row = whole;
                    add(whole_taint);
                    forced = true;
                }
                // E.g. a field of a composite column.
                (None, _) => add(self.unresolved_taint(names)),
            }
        }
        (row, taint.unwrap_or_default(), forced)
    }
}

/// The column in a raw-search comparison side, possibly wrapped in a normalizer.
fn raw_column(node: Node<'_>) -> Option<&nodes::ColumnRef> {
    match node {
        Node::ColumnRef(column) => Some(column),
        Node::FuncCall(call) if is_normalizer(call) => {
            let mut args = call.args().iter();
            match (args.next(), args.next()) {
                (Some(arg), None) => raw_column(arg),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_normalizer(call: &nodes::FuncCall) -> bool {
    let names: Vec<_> = call.funcname().iter().filter_map(|n| n.as_str()).collect();
    matches!(names.as_slice(), [name] | ["pg_catalog", name] if NORMALIZERS.contains(name))
}

/// Values a masked column may be compared with in a raw search.
fn operand_ok(node: Node<'_>) -> bool {
    match node {
        Node::ParamRef(_) | Node::A_Const(_) | Node::ColumnRef(_) => true,
        Node::TypeCast(cast) => operand_ok(cast.arg()),
        Node::FuncCall(call) if is_normalizer(call) => call.args().iter().all(operand_ok),
        Node::NodeList(list) => list.iter().all(operand_ok),
        Node::A_ArrayExpr(array) => array.elements().iter().all(operand_ok),
        _ => false,
    }
}

fn search_op(expr: &nodes::A_Expr) -> Option<SearchOp> {
    let op = expr
        .name()
        .iter()
        .next_back()
        .and_then(|n| n.as_str())
        .unwrap_or("");
    match expr.kind {
        A_Expr_Kind::AEXPR_OP => match op {
            "=" | "<>" | "!=" => Some(SearchOp::Equality),
            "<" | ">" | "<=" | ">=" => Some(SearchOp::Range),
            "~~" | "!~~" | "~~*" | "!~~*" => Some(SearchOp::Like),
            _ => None,
        },
        A_Expr_Kind::AEXPR_OP_ANY | A_Expr_Kind::AEXPR_OP_ALL if matches!(op, "=" | "<>") => {
            Some(SearchOp::Any)
        }
        A_Expr_Kind::AEXPR_DISTINCT | A_Expr_Kind::AEXPR_NOT_DISTINCT => Some(SearchOp::Distinct),
        A_Expr_Kind::AEXPR_IN => Some(SearchOp::In),
        A_Expr_Kind::AEXPR_LIKE | A_Expr_Kind::AEXPR_ILIKE => Some(SearchOp::Like),
        A_Expr_Kind::AEXPR_BETWEEN
        | A_Expr_Kind::AEXPR_NOT_BETWEEN
        | A_Expr_Kind::AEXPR_BETWEEN_SYM
        | A_Expr_Kind::AEXPR_NOT_BETWEEN_SYM => Some(SearchOp::Range),
        _ => None,
    }
}
