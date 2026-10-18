//! Statement shapes: statements that differ only in their literals.
//!
//! Clients using the simple protocol inline values into SQL, so the same
//! query arrives with different text every time and the decision cache keyed by
//! text never hits. The masking decision doesn't depend on literal values, only
//! on where they are, so statements are analyzed once per shape:
//!
//! 1. Literals are replaced with placeholder identifiers carrying a random,
//!    per-process nonce and their position. The resulting SQL is the shape.
//! 2. The shape is analyzed like any statement. A rewrite comes back as SQL
//!    with the placeholders in it, which is split into fixed segments and
//!    literal slots.
//! 3. Each statement with that shape is rendered by putting its own literals,
//!    as deparsed by Postgres' deparser, back into the slots.
//!
//! Literals never go through string interpolation of client text: they're
//! deparsed from the parse tree, so they're always properly quoted.
use std::hash::BuildHasher;
use std::sync::LazyLock;

use pg_raw_parse::{
    Node, NodeMut, make, nodes,
    raw::{CoercionForm, XmlExprOp},
    transform::{self, Assignable, Transform},
};

/// Prefix of literal placeholders, unique to this process so clients can't
/// forge placeholders in their own SQL.
static PREFIX: LazyLock<String> = LazyLock::new(|| {
    let nonce = std::collections::hash_map::RandomState::new().hash_one(std::process::id());
    format!("__pgdog_lit_{nonce:016x}_")
});

/// Is this identifier a literal placeholder?
pub(crate) fn is_placeholder(name: &str) -> bool {
    name.starts_with(PREFIX.as_str())
}

/// A statement reduced to its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Literals {
    /// The statement with literals replaced by placeholders.
    pub shape: String,
    /// Literals in placeholder order, deparsed.
    pub values: Vec<String>,
}

/// A rewritten shape, ready to render with a statement's literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// `segments[0] values[slots[0]] segments[1] ... segments[n]`.
    segments: Vec<String>,
    slots: Vec<usize>,
}

/// Only plain DML is reduced to shapes. Other statements carry literals in
/// positions that aren't expressions (options, settings).
fn eligible(node: Node<'_>) -> bool {
    matches!(
        node,
        Node::SelectStmt(_) | Node::InsertStmt(_) | Node::UpdateStmt(_) | Node::DeleteStmt(_)
    )
}

struct Placeholders<'mem> {
    mem: make::MemoryToken<'mem>,
    values: Vec<String>,
    failed: bool,
}

impl Placeholders<'_> {
    /// A literal as Postgres' deparser writes it, so rendered statements are
    /// identical to fully analyzed ones.
    fn deparse(&self, constant: &nodes::A_Const) -> Option<String> {
        let mem = self.mem;
        let target = mem.make_res_target(None, mem.empty(), mem.make_unique(constant).uncast());
        let mut select = mem.make_node::<nodes::SelectStmt>();
        select.as_mut().set_target_list(mem.make_list(&[target]));
        let sql = pg_raw_parse::deparse(select.as_ref()).ok()?;
        sql.as_str().strip_prefix("SELECT ").map(str::to_owned)
    }
}

impl<'mem> Transform<'mem> for Placeholders<'mem> {
    fn transform_node<'mutref>(&mut self, node: Assignable<'mem, 'mutref>) {
        let literal = match &*node {
            NodeMut::A_Const(constant) => Some(self.deparse(constant)),
            // Options are not expressions: leave their literals alone.
            NodeMut::DefElem(_) => return,
            NodeMut::FuncCall(call) => {
                let name = call.funcname().iter().next_back().and_then(|n| n.as_str());
                // Whether set_config is allowed depends on its literal
                // arguments. NORMALIZE's form is a keyword the deparser reads
                // from a literal.
                if name == Some("set_config")
                    || (call.funcformat == CoercionForm::COERCE_SQL_SYNTAX
                        && matches!(name, Some("normalize" | "is_normalized")))
                {
                    self.failed = true;
                    return;
                }
                None
            }
            _ => None,
        };
        match literal {
            Some(Some(literal)) => {
                let name = format!("{}{}", PREFIX.as_str(), self.values.len());
                self.values.push(literal);
                let mem = self.mem;
                let column =
                    mem.make_column_ref(mem.make_list(&[mem.make_string(Some(&name)).uncast()]));
                node.replace(column.uncast());
            }
            Some(None) => self.failed = true,
            None => transform::transform_node(node.into_inner(), self),
        }
    }

    // The deparser reads these literals as literals: replacing them would
    // write garbage, or crash it.

    /// Type modifiers, e.g. `numeric(10, 2)` or `interval minute`, are part
    /// of the type.
    fn transform_type_name<'mutref>(&mut self, _node: nodes::TypeNameMut<'mem, 'mutref>) {}

    /// JSON_TABLE paths.
    fn transform_json_table_path_spec<'mutref>(
        &mut self,
        _node: nodes::JsonTablePathSpecMut<'mem, 'mutref>,
    ) {
    }

    /// XMLROOT's version and standalone arguments.
    fn transform_xml_expr<'mutref>(&mut self, node: nodes::XmlExprMut<'mem, 'mutref>) {
        if node.op == XmlExprOp::IS_XMLROOT {
            self.failed = true;
            return;
        }
        transform::transform_xml_expr(node, self);
    }
}

/// Reduce a statement to its shape. `None` if it isn't eligible, has no
/// literals, or can't be handled safely.
pub fn literals(sql: &str) -> Option<Literals> {
    // Placeholders are only unique if the client didn't send one.
    if sql.contains("__pgdog_lit_") {
        return None;
    }

    let mut values = None;
    let parsed = make::try_owned(|mem| {
        let mut stmts = mem.parse(sql)?;
        let mut placeholders = Placeholders {
            mem,
            values: vec![],
            failed: false,
        };
        let mut ok = true;
        for stmt in stmts.as_mut() {
            if !eligible(stmt.stmt()) {
                ok = false;
                break;
            }
            transform::transform_raw_stmt(stmt, &mut placeholders);
        }
        if ok && !placeholders.failed {
            values = Some(placeholders.values);
        }
        Ok::<_, pg_raw_parse::Error>(stmts)
    })
    .ok()?;

    let values = values?;
    if values.is_empty() {
        return None;
    }
    let shape = pg_raw_parse::deparse_stmts(parsed.iter()).ok()?;

    Some(Literals {
        shape: format!("{}{shape}", super::leading_comments(sql)),
        values,
    })
}

impl Template {
    /// Split rewritten shape SQL at its placeholders. `None` if a placeholder
    /// refers to a literal the shape doesn't have.
    pub fn new(sql: &str, literals: usize) -> Option<Self> {
        let prefix = PREFIX.as_str();
        let mut segments = vec![];
        let mut slots = vec![];
        let mut rest = sql;

        while let Some(start) = rest.find(prefix) {
            let after = &rest[start + prefix.len()..];
            let digits = after.bytes().take_while(u8::is_ascii_digit).count();
            let slot: usize = after[..digits].parse().ok()?;
            if slot >= literals {
                return None;
            }
            segments.push(rest[..start].to_owned());
            slots.push(slot);
            rest = &after[digits..];
        }
        segments.push(rest.to_owned());

        Some(Self { segments, slots })
    }

    /// The SQL for a statement with this shape.
    pub fn render(&self, values: &[String]) -> Option<String> {
        let mut sql = String::with_capacity(
            self.segments.iter().map(String::len).sum::<usize>()
                + values.iter().map(String::len).sum::<usize>(),
        );
        for (segment, slot) in self.segments.iter().zip(&self.slots) {
            sql.push_str(segment);
            let value = values.get(*slot)?;
            // Negative numbers next to an operator or a cast need parentheses
            // to parse the same way.
            if value.starts_with('-') {
                sql.push('(');
                sql.push_str(value);
                sql.push(')');
            } else {
                sql.push_str(value);
            }
        }
        sql.push_str(self.segments.last()?);
        Some(sql)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_literals() {
        let a = literals("SELECT id FROM users WHERE ssn = '123' AND id > 5 LIMIT 10").unwrap();
        let b = literals("SELECT id FROM users WHERE ssn = 'x''y' AND id > 7 LIMIT 1").unwrap();
        assert_eq!(a.shape, b.shape, "same shape, different literals");
        assert_eq!(a.values, ["'123'", "5", "10"]);
        assert_eq!(b.values, ["'x''y'", "7", "1"]);

        assert!(
            literals("SELECT id FROM users WHERE id = $1").is_none(),
            "no literals"
        );
        assert!(literals("SET statement_timeout = 5").is_none(), "not DML");
        assert!(
            literals("SELECT '__pgdog_lit_0'").is_none(),
            "forged placeholder"
        );
    }

    #[test]
    fn test_literals_the_deparser_needs() {
        // Type modifiers stay in the shape.
        let shape = literals("SELECT x::interval(2), '1 day'::interval minute, 1 FROM t").unwrap();
        assert!(shape.shape.contains("::interval(2)"), "{shape:?}");
        assert!(shape.shape.contains("::interval minute"), "{shape:?}");
        let shape = literals("SELECT '1'::numeric(10, 2)").unwrap();
        assert_eq!(shape.values, ["'1'"]);
        // JSON_TABLE paths stay too (replacing them crashed the deparser).
        let shape = literals(
            "SELECT * FROM JSON_TABLE('{}'::jsonb, '$' COLUMNS (a text PATH '$.a')) j WHERE a = 'x'",
        )
        .unwrap();
        assert_eq!(shape.values, ["'{}'", "'x'"]);
        assert!(shape.shape.contains("'$.a'"), "{shape:?}");
        // Not shaped.
        assert!(literals("SELECT xmlroot('<a/>'::xml, version '1.0', standalone yes)").is_none());
        assert!(literals("SELECT normalize('a', NFC)").is_none());
        assert!(literals("SELECT 'a' IS NFC NORMALIZED").is_none());
    }

    #[test]
    fn test_set_config_not_shaped() {
        assert!(literals("SELECT set_config('app.x', 'v', false)").is_none());
        assert!(literals("SELECT id, pg_catalog.set_config('a', 'b', true) FROM t").is_none());
        assert!(literals("SELECT * FROM set_config('a', 'b', true)").is_none());
    }

    #[test]
    fn test_render() {
        let literals = literals("SELECT id FROM users WHERE ssn = 'it''s' AND id = -5").unwrap();
        let template = Template::new(&literals.shape, literals.values.len()).unwrap();
        assert_eq!(
            template.render(&literals.values).unwrap(),
            "SELECT id FROM users WHERE ssn = 'it''s' AND id = (-5)"
        );
        assert!(
            Template::new(&literals.shape, 1).is_none(),
            "slot out of range"
        );
    }
}
