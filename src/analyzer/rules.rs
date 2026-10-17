//! Fail-closed rules for masked users.
use pg_raw_parse::{
    Node, nodes,
    raw::{DiscardMode, SetOperation, VariableSetKind},
};

/// Built-in functions that run SQL or read data out of band.
const DENIED_FUNCTIONS: &[&str] = &[
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "ts_stat",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "lo_import",
    "lo_export",
    "lo_get",
    "lo_open",
    "loread",
    // Logical decoding output: rows of every table, as of their changes.
    "pg_logical_slot_get_changes",
    "pg_logical_slot_peek_changes",
    "pg_logical_slot_get_binary_changes",
    "pg_logical_slot_peek_binary_changes",
];

/// Built-ins that store or send their arguments where they can be read back.
const SIDE_EFFECT_FUNCTIONS: &[&str] = &[
    "set_config",
    "setseed",
    "setval",
    "nextval",
    "pg_notify",
    "pg_logical_emit_message",
    "lowrite",
    // PG17/18: write pg_class and pg_statistic.
    "pg_restore_relation_stats",
    "pg_restore_attribute_stats",
    "pg_clear_relation_stats",
    "pg_clear_attribute_stats",
    "pg_replication_slot_advance",
];

/// Families of built-ins that store or send their arguments.
const SIDE_EFFECT_PREFIXES: &[&str] = &[
    // Keys show in pg_locks.
    "pg_advisory_",
    "pg_try_advisory_",
    // Large objects (lo_get and friends are denied outright).
    "lo_",
    // Restore points and replication slots.
    "pg_create_",
    "pg_copy_",
    "pg_drop_",
    "pg_replication_origin_",
    "pg_backup_",
    "pg_start_backup",
    // adminpack installs into pg_catalog.
    "pg_file_",
];

/// Catalog relations that expose column values.
const DENIED_RELATIONS: &[&str] = &[
    "pg_stats",
    "pg_stats_ext",
    "pg_stats_ext_exprs",
    "pg_statistic",
    "pg_statistic_ext_data",
    "pg_stat_statements",
];

const CATALOG_SCHEMAS: &[&str] = &["pg_catalog", "information_schema", "pg_toast"];

/// Functions that run SQL or read data out of band. They're blocked even if
/// allowlisted.
pub(super) fn denied_function(name: &str) -> Option<String> {
    (DENIED_FUNCTIONS.contains(&name) || name.starts_with("dblink"))
        .then(|| format!("function {name}() is not allowed for masked users"))
}

/// Does a built-in store or send its arguments where they can be read back?
pub(super) fn side_effect(name: &str) -> bool {
    SIDE_EFFECT_FUNCTIONS.contains(&name)
        || SIDE_EFFECT_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Is a function in `udf_allowlist`? Unqualified calls match entries by name.
pub(super) fn allowlisted(schema: Option<&str>, name: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|entry| match schema {
        Some(schema) => entry.split_once('.') == Some((schema, name)),
        None => entry.rsplit('.').next() == Some(name),
    })
}

/// Is this a reference to a system catalog relation, and is it allowed?
/// Returns `None` if the relation isn't a catalog relation.
pub(super) fn check_catalog_relation(
    schema: Option<&str>,
    name: &str,
) -> Option<Result<(), String>> {
    let catalog = match schema {
        Some(schema) => CATALOG_SCHEMAS.contains(&schema),
        // pg_catalog is implicitly first in every search_path.
        None => name.starts_with("pg_"),
    };

    if !catalog && !DENIED_RELATIONS.contains(&name) {
        return None;
    }

    Some(if DENIED_RELATIONS.contains(&name) {
        Err(format!(
            "{name} exposes column values and is not allowed for masked users"
        ))
    } else {
        Ok(())
    })
}

/// Statements masked users may run.
pub(super) fn check_statement(node: Node<'_>) -> Result<(), String> {
    let allowed = matches!(
        node,
        Node::SelectStmt(_)
            | Node::InsertStmt(_)
            | Node::UpdateStmt(_)
            | Node::DeleteStmt(_)
            | Node::CopyStmt(_)
            | Node::ExplainStmt(_)
            | Node::DeclareCursorStmt(_)
            | Node::PrepareStmt(_)
            | Node::ExecuteStmt(_)
            | Node::DeallocateStmt(_)
            | Node::FetchStmt(_)
            | Node::ClosePortalStmt(_)
            | Node::TransactionStmt(_)
            | Node::VariableSetStmt(_)
            | Node::VariableShowStmt(_)
            | Node::DiscardStmt(_)
            | Node::ListenStmt(_)
            | Node::UnlistenStmt(_)
            | Node::NotifyStmt(_)
            | Node::LockStmt(_)
            | Node::CreateStmt(_)
            | Node::CreateTableAsStmt(_)
            | Node::TruncateStmt(_)
            | Node::VacuumStmt(_)
            // DDL that can't read data. ALTER TABLE, CREATE INDEX and renames are
            // further limited to relations without masked columns.
            | Node::DropStmt(_)
            | Node::CreateSeqStmt(_)
            | Node::AlterSeqStmt(_)
            | Node::AlterTableStmt(_)
            | Node::IndexStmt(_)
            | Node::RenameStmt(_)
    );

    if allowed {
        Ok(())
    } else {
        Err("this statement type is not allowed for masked users".to_owned())
    }
}

/// Can the deparser print this statement? Its COPY printer reads option
/// arguments without checking them, and crashes the process on a missing or
/// mistyped one, e.g. `COPY t TO STDOUT WITH (delimiter)`. Postgres rejects
/// those options anyway. The deparser prints rewritten statements, and
/// normalized ones in logs.
pub(crate) fn deparsable(node: Node<'_>) -> bool {
    let Node::CopyStmt(copy) = node else {
        return true;
    };
    let strings = |list: &pg_raw_parse::list::NodeList| {
        list.iter().all(|node| matches!(node, Node::String(_)))
    };
    copy.options().iter().all(|option| {
        let arg = option.arg();
        match option.defname() {
            None => false,
            Some("format") => matches!(arg.as_str(), Some("binary" | "csv" | "text")),
            Some("delimiter" | "null" | "quote" | "escape" | "encoding") => {
                matches!(arg, Node::String(_))
            }
            Some("force_quote" | "force_not_null" | "force_null") => match arg {
                Node::A_Star(_) => true,
                Node::NodeList(columns) => strings(columns),
                _ => false,
            },
            Some("freeze" | "header") => matches!(
                arg,
                Node::None | Node::String(_) | Node::Integer(_) | Node::Boolean(_)
            ),
            Some(_) => match arg {
                Node::NodeList(values) => strings(values),
                _ => true,
            },
        }
    })
}

/// Does an EXPLAIN run its statement? `ANALYZE` with no value, or any value
/// but a clearly false one, runs it. Postgres rejects values other than
/// true, false, on, off, 1 and 0.
pub(super) fn explain_executes(explain: &nodes::ExplainStmt) -> bool {
    explain.options().iter().any(|option| {
        option.defname() == Some("analyze")
            && match option.arg() {
                Node::Integer(nodes::Integer { ival, .. }) => *ival != 0,
                arg => !arg.as_str().is_some_and(|value| {
                    ["false", "off", "no", "0"]
                        .iter()
                        .any(|off| off.eq_ignore_ascii_case(value))
                }),
            }
    })
}

/// Settings that change how names resolve.
const RESOLUTION_SETTINGS: &[&str] = &["search_path", "role", "session_authorization"];

/// Does this setting change how names resolve? Setting names are
/// case-insensitive.
pub(super) fn changes_resolution_setting(name: &str) -> bool {
    RESOLUTION_SETTINGS
        .iter()
        .any(|setting| setting.eq_ignore_ascii_case(name))
}

/// Statements after which names may resolve differently: changes to
/// `search_path` or the role (`$user`), and DDL that creates, drops or
/// renames relations or changes their columns.
pub(super) fn changes_resolution(node: Node<'_>) -> bool {
    match node {
        Node::ExplainStmt(explain) => changes_resolution(explain.query()),
        Node::SelectStmt(select) => into_clause(select).is_some(),
        Node::CreateStmt(_)
        | Node::CreateTableAsStmt(_)
        | Node::DropStmt(_)
        | Node::RenameStmt(_)
        | Node::AlterTableStmt(_) => true,
        node => changes_resolution_settings(node),
    }
}

/// Does a statement change `search_path` or the role: `SET`, `RESET`,
/// `RESET ALL` or `DISCARD ALL`?
fn changes_resolution_settings(node: Node<'_>) -> bool {
    match node {
        Node::VariableSetStmt(set) => {
            set.kind == VariableSetKind::VAR_RESET_ALL
                || (set.kind != VariableSetKind::VAR_SET_MULTI
                    && set.name().is_some_and(changes_resolution_setting))
        }
        Node::DiscardStmt(discard) => discard.target == DiscardMode::DISCARD_ALL,
        _ => false,
    }
}

/// Most whitespace before the command of a query PgDog is sure to look at.
const LEADING_SPACE: usize = 64;

/// PgDog follows a change to `search_path` or the role only in a query of
/// its own, which it tells by the query's first word: not as a later
/// statement of a query, nor after comments, a `;` or a lot of whitespace.
/// The plugin would then resolve names with a search_path Postgres doesn't
/// use, and the change would stay on the pooled server connection for the
/// next client.
pub(super) fn check_resolution_settings(sql: &str, stmts: &[Node<'_>]) -> Result<(), &'static str> {
    if !stmts.iter().any(|stmt| changes_resolution_settings(*stmt)) {
        return Ok(());
    }
    let alone = stmts.len() == 1;
    let command = sql.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let first_word = ["set", "reset", "discard"].iter().any(|word| {
        command
            .get(..word.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(word))
    });
    if alone && sql.len() - command.len() <= LEADING_SPACE && first_word {
        Ok(())
    } else {
        Err(
            "changes to search_path or the role must be sent as a query of their own, starting with SET, RESET or DISCARD: PgDog doesn't follow them otherwise",
        )
    }
}

/// Does a new relation go to the session's temporary schema: `TEMP`, or a
/// `pg_temp` (or `pg_temp_N`) schema?
pub(super) fn temporary(range_var: &nodes::RangeVar) -> bool {
    range_var.relpersistence as u8 == b't'
        || range_var.schemaname().is_some_and(|schema| {
            let schema = schema.to_ascii_lowercase();
            schema == "pg_temp" || schema.starts_with("pg_temp_")
        })
}

/// DDL whose expressions are stored, or evaluated over rows: defaults,
/// generated columns, checks, `ALTER ... TYPE ... USING` and indexes.
pub(super) fn stores_expressions(node: Node<'_>) -> bool {
    matches!(
        node,
        Node::CreateStmt(_) | Node::AlterTableStmt(_) | Node::IndexStmt(_)
    )
}

/// The INTO clause of a SELECT: on a set operation, its leftmost leaf's,
/// where the parser attaches it.
pub(super) fn into_clause(select: &nodes::SelectStmt) -> Option<&nodes::IntoClause> {
    let mut leaf = select;
    while leaf.op != SetOperation::SETOP_NONE {
        leaf = leaf.larg()?;
    }
    select.into_clause().or_else(|| leaf.into_clause())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_side_effect() {
        for name in [
            "set_config",
            "nextval",
            "pg_notify",
            "pg_advisory_xact_lock",
            "lo_from_bytea",
            "pg_copy_logical_replication_slot",
            "pg_restore_relation_stats",
        ] {
            assert!(side_effect(name), "{name}");
        }
        for name in ["upper", "current_setting", "length", "pg_typeof"] {
            assert!(!side_effect(name), "{name}");
        }
    }

    #[test]
    fn test_functions() {
        assert!(denied_function("lower").is_none());
        assert!(denied_function("query_to_xml").is_some());
        assert!(denied_function("dblink_exec").is_some());
        assert!(denied_function("pg_logical_slot_peek_changes").is_some());
        let allowlist = ["public.my_func".to_owned()];
        assert!(allowlisted(None, "my_func", &allowlist));
        assert!(allowlisted(Some("public"), "my_func", &allowlist));
        assert!(!allowlisted(Some("other"), "my_func", &allowlist));
        assert!(!allowlisted(None, "lower", &allowlist));
    }

    #[test]
    fn test_explain_executes() {
        for (sql, executes) in [
            ("EXPLAIN SELECT 1", false),
            ("EXPLAIN (FORMAT JSON, VERBOSE) SELECT 1", false),
            ("EXPLAIN ANALYZE SELECT 1", true),
            ("EXPLAIN ANALYSE SELECT 1", true),
            ("EXPLAIN (ANALYZE) SELECT 1", true),
            ("EXPLAIN (ANALYZE true, BUFFERS) SELECT 1", true),
            ("EXPLAIN (ANALYZE 1) SELECT 1", true),
            ("EXPLAIN (ANALYZE false) SELECT 1", false),
            ("EXPLAIN (ANALYZE OFF) SELECT 1", false),
            ("EXPLAIN (ANALYZE 0) SELECT 1", false),
            // Any option that may run it does.
            ("EXPLAIN (ANALYZE false, ANALYZE) SELECT 1", true),
            ("EXPLAIN (ANALYZE 'maybe') SELECT 1", true),
        ] {
            let parsed = pg_raw_parse::parse(sql).unwrap();
            let stmt = parsed.into_iter().next().unwrap();
            let Node::ExplainStmt(explain) = stmt.stmt() else {
                panic!("{sql} isn't EXPLAIN");
            };
            assert_eq!(explain_executes(explain), executes, "{sql}");
        }
    }

    #[test]
    fn test_check_catalog_relation() {
        assert_eq!(check_catalog_relation(None, "pg_class"), Some(Ok(())));
        assert!(matches!(
            check_catalog_relation(None, "pg_stats"),
            Some(Err(_))
        ));
        assert!(matches!(
            check_catalog_relation(Some("public"), "pg_stat_statements"),
            Some(Err(_))
        ));
        assert_eq!(check_catalog_relation(None, "users"), None);
        assert_eq!(
            check_catalog_relation(Some("information_schema"), "columns"),
            Some(Ok(()))
        );
    }
}
