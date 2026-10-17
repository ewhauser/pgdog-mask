//! Fail-closed rules for masked users.
use pg_raw_parse::{
    ConstValue, Node, nodes,
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
        Node::VariableSetStmt(set) => {
            set.kind == VariableSetKind::VAR_RESET_ALL
                || (set.kind != VariableSetKind::VAR_SET_MULTI
                    && set.name().is_some_and(changes_resolution_setting))
        }
        Node::DiscardStmt(discard) => discard.target == DiscardMode::DISCARD_ALL,
        Node::SelectStmt(select) => into_clause(select).is_some(),
        Node::CreateStmt(_)
        | Node::CreateTableAsStmt(_)
        | Node::DropStmt(_)
        | Node::RenameStmt(_)
        | Node::AlterTableStmt(_) => true,
        _ => false,
    }
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

/// Is this the one form of `set_config` PgDog tracks, so the session's
/// `search_path` follows it: `SELECT [pg_catalog.]set_config('<name>',
/// '<value>' | NULL, <boolean>)` and nothing else?
pub(super) fn tracked_set_config(node: Node<'_>) -> bool {
    let Node::SelectStmt(select) = node else {
        return false;
    };
    let plain = select.op == SetOperation::SETOP_NONE
        && select.with_clause().is_none()
        && select.into_clause().is_none()
        && select.distinct_clause().is_empty()
        && select.from_clause().is_empty()
        && matches!(select.where_clause(), Node::None)
        && select.group_clause().is_empty()
        && matches!(select.having_clause(), Node::None)
        && select.window_clause().is_empty()
        && select.values_lists().is_empty()
        && select.sort_clause().is_empty()
        && matches!(select.limit_offset(), Node::None)
        && matches!(select.limit_count(), Node::None)
        && select.locking_clause().is_empty();
    let targets: Vec<_> = select.target_list().iter().collect();
    let [target] = targets.as_slice() else {
        return false;
    };
    let Node::FuncCall(call) = target.val() else {
        return false;
    };
    let name: Vec<_> = call.funcname().iter().filter_map(|n| n.as_str()).collect();
    let args: Vec<_> = call
        .args()
        .iter()
        .map(|arg| match arg {
            Node::A_Const(constant) => Some(constant.val()),
            _ => None,
        })
        .collect();
    plain
        && matches!(
            name.as_slice(),
            ["set_config"] | ["pg_catalog", "set_config"]
        )
        && !call.agg_star
        && !call.agg_distinct
        && !call.func_variadic
        && call.over().is_none()
        && call.agg_order().is_empty()
        && matches!(call.agg_filter(), Node::None)
        && matches!(
            args.as_slice(),
            [
                Some(Some(ConstValue::String(_))),
                Some(Some(ConstValue::String(_)) | None),
                Some(Some(ConstValue::Boolean(_))),
            ]
        )
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
        let allowlist = ["public.my_func".to_owned()];
        assert!(allowlisted(None, "my_func", &allowlist));
        assert!(allowlisted(Some("public"), "my_func", &allowlist));
        assert!(!allowlisted(Some("other"), "my_func", &allowlist));
        assert!(!allowlisted(None, "lower", &allowlist));
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
