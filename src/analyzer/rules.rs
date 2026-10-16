//! Fail-closed rules for masked users.
use pg_raw_parse::Node;

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
    );

    if allowed {
        Ok(())
    } else {
        Err("this statement type is not allowed for masked users".to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
