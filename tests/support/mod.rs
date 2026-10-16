//! Load a database's catalog the way PgDog does for CATALOG plugins: with PgDog's
//! own catalog queries, converted into the `Catalog` PgDog sends to plugins.
use std::collections::HashMap;

use pgdog_mask::catalog::Catalog;
use pgdog_plugin::{CatalogParts, catalog as plugin};
use pgdog_stats::{Column, Function, Operator, Relation, SecurityLabel};
use tokio_postgres::{Client, SimpleQueryMessage};

// PgDog's schema loader queries (pgdog/src/backend/schema/*.sql), copied from the
// PgDog revision in Cargo.toml. Update them together.
const QUERIES: &str = "tests/support/sql";
const RELATIONS: &str = include_str!("sql/relations.sql");
const COLUMNS: &str = include_str!("sql/columns_catalog.sql");
const VIEWS: &str = include_str!("sql/views.sql");
const FUNCTIONS: &str = include_str!("sql/functions.sql");
const OPERATORS: &str = include_str!("sql/operators.sql");

type Row = Vec<Option<String>>;

/// Run a catalog query. Like PgDog, queries that print names run with an empty
/// `search_path`, so names come back schema-qualified.
async fn rows(client: &Client, query: &str, qualified: bool) -> Vec<Row> {
    let sql = if qualified {
        format!("SET LOCAL search_path TO ''; {query}")
    } else {
        query.to_owned()
    };
    client
        .simple_query(&sql)
        .await
        .unwrap_or_else(|err| panic!("catalog query from {QUERIES} failed: {err:?}"))
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(
                (0..row.len())
                    .map(|i| row.get(i).map(str::to_owned))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

fn text(row: &Row, i: usize) -> String {
    row.get(i).cloned().flatten().unwrap_or_default()
}

fn json<T: serde::de::DeserializeOwned>(row: &Row) -> T {
    serde_json::from_str(&text(row, 0)).expect("catalog row is JSON")
}

/// The catalog of the given schemas, as the plugin receives it from PgDog.
pub async fn load_catalog(client: &Client, schemas: &[&str], search_path: &[&str]) -> Catalog {
    let in_schemas = |schema: &str| schemas.contains(&schema);

    let mut relations: HashMap<(String, String), Relation> = HashMap::new();
    for row in rows(client, RELATIONS, false).await {
        let schema = text(&row, 0);
        if !in_schemas(&schema) {
            continue;
        }
        let non_empty = |i| Some(text(&row, i)).filter(|s| !s.is_empty());
        let relation = Relation {
            schema: schema.clone(),
            name: text(&row, 1),
            type_: text(&row, 2),
            owner: text(&row, 3),
            persistence: text(&row, 4),
            access_method: text(&row, 5),
            description: text(&row, 6),
            oid: text(&row, 7).parse().unwrap_or_default(),
            parent_table_schema: non_empty(8),
            parent_table_name: non_empty(9),
            columns: Default::default(),
            definition: None,
            options: vec![],
        };
        relations.insert((schema, relation.name.clone()), relation);
    }

    for row in rows(client, COLUMNS, true).await {
        let key = (text(&row, 1), text(&row, 2));
        let Some(relation) = relations.get_mut(&key) else {
            continue;
        };
        let column = Column {
            table_catalog: text(&row, 0),
            table_schema: text(&row, 1),
            table_name: text(&row, 2),
            column_name: text(&row, 3),
            column_default: text(&row, 4),
            is_nullable: text(&row, 5) == "true",
            data_type: text(&row, 6),
            ordinal_position: text(&row, 7).parse().unwrap_or_default(),
            is_primary_key: text(&row, 8) == "true",
            foreign_keys: vec![],
            type_name: text(&row, 9),
            comment: row.get(10).cloned().flatten(),
            security_labels: serde_json::from_str::<Vec<SecurityLabel>>(&text(&row, 11))
                .unwrap_or_default(),
        };
        relation.columns.insert(column.column_name.clone(), column);
    }

    #[derive(serde::Deserialize)]
    struct View {
        schema: String,
        name: String,
        definition: Option<String>,
        options: Vec<String>,
    }
    for row in rows(client, VIEWS, true).await {
        let view: View = json(&row);
        if let Some(relation) = relations.get_mut(&(view.schema, view.name)) {
            relation.definition = view.definition;
            relation.options = view.options;
        }
    }

    let functions_sql =
        FUNCTIONS.replace("{sql_body}", "pg_catalog.pg_get_function_sqlbody(p.oid)");
    let functions: Vec<Function> = rows(client, &functions_sql, true)
        .await
        .iter()
        .map(json::<Function>)
        .filter(|function| in_schemas(&function.schema))
        .collect();
    let operators: Vec<Operator> = rows(client, OPERATORS, true)
        .await
        .iter()
        .map(json::<Operator>)
        .filter(|operator| in_schemas(&operator.schema))
        .collect();
    let system_functions = rows(
        client,
        "SELECT DISTINCT proname::text FROM pg_catalog.pg_proc WHERE pronamespace = 'pg_catalog'::regnamespace ORDER BY 1",
        false,
    )
    .await
    .iter()
    .map(|row| text(row, 0))
    .collect();

    // Converted like PgDog does (pgdog/src/plugin/catalog.rs).
    let mut relations: Vec<_> = relations.into_values().map(relation).collect();
    relations.sort_by(|a, b| (&a.schema, &a.name).cmp(&(&b.schema, &b.name)));
    let catalog = plugin::Catalog {
        parts: CatalogParts::ALL,
        search_path: search_path.iter().map(|s| (*s).to_owned()).collect(),
        relations,
        functions: functions.into_iter().map(function).collect(),
        system_functions,
        operators: operators.into_iter().map(operator).collect(),
    };
    Catalog::from_plugin(&catalog)
}

fn relation(relation: Relation) -> plugin::Relation {
    let kind = match relation.type_.as_str() {
        "table" => plugin::RelationKind::Table,
        "partitioned table" => plugin::RelationKind::PartitionedTable,
        "view" => plugin::RelationKind::View,
        "materialized view" => plugin::RelationKind::MaterializedView,
        "foreign table" => plugin::RelationKind::ForeignTable,
        _ => plugin::RelationKind::Other,
    };
    plugin::Relation {
        schema: relation.schema,
        name: relation.name,
        kind,
        columns: relation
            .columns
            .into_values()
            .map(|column| plugin::Column {
                name: column.column_name,
                data_type: column.data_type,
                type_name: column.type_name,
                is_primary_key: column.is_primary_key,
                comment: column.comment,
                security_labels: column
                    .security_labels
                    .into_iter()
                    .map(|label| plugin::SecurityLabel {
                        provider: label.provider,
                        label: label.label,
                    })
                    .collect(),
            })
            .collect(),
        parent: relation.parent_table_schema.zip(relation.parent_table_name),
        definition: relation.definition,
        options: relation.options,
    }
}

fn function(function: Function) -> plugin::Function {
    plugin::Function {
        oid: function.oid as u32,
        schema: function.schema,
        name: function.name,
        kind: function.kind,
        argument_types: function.argument_types,
        argument_names: function.argument_names,
        argument_defaults: function.argument_defaults.max(0) as u16,
        variadic: function.variadic,
        return_type: function.return_type,
        result: function.result,
        returns_set: function.returns_set,
        output_names: function.output_names,
        output_types: function.output_types,
        language: function.language,
        source: function.source,
        sql_body: function.sql_body,
        volatility: function.volatility,
        security_definer: function.security_definer,
        strict: function.strict,
        config: function.config,
        extension: function.extension,
    }
}

fn operator(operator: Operator) -> plugin::Operator {
    plugin::Operator {
        oid: operator.oid as u32,
        schema: operator.schema,
        name: operator.name,
        left_type: operator.left_type,
        right_type: operator.right_type,
        result_type: operator.result_type,
        function_oid: operator.function_oid as u32,
        function_schema: operator.function_schema,
        function_name: operator.function_name,
    }
}
