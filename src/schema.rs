//! Load a database's catalog the way PgDog does for CATALOG plugins: with PgDog's
//! own catalog queries, converted into the `Catalog` PgDog sends to plugins.
//! Used by `pgdog-mask validate` and the tests, with the `cli` feature.
use std::collections::HashMap;

use pgdog_plugin::{CatalogParts, catalog as plugin};
use pgdog_stats::{Column, Function, Operator, Relation, SecurityLabel};
use thiserror::Error;
use tokio_postgres::{Client, SimpleQueryMessage};

use crate::catalog::Catalog;

// PgDog's schema loader queries (pgdog/src/backend/schema/*.sql), copied from the
// PgDog revision in Cargo.toml. Update them together.
const RELATIONS: &str = include_str!("schema/relations.sql");
const COLUMNS: &str = include_str!("schema/columns_catalog.sql");
const VIEWS: &str = include_str!("schema/views.sql");
const FUNCTIONS: &str = include_str!("schema/functions.sql");
const OPERATORS: &str = include_str!("schema/operators.sql");

#[derive(Debug, Error)]
pub enum Error {
    #[error("catalog query failed: {0}")]
    Query(#[from] tokio_postgres::Error),

    #[error("catalog row isn't valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

type Row = Vec<Option<String>>;

/// Run a catalog query. Like PgDog, queries that print names run with an empty
/// `search_path`, so names come back schema-qualified.
async fn rows(client: &Client, query: &str, qualified: bool) -> Result<Vec<Row>, Error> {
    let sql = if qualified {
        format!("SET LOCAL search_path TO ''; {query}")
    } else {
        query.to_owned()
    };
    Ok(client
        .simple_query(&sql)
        .await?
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(
                (0..row.len())
                    .map(|i| row.get(i).map(str::to_owned))
                    .collect(),
            ),
            _ => None,
        })
        .collect())
}

fn text(row: &Row, i: usize) -> String {
    row.get(i).cloned().flatten().unwrap_or_default()
}

fn json<T: serde::de::DeserializeOwned>(row: &Row) -> Result<T, Error> {
    Ok(serde_json::from_str(&text(row, 0))?)
}

/// The catalog PgDog would send the plugin for the connected database, limited
/// to `schemas` if given.
pub async fn load_catalog(
    client: &Client,
    schemas: Option<&[&str]>,
    search_path: &[&str],
) -> Result<Catalog, Error> {
    let in_schemas = |schema: &str| schemas.is_none_or(|schemas| schemas.contains(&schema));

    let mut relations: HashMap<(String, String), Relation> = HashMap::new();
    for row in rows(client, RELATIONS, false).await? {
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

    for row in rows(client, COLUMNS, true).await? {
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
            type_oid: text(&row, 12).parse().unwrap_or_default(),
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
    for row in rows(client, VIEWS, true).await? {
        let view: View = json(&row)?;
        if let Some(relation) = relations.get_mut(&(view.schema, view.name)) {
            relation.definition = view.definition;
            relation.options = view.options;
        }
    }

    let functions_sql =
        FUNCTIONS.replace("{sql_body}", "pg_catalog.pg_get_function_sqlbody(p.oid)");
    let functions: Vec<Function> = rows(client, &functions_sql, true)
        .await?
        .iter()
        .map(json::<Function>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|function| in_schemas(&function.schema))
        .collect();
    let operators: Vec<Operator> = rows(client, OPERATORS, true)
        .await?
        .iter()
        .map(json::<Operator>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|operator| in_schemas(&operator.schema))
        .collect();
    let system_functions = rows(
        client,
        "SELECT DISTINCT proname::text FROM pg_catalog.pg_proc WHERE pronamespace = 'pg_catalog'::regnamespace ORDER BY 1",
        false,
    )
    .await?
    .iter()
    .map(|row| text(row, 0))
    .collect();

    // Converted like PgDog does (pgdog/src/plugin/catalog.rs).
    let mut relations: Vec<_> = relations.into_values().map(relation).collect();
    relations.sort_by(|a, b| (&a.schema, &a.name).cmp(&(&b.schema, &b.name)));
    let mut catalog = plugin::Catalog::new(CatalogParts::ALL);
    catalog.search_path = search_path.iter().map(|s| (*s).to_owned()).collect();
    catalog.relations = relations;
    catalog.functions = functions.into_iter().map(function).collect();
    catalog.system_functions = system_functions;
    catalog.operators = operators.into_iter().map(operator).collect();
    Ok(Catalog::from_plugin(&catalog))
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
    let mut out = plugin::Relation::new(relation.schema, relation.name, kind);
    out.columns = relation.columns.into_values().map(column).collect();
    out.parent = relation.parent_table_schema.zip(relation.parent_table_name);
    out.definition = relation.definition;
    out.options = relation.options;
    out
}

fn column(column: Column) -> plugin::Column {
    let mut out = plugin::Column::new(column.column_name, column.data_type);
    out.type_name = column.type_name;
    out.type_oid = column.type_oid;
    out.is_primary_key = column.is_primary_key;
    out.comment = column.comment;
    out.security_labels = column
        .security_labels
        .into_iter()
        .map(|label| plugin::SecurityLabel::new(label.provider, label.label))
        .collect();
    out
}

fn function(function: Function) -> plugin::Function {
    let mut out = plugin::Function::new(function.oid as u32, function.schema, function.name);
    out.kind = function.kind;
    out.argument_types = function.argument_types;
    out.argument_names = function.argument_names;
    out.argument_defaults = function.argument_defaults.max(0) as u16;
    out.variadic = function.variadic;
    out.return_type = function.return_type;
    out.result = function.result;
    out.returns_set = function.returns_set;
    out.output_names = function.output_names;
    out.output_types = function.output_types;
    out.language = function.language;
    out.source = function.source;
    out.sql_body = function.sql_body;
    out.volatility = function.volatility;
    out.security_definer = function.security_definer;
    out.strict = function.strict;
    out.config = function.config;
    out.extension = function.extension;
    out
}

fn operator(operator: Operator) -> plugin::Operator {
    let mut out = plugin::Operator::new(operator.oid as u32, operator.schema, operator.name);
    out.left_type = operator.left_type;
    out.right_type = operator.right_type;
    out.result_type = operator.result_type;
    out.function_oid = operator.function_oid as u32;
    out.function_schema = operator.function_schema;
    out.function_name = operator.function_name;
    out
}
