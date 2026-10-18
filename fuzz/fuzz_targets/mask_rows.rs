//! The mask hook: batches of result rows for proxy-masked columns, with valid,
//! NULL and unknown mask IDs, declared and mismatched types, both formats, and
//! arbitrary values.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pgdog_mask::pgdog_plugin::types::{DataType, Datum, Format};
use pgdog_mask::pgdog_plugin::{ColumnTransform, HookError, TransformBatch, TransformColumn, TransformId, Value};
use pgdog_mask_fuzz::fixture::{proxy_masks, type_oid};
use pgdog_mask_fuzz::plugin;

const MAX_ROWS: usize = 32;
const MAX_COLUMNS: usize = 6;

/// Types worth decoding.
const TYPES: &[&str] = &[
    "boolean",
    "bytea",
    "bigint",
    "smallint",
    "integer",
    "text",
    "real",
    "double precision",
    "character",
    "character varying",
    "date",
    "timestamp without time zone",
    "timestamp with time zone",
    "numeric",
    "uuid",
    "jsonb",
];

#[derive(Debug, Arbitrary)]
struct Input {
    rows: u8,
    columns: Vec<ColumnInput>,
}

#[derive(Debug, Arbitrary)]
struct ColumnInput {
    mask: MaskChoice,
    type_oid: TypeChoice,
    binary: bool,
    values: Vec<Option<Vec<u8>>>,
}

#[derive(Debug, Arbitrary)]
enum MaskChoice {
    Proxy(u8),
    /// PgDog applies NULL masks itself, but one passed anyway must give NULLs.
    Null,
    Id(u64),
}

#[derive(Debug, Arbitrary)]
enum TypeChoice {
    /// The column's own type.
    Declared,
    Known(u8),
    Oid(u32),
}

/// Known issue, skipped so it doesn't hide new findings: binary timestamps
/// within the last ~950 billion microseconds of Postgres's range (294276 AD)
/// overflow when converted to the Unix epoch (pgdog-postgres-types), which
/// panics with overflow checks on.
fn overflows_timestamp(type_oid: u32, format: Format, value: &[u8]) -> bool {
    const POSTGRES_EPOCH_MICROS: i64 = 946_684_800_000_000;
    let Ok(bytes) = <[u8; 8]>::try_from(value) else {
        return false;
    };
    let micros = i64::from_be_bytes(bytes);
    matches!(type_oid, 1114 | 1184)
        && format == Format::Binary
        && micros != i64::MAX
        && micros.checked_add(POSTGRES_EPOCH_MICROS).is_none()
}

/// The plugin decodes values with the column's type; types with the same
/// representation as text decode as text.
fn data_type(type_oid: u32) -> DataType {
    match type_oid {
        1042 | 19 => DataType::Text,
        oid => DataType::from_oid(oid as i32),
    }
}

fuzz_target!(|input: Input| {
    let plugin = plugin();
    let proxies = proxy_masks();
    let rows = input.rows as usize % (MAX_ROWS + 1);

    let masks: Vec<(ColumnTransform, Format)> = input
        .columns
        .iter()
        .take(MAX_COLUMNS)
        .map(|column| {
            let mut mask = match column.mask {
                MaskChoice::Proxy(i) => proxies[i as usize % proxies.len()],
                MaskChoice::Null => ColumnTransform::null(0),
                MaskChoice::Id(id) => ColumnTransform::new(0, TransformId(id), 25),
            };
            mask.type_oid = match column.type_oid {
                TypeChoice::Declared => mask.type_oid,
                TypeChoice::Known(i) => type_oid(TYPES[i as usize % TYPES.len()]),
                TypeChoice::Oid(oid) => oid,
            };
            let format = if column.binary {
                Format::Binary
            } else {
                Format::Text
            };
            (mask, format)
        })
        .collect();
    // Every column of a batch has one value per row.
    let values: Vec<Vec<Value<'_>>> = input
        .columns
        .iter()
        .take(MAX_COLUMNS)
        .map(|column| {
            (0..rows)
                .map(|row| Value::new(column.values.get(row).and_then(Option::as_deref)))
                .collect()
        })
        .collect();
    let known_issue = masks.iter().zip(&values).any(|((mask, format), values)| {
        values
            .iter()
            .filter_map(Value::get)
            .any(|value| overflows_timestamp(mask.type_oid, *format, value))
    });
    if known_issue {
        return;
    }
    let columns: Vec<TransformColumn<'_>> = masks
        .iter()
        .zip(&values)
        .map(|((mask, format), values)| TransformColumn::new(mask, *format, values))
        .collect();
    let batch = TransformBatch::new(rows as u32, &columns);

    let known =
        |mask: &ColumnTransform| mask.is_null() || proxies.iter().any(|proxy| proxy.transform == mask.transform);
    let masked = match plugin.transform_rows(&batch) {
        Ok(masked) => masked,
        // Unmaskable values fail the result; that's the contract.
        Err(HookError::Failed(_)) => return,
        Err(err) => panic!("mask hook failed: {err}"),
    };
    assert!(
        masks.iter().all(|(mask, _)| known(mask)),
        "unknown mask IDs must fail"
    );
    assert_eq!(masked.len(), columns.len() * rows);

    for (c, ((mask, format), values)) in masks.iter().zip(&values).enumerate() {
        for (row, value) in values.iter().enumerate() {
            let out = masked.get(c * rows + row);
            if mask.is_null() {
                assert_eq!(out, None, "a NULL mask returned a value");
                continue;
            }
            match (value.get(), out) {
                (None, None) => (),
                (None, Some(_)) => panic!("NULL masked to a value"),
                (Some(_), None) => (),
                (Some(_), Some(bytes)) => {
                    // Masked values have the column's type.
                    if let Err(err) = Datum::new(bytes, data_type(mask.type_oid), *format, false) {
                        panic!(
                            "masked value of type {} doesn't decode: {err}",
                            mask.type_oid
                        );
                    }
                }
            }
        }
    }
});
