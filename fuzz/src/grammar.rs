//! SQL statements generated from fuzzer input, over the fixture schema.
//!
//! Random bytes rarely parse as SQL, so this target builds statements that do:
//! queries, writes, `COPY`, cursors and utility statements over the fixture's
//! tables, views and functions, with every kind of literal so the statement
//! shape cache is exercised too.
//!
//! While generating, it records whether the statement reads a masked column
//! for [`MASKED_USER`](crate::fixture::MASKED_USER): a reference in any
//! expression, `*` or a whole-row reference over a masked column, `COPY` of a
//! masked table, or a call of a function computed from masked columns. Such
//! a statement must never be allowed as is.
use std::sync::LazyLock;

use arbitrary::{Result, Unstructured};
use pgdog_mask::pgdog_plugin::catalog::{Relation, RelationKind};

use crate::fixture::{MASKED_FUNCTIONS, masked, relations};

/// Expression nesting, beyond which expressions are leaves.
const MAX_DEPTH: u32 = 4;

/// A generated statement.
#[derive(Debug)]
pub struct Generated {
    pub sql: String,
    /// The statement reads a masked column.
    pub reads_masked: bool,
}

/// Generate a statement.
pub fn statement(u: &mut Unstructured<'_>) -> Result<Generated> {
    let mut generator = Generator {
        u,
        scopes: vec![],
        aliases: 0,
        reads_masked: false,
        counting: true,
    };
    let sql = generator.top_level(true)?;
    Ok(Generated {
        sql,
        reads_masked: generator.reads_masked,
    })
}

static RELATIONS: LazyLock<Vec<Relation>> = LazyLock::new(relations);

/// A `FROM` item in scope: its alias and columns.
#[derive(Debug, Clone)]
struct Item {
    alias: String,
    /// Column names, and whether each is masked.
    columns: Vec<(String, bool)>,
}

impl Item {
    fn any_masked(&self) -> bool {
        self.columns.iter().any(|(_, masked)| *masked)
    }
}

struct Generator<'a, 'u> {
    u: &'a mut Unstructured<'u>,
    /// `FROM` items by query level, innermost last.
    scopes: Vec<Vec<Item>>,
    aliases: usize,
    reads_masked: bool,
    /// Reads count towards `reads_masked`. Off under `EXPLAIN`, which returns no rows.
    counting: bool,
}

/// Functions masked users may call on any value, with their arity.
const FUNCTIONS: &[(&str, usize)] = &[
    ("upper", 1),
    ("lower", 1),
    ("length", 1),
    ("md5", 1),
    ("btrim", 1),
    ("reverse", 1),
    ("substr", 2),
    ("left", 2),
    ("right", 2),
    ("concat", 2),
    ("coalesce", 2),
    ("nullif", 2),
    ("greatest", 2),
    ("format", 2),
    ("to_char", 2),
    ("pg_catalog.upper", 1),
    ("last4", 1),
    ("public.last4", 1),
    ("safe_fn", 1),
    ("same", 2),
    ("recursive_fn", 1),
    ("count_users", 0),
    ("plpgsql_fn", 0),
    ("now", 0),
    ("unknown_fn", 1),
    ("pg_sleep", 1),
    ("set_config", 3),
    ("current_setting", 1),
    // Computed from masked columns.
    ("user_ssn", 1),
    ("public.user_ssn_p", 1),
    ("user_ssn_definer", 1),
    ("atomic_ssn", 1),
    ("volatile_ssn", 1),
    ("ssn_eq", 2),
];

const AGGREGATES: &[&str] = &["count", "max", "min", "sum", "avg", "array_agg", "bool_or"];

const BINARY: &[&str] = &[
    "=",
    "<>",
    "<",
    ">",
    "<=",
    ">=",
    "+",
    "-",
    "*",
    "/",
    "%",
    "||",
    "AND",
    "OR",
    "LIKE",
    "ILIKE",
    "~",
    "~~",
    "!~",
    "===",
    "@@@",
    "IS DISTINCT FROM",
    "IS NOT DISTINCT FROM",
    "SIMILAR TO",
];

const TYPES: &[&str] = &[
    "text",
    "varchar(4)",
    "integer",
    "bigint",
    "numeric",
    "boolean",
    "bytea",
    "date",
    "json",
    "jsonb",
    "regclass",
    "name",
];

const UTILITY: &[&str] = &[
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "SET search_path TO public",
    "SET LOCAL search_path TO pg_catalog",
    "RESET ALL",
    "SHOW search_path",
    "DISCARD ALL",
    "LISTEN chan",
    "NOTIFY chan, 'x'",
    "VACUUM users",
    "ANALYZE users",
    "LOCK TABLE users",
    "TRUNCATE orders",
    "DEALLOCATE ALL",
    "CLOSE ALL",
    "FETCH ALL FROM c",
    "EXECUTE p",
    "SET ROLE pii_admin",
    "SET SESSION AUTHORIZATION admin",
    "ALTER TABLE users ADD COLUMN x text",
    "DROP TABLE orders",
    "CREATE INDEX ON users (ssn)",
    "COMMENT ON COLUMN users.ssn IS 'x'",
    "SECURITY LABEL ON COLUMN users.ssn IS 'x'",
    "GRANT SELECT ON users TO PUBLIC",
    "DO $$ BEGIN PERFORM 1; END $$",
    "CALL some_procedure()",
];

impl Generator<'_, '_> {
    fn pick<'s>(&mut self, items: &'s [&'s str]) -> Result<&'s str> {
        self.u.choose(items).copied()
    }

    fn alias(&mut self, prefix: &str) -> String {
        self.aliases += 1;
        format!("{prefix}{}", self.aliases)
    }

    fn read(&mut self, masked: bool) {
        if masked && self.counting {
            self.reads_masked = true;
        }
    }

    fn top_level(&mut self, several: bool) -> Result<String> {
        Ok(match self.u.int_in_range(0..=15)? {
            0..=4 => self.select(0)?.0,
            5 => self.insert()?,
            6 => self.update()?,
            7 => self.delete()?,
            8 => format!("COPY ({}) TO STDOUT", self.select(0)?.0),
            9 => self.copy_table()?,
            10 => {
                let counting = self.counting;
                self.counting = false;
                let verbose = if self.u.arbitrary()? { "VERBOSE " } else { "" };
                let sql = format!("EXPLAIN {verbose}{}", self.select(0)?.0);
                self.counting = counting;
                sql
            }
            11 if several => {
                let first = self.top_level(false)?;
                let second = self.top_level(false)?;
                format!("{first}; {second}")
            }
            11 => self.select(0)?.0,
            12 => match self.u.int_in_range(0..=3)? {
                0 => format!("PREPARE p AS {}", self.select(0)?.0),
                1 => format!("DECLARE c CURSOR FOR {}", self.select(0)?.0),
                2 => format!("CREATE TEMP TABLE t AS {}", self.select(0)?.0),
                _ => format!("CREATE MATERIALIZED VIEW mv AS {}", self.select(0)?.0),
            },
            13 => self.pick(UTILITY)?.to_owned(),
            14 => self.dynamic_sql()?,
            _ => {
                // A leading comment, as PgDog routing hints are sent.
                let comment = self.comment()?;
                format!("/* {comment} */ {}", self.select(0)?.0)
            }
        })
    }

    /// Functions that run SQL given as text.
    fn dynamic_sql(&mut self) -> Result<String> {
        if self.u.arbitrary()? {
            let (query, _) = self.select(0)?;
            Ok(format!(
                "SELECT query_to_xml({}, true, false, '')",
                quote(&query)
            ))
        } else {
            let relation = self.relation()?;
            let any_masked = relation
                .columns
                .iter()
                .any(|c| masked(&relation.name, &c.name));
            self.read(any_masked);
            Ok(format!(
                "SELECT table_to_xml({}, true, false, '')",
                quote(&format!("public.{}", relation.name))
            ))
        }
    }

    fn comment(&mut self) -> Result<String> {
        let text: String = self.u.arbitrary()?;
        Ok(text.replace("*/", "").replace('\0', ""))
    }

    fn relation(&mut self) -> Result<&'static Relation> {
        self.u.choose(&RELATIONS)
    }

    /// A fixture relation, as a `FROM` item.
    fn table_item(&mut self) -> Result<(String, Item)> {
        let relation = self.relation()?;
        let alias = self.alias("t");
        let qualified = if self.u.arbitrary()? { "public." } else { "" };
        let only = if relation.kind == RelationKind::Table && self.u.ratio(1, 8)? {
            "ONLY "
        } else {
            ""
        };
        let columns = relation
            .columns
            .iter()
            .map(|c| (c.name.clone(), masked(&relation.name, &c.name)))
            .collect();
        Ok((
            format!("{only}{qualified}{} AS {alias}", relation.name),
            Item { alias, columns },
        ))
    }

    /// A `FROM` item: a table, subquery, set-returning function or series.
    fn source(&mut self, depth: u32) -> Result<(String, Item)> {
        match self.u.int_in_range(0..=5)? {
            0 if depth < MAX_DEPTH => {
                let lateral = if self.u.arbitrary()? { "LATERAL " } else { "" };
                let (sql, columns) = self.select(depth + 1)?;
                let alias = self.alias("s");
                Ok((
                    format!("{lateral}({sql}) AS {alias}"),
                    Item {
                        alias,
                        columns: columns.into_iter().map(|c| (c, false)).collect(),
                    },
                ))
            }
            1 => {
                // Returns masked values in `ssn`.
                let alias = self.alias("f");
                Ok((
                    format!("public.ssns() AS {alias}(id bigint, ssn text)"),
                    Item {
                        alias,
                        columns: vec![("id".into(), false), ("ssn".into(), true)],
                    },
                ))
            }
            2 => {
                let alias = self.alias("g");
                Ok((
                    format!("generate_series(1, 3) AS {alias}(n)"),
                    Item {
                        alias,
                        columns: vec![("n".into(), false)],
                    },
                ))
            }
            _ => self.table_item(),
        }
    }

    /// A `SELECT`, and the names of its output columns.
    fn select(&mut self, depth: u32) -> Result<(String, Vec<String>)> {
        let mut sql = String::new();
        let mut items = vec![];

        if depth == 0 && self.u.ratio(1, 6)? {
            let mut ctes = vec![];
            for _ in 0..self.u.int_in_range(1..=2)? {
                self.scopes.push(vec![]);
                let (cte, columns) = self.select(depth + 1)?;
                self.scopes.pop();
                let name = self.alias("cte");
                ctes.push(format!("{name} AS ({cte})"));
                // Referenced below, so it always runs.
                let alias = self.alias("c");
                items.push((
                    format!("{name} AS {alias}"),
                    Item {
                        alias,
                        columns: columns.into_iter().map(|c| (c, false)).collect(),
                    },
                ));
            }
            sql.push_str(&format!("WITH {} ", ctes.join(", ")));
        }

        self.scopes.push(vec![]);
        let mut from = String::new();
        for (sql, item) in items {
            self.push_item(&mut from, sql, item, depth)?;
        }
        for _ in 0..self.u.int_in_range(0..=3)? {
            let (sql, item) = self.source(depth)?;
            self.push_item(&mut from, sql, item, depth)?;
        }

        sql.push_str("SELECT ");
        if self.u.ratio(1, 8)? {
            sql.push_str("DISTINCT ");
        }
        let mut columns = vec![];
        let mut targets = vec![];
        for i in 0..self.u.int_in_range(1..=4)? {
            let in_scope = self.scopes.last().cloned().unwrap_or_default();
            match self.u.int_in_range(0..=7)? {
                0 if !in_scope.is_empty() => {
                    for item in &in_scope {
                        self.read(item.any_masked());
                        columns.extend(item.columns.iter().map(|(name, _)| name.clone()));
                    }
                    targets.push("*".to_owned());
                }
                1 if !in_scope.is_empty() => {
                    let item = self.u.choose(&in_scope)?.clone();
                    self.read(item.any_masked());
                    columns.extend(item.columns.iter().map(|(name, _)| name.clone()));
                    targets.push(format!("{}.*", item.alias));
                }
                _ => {
                    let expr = self.expr(depth)?;
                    let name = format!("c{i}");
                    targets.push(format!("{expr} AS {name}"));
                    columns.push(name);
                }
            }
        }
        sql.push_str(&targets.join(", "));
        if !from.is_empty() {
            sql.push_str(" FROM ");
            sql.push_str(&from);
        }
        if self.u.ratio(1, 2)? {
            sql.push_str(&format!(" WHERE {}", self.expr(depth)?));
        }
        if self.u.ratio(1, 6)? {
            sql.push_str(&format!(" GROUP BY {}", self.expr(depth)?));
            if self.u.arbitrary()? {
                sql.push_str(&format!(" HAVING {}", self.expr(depth)?));
            }
        }
        if self.u.ratio(1, 4)? {
            let direction = self.pick(&["", " ASC", " DESC", " NULLS FIRST"])?;
            sql.push_str(&format!(" ORDER BY {}{direction}", self.expr(depth)?));
        }
        if self.u.ratio(1, 4)? {
            sql.push_str(&format!(" LIMIT {}", self.u.int_in_range(0..=100u8)?));
        }
        if self.u.ratio(1, 10)? {
            sql.push_str(" FOR UPDATE");
        }
        self.scopes.pop();

        if depth < MAX_DEPTH && self.u.ratio(1, 8)? {
            let op = self.pick(&["UNION", "UNION ALL", "INTERSECT", "EXCEPT"])?;
            let (other, _) = self.select(depth + 1)?;
            sql = format!("({sql}) {op} ({other})");
        }

        Ok((sql, columns))
    }

    /// Add a `FROM` item to the innermost scope, joined to the items before it.
    fn push_item(&mut self, from: &mut String, sql: String, item: Item, depth: u32) -> Result<()> {
        let first = from.is_empty();
        self.scopes
            .last_mut()
            .expect("a FROM list has a scope")
            .push(item);
        if first {
            from.push_str(&sql);
            return Ok(());
        }
        match self.u.int_in_range(0..=3)? {
            0 => from.push_str(&format!(", {sql}")),
            1 => from.push_str(&format!(" CROSS JOIN {sql}")),
            _ => {
                let join = self.pick(&["JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN"])?;
                let on = self.expr(depth)?;
                from.push_str(&format!(" {join} {sql} ON {on}"));
            }
        }
        Ok(())
    }

    fn expr(&mut self, depth: u32) -> Result<String> {
        if depth >= MAX_DEPTH {
            return self.leaf();
        }
        let next = depth + 1;
        Ok(match self.u.int_in_range(0..=17)? {
            0..=1 => self.literal()?,
            2..=4 => self.column()?,
            5 => {
                let left = self.expr(next)?;
                let op = self.pick(BINARY)?;
                let right = self.expr(next)?;
                format!("({left} {op} {right})")
            }
            6 => {
                let e = self.expr(next)?;
                match self.u.int_in_range(0..=3)? {
                    0 => format!("(NOT {e})"),
                    1 => format!("(- {e})"),
                    2 => format!("({e} IS NULL)"),
                    _ => format!("({e} IS NOT NULL)"),
                }
            }
            7 => self.call(next)?,
            8 => {
                let e = self.expr(next)?;
                let ty = self.pick(TYPES)?;
                format!("({e})::{ty}")
            }
            9 => {
                let when = self.expr(next)?;
                let then = self.expr(next)?;
                let other = self.expr(next)?;
                format!("(CASE WHEN {when} THEN {then} ELSE {other} END)")
            }
            10 => format!("({})", self.select(next)?.0),
            11 => format!("(EXISTS ({}))", self.select(next)?.0),
            12 => {
                let e = self.expr(next)?;
                if self.u.arbitrary()? {
                    format!("({e} IN ({}))", self.select(next)?.0)
                } else {
                    let a = self.expr(next)?;
                    let b = self.expr(next)?;
                    format!("({e} IN ({a}, {b}))")
                }
            }
            13 => self.whole_row()?,
            14 => {
                let agg = self.pick(AGGREGATES)?;
                if self.u.ratio(1, 4)? {
                    "count(*)".to_owned()
                } else {
                    let distinct = if self.u.ratio(1, 4)? { "DISTINCT " } else { "" };
                    format!("{agg}({distinct}{})", self.expr(next)?)
                }
            }
            15 => {
                // Only generate what's used: generating marks reads.
                let window = self.u.int_in_range(0..=2)?;
                let order = self.expr(next)?;
                match window {
                    0 => format!("row_number() OVER (ORDER BY {order})"),
                    1 => format!("lag({}) OVER (PARTITION BY {order})", self.expr(next)?),
                    _ => format!(
                        "first_value({}) OVER (ORDER BY {order} ROWS UNBOUNDED PRECEDING)",
                        self.expr(next)?
                    ),
                }
            }
            16 => {
                let a = self.expr(next)?;
                let b = self.expr(next)?;
                match self.u.int_in_range(0..=2)? {
                    0 => format!("ROW({a}, {b})"),
                    1 => format!("ARRAY[{a}, {b}]"),
                    _ => {
                        let c = self.expr(next)?;
                        format!("({a} BETWEEN {b} AND {c})")
                    }
                }
            }
            _ => format!("${}", self.u.int_in_range(1..=3u8)?),
        })
    }

    fn leaf(&mut self) -> Result<String> {
        if self.u.arbitrary()? {
            self.column()
        } else {
            self.literal()
        }
    }

    /// A column of an item in scope, from this query level or an outer one.
    fn column(&mut self) -> Result<String> {
        let levels: Vec<usize> = (0..self.scopes.len())
            .filter(|level| !self.scopes[*level].is_empty())
            .collect();
        if levels.is_empty() {
            return self.literal();
        }
        // Mostly the innermost level.
        let level = if self.u.ratio(3, 4)? {
            *levels.last().expect("not empty")
        } else {
            *self.u.choose(&levels)?
        };
        let innermost = level == self.scopes.len() - 1;
        let items = &self.scopes[level];
        let item = &items[self.u.choose_index(items.len())?];
        if item.columns.is_empty() {
            return self.literal();
        }
        let (name, masked) = item.columns[self.u.choose_index(item.columns.len())?].clone();
        // Unqualified only where it can't be ambiguous.
        let unqualified = innermost && items.len() == 1 && self.u.arbitrary()?;
        let sql = if unqualified {
            name
        } else {
            format!("{}.{name}", item.alias)
        };
        self.read(masked);
        Ok(sql)
    }

    /// A whole-row reference, which reads every column.
    fn whole_row(&mut self) -> Result<String> {
        let Some(items) = self.scopes.last().filter(|items| !items.is_empty()) else {
            return self.literal();
        };
        let item = items[self.u.choose_index(items.len())?].clone();
        self.read(item.any_masked());
        let f = self.pick(&["row_to_json", "to_jsonb", "to_json", "hstore"])?;
        Ok(format!("{f}({})", item.alias))
    }

    fn call(&mut self, depth: u32) -> Result<String> {
        let (name, arity) = *self.u.choose(FUNCTIONS)?;
        let bare = name.rsplit('.').next().unwrap_or(name);
        self.read(MASKED_FUNCTIONS.contains(&bare));
        let args = (0..arity)
            .map(|_| self.expr(depth))
            .collect::<Result<Vec<_>>>()?;
        Ok(format!("{name}({})", args.join(", ")))
    }

    fn literal(&mut self) -> Result<String> {
        Ok(match self.u.int_in_range(0..=13)? {
            0 => self.u.arbitrary::<i64>()?.to_string(),
            1 => self.u.int_in_range(-10..=10i8)?.to_string(),
            2 => {
                let f: f64 = self.u.arbitrary()?;
                if f.is_finite() {
                    format!("{f:?}")
                } else {
                    "1.5e3".to_owned()
                }
            }
            3 => quote(&self.text()?),
            4 => format!("E{}", quote(&self.text()?.replace('\\', "\\\\"))),
            5 => {
                let text = self.text()?.replace('$', "");
                format!("$${text}$$")
            }
            6 => "NULL".to_owned(),
            7 => self.pick(&["true", "false"])?.to_owned(),
            8 => format!("{}::text", quote(&self.text()?)),
            9 => "DATE '2024-01-01'".to_owned(),
            10 => "interval '1 day'".to_owned(),
            11 => "X'1F'".to_owned(),
            12 => self
                .pick(&["'123-45-6789'", "'a@b.c'", "'%'", "'_'", "''''", "'$1'"])?
                .to_owned(),
            _ => self
                .pick(&["current_user", "session_user", "CURRENT_DATE"])?
                .to_owned(),
        })
    }

    fn text(&mut self) -> Result<String> {
        let text: String = self.u.arbitrary()?;
        Ok(text.replace('\0', ""))
    }

    fn insert(&mut self) -> Result<String> {
        let relation = self.relation()?;
        let alias = self.alias("t");
        let count = self
            .u
            .int_in_range(1..=relation.columns.len().clamp(1, 3))?;
        let mut columns = vec![];
        for _ in 0..count {
            columns.push(self.u.choose(&relation.columns)?.name.clone());
        }
        let source = if self.u.arbitrary()? {
            // VALUES can't reference the table.
            self.scopes.push(vec![]);
            let values = (0..count)
                .map(|_| self.expr(1))
                .collect::<Result<Vec<_>>>()?;
            self.scopes.pop();
            format!("VALUES ({})", values.join(", "))
        } else {
            self.select(1)?.0
        };
        let conflict = if self.u.ratio(1, 4)? {
            " ON CONFLICT DO NOTHING"
        } else {
            ""
        };
        let item = Item {
            alias: alias.clone(),
            columns: relation
                .columns
                .iter()
                .map(|c| (c.name.clone(), masked(&relation.name, &c.name)))
                .collect(),
        };
        let returning = self.returning(item)?;
        Ok(format!(
            "INSERT INTO {} AS {alias} ({}) {source}{conflict}{returning}",
            relation.name,
            columns.join(", ")
        ))
    }

    fn update(&mut self) -> Result<String> {
        let (target, item) = self.table_item()?;
        self.scopes.push(vec![item.clone()]);
        let mut from = String::new();
        if self.u.ratio(1, 3)? {
            let (sql, other) = self.source(1)?;
            from = format!(" FROM {sql}");
            self.scopes.last_mut().expect("scope").push(other);
        }
        let mut sets = vec![];
        for _ in 0..self.u.int_in_range(1..=2)? {
            let (column, _) = self.u.choose(&item.columns)?.clone();
            let value = self.expr(1)?;
            sets.push(format!("{column} = {value}"));
        }
        let filter = self.filter()?;
        self.scopes.pop();
        let returning = self.returning(item)?;
        Ok(format!(
            "UPDATE {target} SET {}{from}{filter}{returning}",
            sets.join(", ")
        ))
    }

    fn delete(&mut self) -> Result<String> {
        let (target, item) = self.table_item()?;
        self.scopes.push(vec![item.clone()]);
        let mut using = String::new();
        if self.u.ratio(1, 3)? {
            let (sql, other) = self.source(1)?;
            using = format!(" USING {sql}");
            self.scopes.last_mut().expect("scope").push(other);
        }
        let filter = self.filter()?;
        self.scopes.pop();
        let returning = self.returning(item)?;
        Ok(format!("DELETE FROM {target}{using}{filter}{returning}"))
    }

    fn filter(&mut self) -> Result<String> {
        Ok(if self.u.arbitrary()? {
            format!(" WHERE {}", self.expr(1)?)
        } else {
            String::new()
        })
    }

    fn returning(&mut self, item: Item) -> Result<String> {
        if !self.u.ratio(1, 3)? {
            return Ok(String::new());
        }
        self.scopes.push(vec![item.clone()]);
        let sql = if self.u.arbitrary()? {
            self.read(item.any_masked());
            " RETURNING *".to_owned()
        } else {
            format!(" RETURNING {}", self.expr(1)?)
        };
        self.scopes.pop();
        Ok(sql)
    }

    fn copy_table(&mut self) -> Result<String> {
        let relation = self.relation()?;
        if self.u.arbitrary()? {
            // A write: reads nothing.
            return Ok(format!("COPY {} FROM STDIN", relation.name));
        }
        // Postgres only copies plain tables out; views fail.
        let table = relation.kind == RelationKind::Table;
        if self.u.arbitrary()? {
            let column = self.u.choose(&relation.columns)?;
            self.read(table && masked(&relation.name, &column.name));
            Ok(format!(
                "COPY {} ({}) TO STDOUT",
                relation.name, column.name
            ))
        } else {
            let any_masked = relation
                .columns
                .iter()
                .any(|c| masked(&relation.name, &c.name));
            self.read(table && any_masked);
            Ok(format!("COPY {} TO STDOUT", relation.name))
        }
    }
}

/// A string literal.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}
