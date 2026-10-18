---
title: Error and notice redaction
description: How the plugin keeps row values in Postgres errors and notices away from masked users.
---

Postgres errors can quote the data a statement touched:

```text
ERROR:  new row for relation "users" violates check constraint "users_name_check"
DETAIL:  Failing row contains (1, forbidden, 123-45-6789, alice@example.com).
```

```text
ERROR:  duplicate key value violates unique constraint "users_ssn_key"
DETAIL:  Key (ssn)=(123-45-6789) already exists.
```

In `enforce` mode, the plugin removes `DETAIL` from every `ErrorResponse` and `NoticeResponse` Postgres sends a masked user, not only those of statements on masked tables: triggers and functions can raise errors about other tables. This session-wide scrub removes `DETAIL` only; [per-statement redaction](#per-statement-redaction) replaces the whole message of some statements, for users with proxy masks and for every masked user reading a [view queried like a table](#views-queried-like-tables). The severity and SQLSTATE reach the client unchanged, so applications keep handling errors correctly. Exempt users keep `DETAIL`, and so does everyone in `shadow` mode, which doesn't change what clients receive.

To keep `DETAIL` for masked users, turn it off:

```toml
[general]
scrub_error_detail = false
```

The setting is ignored for users with [proxy masks](../proxy-masks/): they always lose `DETAIL`. A check constraint's `Failing row contains (…)` on an `UPDATE` of other columns would otherwise show real proxy-masked values.

## Other fields

Outside the statements below, only `DETAIL` is removed. Other fields, such as the message itself, are left as they are. SQL masks prevent most leaks through them: for example, with a SQL mask on `ssn`, `SELECT ssn::int FROM users` casts the masked value, so its error quotes the mask, not the real value. The same holds for views the plugin inlines, but not for a [view queried like a table](#views-queried-like-tables), whose definition runs on real values. Messages from functions in `udf_allowlist` and extensions in `extension_allowlist` are your responsibility.

## Per-statement redaction

Proxy masks leave the statement as written, so Postgres computes on real values, and its errors can quote them: `SELECT ssn::int FROM users` fails with `invalid input syntax for type integer: "123-45-6789"`. For these statements, the plugin asks PgDog to replace the message of every error and notice the statement causes:

```text
ERROR:  error message removed: the statement reads values this user can't see
```

PgDog keeps the severity, the SQLSTATE, the position in the statement, and the names of the objects involved (schema, table, column, data type and constraint), so applications can still handle the error. Everything else, including the message, `DETAIL`, `HINT` and `CONTEXT`, is removed.

For a user with proxy masks, a statement's errors are redacted when it:

- **computes with a proxy-masked column**: uses it anywhere other than as a whole output column, such as in a condition, a join, a `GROUP BY`, `ORDER BY` or `DISTINCT ON` that names it (or an output alias of it) or an expression over it, `LIMIT`, a function argument, a cast, `ROW(…)`, a subquery's value or an `UPDATE … SET` value, or references the whole row of a table with proxy-masked columns;
- **calls a function or reads a view** whose body reads proxy-masked columns, or writes, including the functions of the commutators and negators the planner may run in place of a user-defined operator. A [view queried like a table](#views-queried-like-tables) counts for SQL-masked columns too;
- **converts a value to a type that isn't built in**, such as a domain: by a cast, by passing it to a function parameter of that type, or as a function's result. A domain's checks and a user-defined cast's function run, and may write;
- **writes, maintains, alters or commits**, whatever the table: `INSERT`, `UPDATE`, `DELETE` and `COPY … FROM`, directly, through a view, in a CTE, under `EXPLAIN`, or in the body of a SQL function the statement calls; `TRUNCATE`, `VACUUM`, `ANALYZE`, `LOCK` and DDL; `COMMIT` and `PREPARE TRANSACTION`. Triggers, constraints, defaults, index expressions, row security policies and event triggers run on real values, of any table, and can put them in a message. Deferred constraint triggers fire at `COMMIT`;
- is a **`FETCH` or `MOVE`**, or contains an **`EXECUTE`**. Their rows come from a statement checked earlier.

A position such as `ORDER BY 1`, `GROUP BY 1` or `DISTINCT ON (1)` refers to the output column and doesn't count, and neither does plain `DISTINCT`. Plain `EXPLAIN` follows the same rules: planning can raise errors on constants, such as a cast in a condition. In a query with several statements, the errors of all of them are redacted if one needs it, so `BEGIN; …; COMMIT` sent as one query is redacted. A read-only statement that only returns proxy-masked columns, such as `SELECT id, ssn FROM users WHERE id = $1`, keeps its messages.

### Views queried like tables

A view queried like a table (`security_barrier`, `security_invoker`, with masked columns of its own, or every view with `inline_views = false`) has only its columns masked. Its definition runs on real values, whatever the user's masks. With

```sql
CREATE VIEW err_sb WITH (security_barrier) AS
  SELECT id FROM users WHERE ssn::int > 0;
```

`SELECT id FROM err_sb` fails with `invalid input syntax for type integer: "123-45-6789"`, also for a user with a SQL mask on `ssn`, and the value is in the message, not in `DETAIL`. So for every masked user, including users with only SQL masks, a statement's errors are redacted when it reads, or writes through, a view queried like a table whose definition:

- computes with a column masked for the user, SQL or proxy, in any of the ways listed above, such as the cast in `err_sb`'s condition, or calls a SQL function whose body reads one;
- calls a function that writes, or one the plugin can't analyze, such as a PL/pgSQL row filter in `WHERE can_see(id)`: it may read masked columns on its own;
- converts a value to a type that isn't built in.

Statements that read such a view through another view, or through a SQL function, are redacted too. A definition that only passes masked columns through as its own columns, and filters on unmasked ones, doesn't make the statement redacted. Views the plugin inlines don't need this: their SQL-masked columns are rewritten like the statement's, so with the same definition inlined, the error quotes the mask. Materialized views don't either: their definition runs only on `REFRESH`.

Redaction needs no configuration. Exempt users and `shadow` mode aren't affected. Users with only SQL masks are affected only by [views queried like tables](#views-queried-like-tables).
