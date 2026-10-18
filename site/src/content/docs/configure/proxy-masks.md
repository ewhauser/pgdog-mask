---
title: Proxy masks
description: Mask result columns in code, with keyed hashes, format-preserving encryption, vault tokens or your own logic, while Postgres runs the statement unchanged.
---

SQL masks are expressions Postgres evaluates. Some masks shouldn't or can't be written that way:

- a **keyed hash** whose key must never appear in a statement, where `pg_stat_statements`, server logs and `EXPLAIN` would expose it;
- **format-preserving encryption**, which Postgres doesn't implement;
- **tokens from a vault**, which Postgres can't call;
- any **logic you write in Rust**.

A proxy mask is computed by the plugin, on the rows Postgres returns, before they reach the client. The statement isn't rewritten for the column: Postgres runs it on real values, with the same plan, indexes and rows as for an unmasked user. That lets a trusted engineer run, or `EXPLAIN`, the application's exact SQL without receiving the protected values.

:::caution[For trusted roles]
Conditions, joins and ordering run on real values, so a user with a proxy mask can confirm a guessed value with `WHERE`, or rank rows by it with `ORDER BY`. Give proxy masks to roles you trust not to probe, and keep a SQL mask as the default for everyone else. See [Security model](#security-model).
:::

```toml
[[policies]]
name = "ssn"
data_type = "character varying"
mask = "null"                              # everyone else: a SQL mask

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"

[[policies.rules]]
roles = ["engineer"]
mask = "proxy"
proxy = "hmac_sha256"                      # the proxy mask's registered name
options = { key_env = "SSN_HMAC_KEY" }     # passed to the mask

[[masked_columns]]
name = "users"
column = "ssn"
policy = "ssn"
```

Admins see real values, engineers get HMAC tokens computed in the plugin, and everyone else gets `NULL`, in the statement. A user whose profile includes any proxy mask is a **user with proxy masks**; a few rules below apply only to them. The examples on this page run as a user with the `engineer` role.

## How proxy masks apply

- **The statement isn't rewritten for proxy-masked columns.** References to them are left as written wherever they appear, so conditions, joins, grouping, ordering and limits run on real values, and Postgres plans the statement it would plan for an unmasked user. The plugin only makes rewrites that don't change the plan: it expands `*` into column names, and inlines views, as Postgres itself does. Columns with SQL masks in the same statement are rewritten as usual.
- **Output columns that pass the column through get the proxy mask.** That's a plain reference, optionally aliased, or `*`, at any depth: through subqueries, CTEs, views, and `UNION` branches that all pass the same column.
- **Outputs computed from the column return `NULL`**: function calls, operators, casts, aggregates, window functions, `CASE`, scalar subqueries, and `UNION` with a branch that returns something else.
- **Statements that would move values where PgDog can't mask them are blocked**: writes from the column, `CREATE TABLE AS`, `COPY … TO`, cursors, and side effects such as `set_config`. Writing new values into the column, from parameters or literals, is allowed.
- **Errors are redacted** for statements that compute with the column, and for every statement that writes, maintains, alters or commits. See [Error and notice redaction](../errors/#per-statement-redaction).

| Statement | What happens |
| --- | --- |
| `SELECT ssn FROM users` | Sent unchanged. `ssn` gets the proxy mask. |
| `SELECT * FROM users` | `*` is expanded into column names, so the plugin knows where `ssn` lands. `ssn` gets the proxy mask. |
| `SELECT s.ssn FROM (SELECT ssn FROM users) s` | The proxy mask: the subquery passes `ssn` through. |
| `WITH s AS (SELECT id, ssn FROM users) SELECT ssn FROM s` | The proxy mask. |
| `SELECT ssn FROM user_ssns`, a view selecting `users.ssn` | The view is inlined, and its `ssn` gets the proxy mask. |
| `SELECT ssn FROM users UNION ALL SELECT ssn FROM users_2024` | The proxy mask: both branches pass `ssn` through (`users_2024` is a partition of `users`). |
| `SELECT ssn FROM users UNION ALL SELECT name FROM users` | `NULL`: one branch returns another column. |
| `SELECT upper(ssn) FROM users` | `NULL`: computed from `ssn`. Errors are redacted. |
| `SELECT id, row_number() OVER (ORDER BY ssn) FROM users` | `id` as is. The `row_number()` column is `NULL`: it's computed from the order of `ssn`. |
| `SELECT (SELECT ssn FROM users WHERE id = 1)` | `NULL`: a scalar subquery is treated as a computation. |
| `SELECT id FROM users WHERE ssn = $1` | Sent unchanged. The condition compares real values and finds the matching rows. Errors are redacted. |
| `SELECT ssn FROM users ORDER BY ssn DESC LIMIT 5 OFFSET 2` | Sorted by real values; `ssn` gets the proxy mask. Errors are redacted. |
| `UPDATE users SET name = $1 WHERE id = $2 RETURNING ssn` | `ssn` gets the proxy mask. Errors are redacted, because the statement writes: triggers and constraints run on real values. |
| `SELECT JSON_ARRAY(SELECT ssn FROM users)` | `NULL`: aggregated from `ssn`, like `ARRAY(SELECT ssn FROM users)`. |
| `SELECT 1; SELECT ssn FROM users` | Each statement's results are masked separately: `ssn` in the second result gets the proxy mask. |
| `UPDATE users SET name = ssn WHERE id = 1` | Blocked: it would copy `ssn` into a column PgDog can't mask. |
| `CREATE TABLE scratch AS SELECT id, ssn FROM users` | Blocked. |
| `COPY users TO STDOUT` | Blocked: `COPY` data isn't masked. List the columns without `ssn`, or use `SELECT`. |
| `DECLARE c CURSOR FOR SELECT id FROM users WHERE ssn::int > 5` | Blocked: see [Statements that run later](#statements-that-run-later). |
| `EXECUTE p(1)` | Blocked, unless `p` was prepared earlier in the same query. |
| `PREPARE p AS SELECT id, name FROM users WHERE id = $1; EXECUTE p(1)` | Runs. Errors are redacted. |
| `SELECT set_config('app.x', ssn, false) FROM users` | Blocked: the setting would hold the real value. |
| `SELECT user_ssn(o.user_id) FROM orders o`, a SQL function that reads `users.ssn` | The function is called as is, not inlined, and its result is `NULL`. |
| `EXPLAIN SELECT ssn FROM users WHERE ssn = $1` | Sent unchanged: Postgres shows the real plan. Errors are redacted. |
| `EXPLAIN ANALYZE UPDATE users SET name = ssn WHERE id = 1` | Blocked: `EXPLAIN ANALYZE` runs the statement. Plain `EXPLAIN` doesn't, so the same statement under `EXPLAIN` alone is allowed. |
| `EXPLAIN SELECT imm_ssn(1)`, an `IMMUTABLE` function reading `users.ssn` | Blocked: the planner can compute the call in advance, and the plan would show its result. `SELECT imm_ssn(1)` without `EXPLAIN` returns `NULL`. |
| `PREPARE p(text) AS SELECT $1; EXPLAIN EXECUTE p(user_ssn(1))` | Blocked: `EXECUTE` arguments are checked like writes, even under plain `EXPLAIN`, which evaluates them and plans with their values. |

## Conditions and ordering use real values

Postgres runs conditions, joins, grouping and ordering on the column's real value:

```sql
-- finds the rows whose real ssn is $1; ssn isn't in the results
SELECT id FROM users WHERE ssn = $1;
-- sorted by the real values, returned as tokens in that order
SELECT ssn FROM users ORDER BY ssn DESC LIMIT 5 OFFSET 2;
```

So the statement returns the same rows as for an unmasked user, an index on `ssn` serves the condition, and `EXPLAIN` shows the plan production uses. [`search = "raw"`](../raw-search/) doesn't apply: proxy rules always search real values.

## Security model

- **Clients never receive proxy-masked values.** Output columns get the proxy mask, outputs computed from the column are `NULL`, statements that would copy values elsewhere are blocked, and error messages that could quote them are redacted. The exceptions are listed under [known limits](../../reference/security/#known-limits).
- **Clients can infer them.** Filtering, joining, grouping and sorting run on real values. `SELECT ssn FROM users WHERE ssn = '123-45-6789' AND id = 7` returns a row only if the guess is right, `LIKE` narrows a value down a character at a time, and `ORDER BY ssn` ranks rows by it. A proxy mask allows at least what [raw search](../raw-search/#what-youre-allowing) with every operator allows.
- **Use proxy masks for trusted roles**: engineers debugging production queries, or anyone who needs the real plan from `EXPLAIN`. They stop values from being read, copied or exported in bulk, not from being probed. Give everyone else a SQL mask, as the policy's default or in another rule.
- **Errors and timing.** Whether a statement fails, and how long it takes, can depend on real values. These channels are accepted; the contents of error messages are redacted.

## Positions and `*`

PgDog masks result columns by position, so the plugin places every mask at a position that depends only on the statement's text, never on how many columns the catalog says a table has:

- `*` over a table with masked columns is expanded into column names, as for SQL masks.
- For users with proxy masks, `*` over any table inside a subquery, CTE or other nested query is expanded too. In `SELECT s.*, upper(u.ssn) FROM (SELECT * FROM orders) s, users u`, the inner `*` is sent as `orders.id AS id, orders.user_id AS user_id, orders.total AS total`. Expanding `*` doesn't change the plan, but it changes the statement's text, so [shadow mode](../../start/shadow-mode/) logs these statements as rewrites.
- A `*` whose width the plugin can't know blocks the statement when it comes before, or covers, a column carrying proxy-masked values: `*` over a function in `FROM`, over a catalog table such as `pg_class`, over `(expression).*`, over a join with `USING` or `NATURAL`, which merges columns, or over an aliased join of tables, `(a JOIN b ON …) AS j`, which can only be expanded as `j.*`. `SELECT * FROM pg_class c, users u` and `SELECT f.*, u.ssn FROM users u, generate_series(1, 2) f` fail with `can't place masks on the results: …`. List the columns instead.

## Statements that run later

PgDog attaches masks to the statement the plugin checked. A statement prepared or declared under a name could run later, through another message, without them:

- **Cursors and SQL `PREPARE`.** For users with proxy masks, `DECLARE` and `PREPARE` are blocked when the statement uses a proxy-masked column anywhere, in its results or only in a condition: `DECLARE c CURSOR FOR SELECT id FROM users WHERE ssn::int > 5` and `PREPARE p AS SELECT id FROM users WHERE ssn = $1` are both blocked. A protocol-level `Execute` of the cursor, or `Bind` of the name, would get neither masks nor redaction.
- **SQL `EXECUTE`** only runs a statement prepared by a `PREPARE` earlier in the same query, such as `PREPARE p AS SELECT id, name FROM users WHERE id = $1; EXECUTE p(1)`. Its arguments must not carry proxy-masked values, even under plain `EXPLAIN`, which evaluates them and shows them in the plan. `EXECUTE p(1)` on its own is blocked, for every masked user, with SQL masks too: the plugin can't know what a name prepared elsewhere runs. It could even be a statement PgDog prepared for another client.
- **`FETCH`, `MOVE` and `EXECUTE`** always get error redaction for users with proxy masks.

Prepare statements through your driver, with the extended protocol, instead. Those are checked when they're prepared, and masked at every execution. PgDog refuses a `Bind` or `Describe` of a statement name the client didn't prepare through it, with `26000`.

## Configuration errors

Proxy rules only take proxy mask keys. The configuration is rejected for:

- **`fallback`**, on any policy or rule: `policy "ssn": "fallback" was removed: proxy masks no longer rewrite other references to the column. …` Remove it, and the SQL mask keys it used, such as `keep_suffix`. See [Upgrade a deployment](../../operate/upgrade/#upgrading-to-results-only-proxy-masks).
- **`search = "raw"`** on a proxy rule: `search = "raw" doesn't apply to mask = "proxy": conditions on proxy-masked columns always compare real values`. **`search_operators`** is rejected too.
- **SQL mask keys** on a proxy rule: `value`, `keep_prefix`, `keep_suffix`, `fill`, `digits`, `unit` and `expression`, each with `"<key>" doesn't apply to mask = "proxy"`.
- **`proxy` or `options`** on a rule whose `mask` isn't `"proxy"`.

`scrub_error_detail = false` isn't an error, but it's ignored for users with proxy masks: their errors and notices always lose `DETAIL`.

## Built-in proxy masks

| `proxy` | Types | Options | Result |
| --- | --- | --- | --- |
| `hmac_sha256` | text types | `key_env` or `key_file`; `length` (1–64) | Hex HMAC-SHA256 of the value, optionally truncated to `length` digits. The same value always gives the same result under the same key, so clients can join, group and count the tokens they receive. |
| `ff1` | text types | `key_env` or `key_file`: a hex AES key of 16, 24 or 32 bytes; `alphabet`: `digits` (default), `alphanumeric`, or the characters themselves; `tweak` | NIST FF1 format-preserving encryption. Characters in the alphabet are encrypted in place and others kept, so `4111-1111-1111-1111` stays `NNNN-NNNN-NNNN-NNNN`. Values with too few alphabet characters for FF1 (fewer than 6 digits) are replaced with `*`. |

Keys come from the environment variable named by `key_env`, or the file named by `key_file`, so they don't appear in the configuration file. They're read each time the configuration loads; see [rotating keys](../../operate/logs/#rotate-proxy-mask-keys). A mask that can't be built, for example because its key is missing, is a configuration error.

## Your own masks

Proxy masks are Rust code registered by name. To add your own, build the plugin with them: see [Write a proxy mask](../../develop/proxy-masks/).

## Behavior

- **Types and formats.** A proxy mask returns a value of the column's type. Values are decoded from, and encoded back into, whatever format the client requested, text or binary.
- **Batches.** The plugin masks rows in batches of up to 256 rows that have already arrived from Postgres, so it doesn't wait for more rows before sending the ones it has.
- **Failures.** If a proxy mask fails, the query is canceled and the client's connection is closed with a `FATAL` error, since some rows may already have been sent.
- **Cost.** Every masked value goes through the plugin. Prefer SQL masks where a keyed or coded mask isn't needed.
