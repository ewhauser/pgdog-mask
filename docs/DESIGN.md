# Dynamic Data Masking for PgDog — Design

> This project ([pgdog-mask](../README.md)) is the plugin. The PgDog changes it needs (plugin API 0.7, §8) are on [`ewhauser/pgdog`](https://github.com/ewhauser/pgdog), branch `masking/plugin-api`. Paths like `pgdog/src/...` refer to that repository.

Status: P1 and P2 implemented · Scope: `pgdog-plugin` API extensions + this plugin

## 1. Summary

We will build column-level dynamic data masking as a PgDog plugin. The model follows Snowflake Dynamic Data Masking. Masking policies are attached to columns. Each policy picks a masking expression based on who is asking. Masking happens at query time, and the stored data is never changed.

The plugin parses every statement with `pg_raw_parse`. It resolves each column reference to a base `schema.table.column` and checks it against the policies for the caller's identity. Every reference to a masked column is then replaced with the policy's masking expression. This applies wherever the reference appears: projections, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY`, `RETURNING`, subqueries, CTEs, `COPY` and `INSERT … SELECT`. PgDog sends the rewritten SQL, and Postgres computes the masked values.

The rewrite is the main enforcement mechanism. Two narrower hooks cover what SQL cannot express: **column masks**, computed by the plugin on batches of result rows (keyed HMAC/tokenization with secrets that must not reach the database, format-preserving encryption), and **error redaction**, which removes values from the errors and notices Postgres returns.

All of them are **generic plugin APIs** (§8): a statement hook returning a verdict, a batched column-mask hook, and an error-redaction hook. None is masking-specific, so PgDog core gains only reusable extension points. Encryption, DLP and audit plugins could use the same hooks.

### Goals

- Snowflake-equivalent semantics: role-conditional, column-level, type-preserving masks, applied at query time everywhere the column is referenced.
- No changes to the application or to Postgres. The app connects to PgDog as it does today.
- Fail closed. If the analyzer cannot prove a statement is safe for a restricted identity, the statement is blocked.
- Zero overhead for identities that see nothing masked, and near-zero for everyone else on cache hits.
- Keep core changes minimal and generic. All masking logic lives in the plugin.

### Non-goals (v1)

- Protecting data from clients that connect to Postgres directly, bypassing PgDog. Deployment must enforce that with network policy and credentials.
- Row access policies (row-level filtering). The architecture supports them (§13), but they are a separate feature.
- Preventing statistical inference from aggregates over *unmasked* columns. Snowflake doesn't prevent this either.
- Masking inside opaque server-side code: PL/pgSQL and other procedural-language functions, `DO` blocks, dynamic SQL. These are blocked for restricted identities unless allowlisted. SQL-language functions *are* analyzed (§6.7).

---

## 2. Key decision: rewrite first, proxy-side work second

The initial idea was to mask in the result stream: let the query run, then mask `DataRow` values in the proxy. That needs the fewest core changes. On its own, though, it is **not secure**, and it cannot match Snowflake semantics:

| Leak vector | Example | Result-transform only | AST rewrite |
|---|---|---|---|
| Predicate oracle | `WHERE ssn = '123-45-6789'`, `WHERE ssn LIKE '1%'` | leaks (binary search on the value) | masked: compares masked values |
| Derived expressions | `SELECT ssn \|\| ''`, `upper(ssn)`, `ssn::int`, `left(ssn,3)` | leaks unless every expression is tracked | masked at the leaf |
| Aggregates / ordering | `max(salary)`, `ORDER BY salary LIMIT 1` | leaks | masked |
| Whole-row references | `SELECT row_to_json(u) FROM users u`, `SELECT u::text` | leaks | rewritten to a masked row |
| Write-then-read exfiltration | `INSERT INTO t2 SELECT ssn FROM users`; `CREATE TABLE AS` | leaks permanently | masked data is written |
| Error messages | `SELECT ssn::int …` → `invalid input syntax for type integer: "123-45-6789"` | leaks | the cast runs on the masked value |
| COPY | `COPY users TO STDOUT` (stream not row-aligned) | hard | rewritten to `COPY (SELECT …) TO` |
| Extended protocol | `Execute` with no `RowDescription` (Describe skipped) | needs positional plans and binary encoders | Postgres handles it |
| Cross-shard merge | sort/aggregate across shards run on raw values | ordering leaks | merged values are already masked |

A rewrite only has to resolve **leaf column references**. It does not have to track lineage through arbitrary expressions, because masking at the leaf carries through everything built on top of it. Postgres then produces the correct `RowDescription`, types and binary encodings. This is also how Snowflake works: it rewrites the column into the policy body everywhere it appears.

Proxy-side work stays for two narrower jobs, each with its own typed hook:

1. **Proxy-only masks** (column masks). Keyed HMAC, tokenization against a vault and FPE need a secret that must not appear in SQL text, where `pg_stat_statements`, logs and `EXPLAIN` would expose it. These masks are only allowed when the masked column appears as a plain passthrough in the top-level projection, cast to text. Any other reference to the same column still gets the policy's SQL fallback mask through the rewrite.
2. **Error and notice redaction.** For example, a `CHECK` violation `DETAIL: Failing row contains (5, 123-45-6789, …)` exposes the stored values of other masked columns in the row. Redaction applies to every error and notice a masked user gets, not only those of statements touching masked relations: triggers and functions can raise errors about other tables.

An earlier version of the API passed raw protocol messages to a generic transform hook. It was replaced (§8): plugins would have had to parse the wire protocol and manage handle lifetimes, and PgDog to expose them, for two jobs that need neither.

---

## 3. Snowflake feature mapping

| Snowflake | PgDog masking |
|---|---|
| `CREATE MASKING POLICY p AS (val T) RETURNS T -> CASE WHEN CURRENT_ROLE() IN (...) THEN val ELSE ... END` | `[[policies]]` with ordered `cases` (role conditions) and a `default`. Conditions are evaluated in the proxy. Mask bodies are SQL expressions or built-ins. |
| `ALTER TABLE … MODIFY COLUMN c SET MASKING POLICY p` | `[[columns]]` assignment |
| Conditional masking (`USING (val, other_col)`) | `using = { name = "other_col" }` in the assignment. The extra column is referenced from the same range table entry. |
| Tag-based masking | `[[tags]]` → policy. Columns are tagged in TOML, by regex classifier, or in the database through column comments or security labels (§7.4) |
| Searching a masked column | opt-in per rule: `search = "raw"` (§6.8). Snowflake has no equivalent |
| Policy return type = input type | enforced at load time; masks are wrapped in an explicit cast to the column type |
| Applies through views | views that reference masked columns are inlined with masking applied (§6.6) |
| `CURRENT_ROLE()` / `IS_ROLE_IN_SESSION()` | masking roles resolved from PgDog's authenticated identity (§5) |
| `SYSTEM$GET_TAG`, policy references views | `pgdog-mask explain` CLI + shadow-mode logs + admin stats |

The deliberate difference is how the condition is evaluated. Snowflake evaluates `CURRENT_ROLE()` inside SQL. PgDog evaluates role conditions **in the proxy at plan time** and constant-folds them. Unmasked identities therefore get the original SQL byte-for-byte, and masked identities get only the mask expression, never a `CASE` that includes the raw branch.

---

## 4. Architecture

```
 client ──► QueryEngine::handle (pgdog/src/frontend/client/query_engine/mod.rs:136)
              │ rewrite_extended        (client stmt names → __pgdog_N)
              │ cluster_check
              │ ┌──────────────────────────────────────────────────────────────┐
              │ │ NEW apply_statement_plugins                                  │
              │ │   plugin.statement(&Session, sql) ─► Allow                   │
              │ │       | Rewrite{sql, column masks} | Deny{sqlstate, msg}     │
              │ │   Rewrite → replace Query/Parse text before the prepared     │
              │ │   statement cache sees it; Bind re-checks only when the      │
              │ │   plugin's generation or search_path changed                 │
              │ └──────────────────────────────────────────────────────────────┘
              │ parse_request           (PgDog AST cache + pgdog rewrites on *masked* SQL)
              │ rewrite_request / route_query / finalize_after_route (sharding as usual)
              │ execute
              ▼
 Postgres ──► Server::read → Binding (Direct | MultiShard merge/sort/agg)
              ▼
            QueryEngine::process_server_message (query_engine/query.rs:189)
              │ ┌──────────────────────────────────────────────────────────────┐
              │ │ NEW E/N: plugin.redact_error(&Session, fields)               │
              │ │ NEW D with column masks: plugin.mask_rows(batch of rows)     │
              │ └──────────────────────────────────────────────────────────────┘
              ▼ stream.send
            client
```

Why these two points:

- **Statement hook before `parse_request`.** PgDog's own rewrite engine (`StatementRewrite::maybe_rewrite`) mutates the cached AST in place and memoizes cross-shard rewrites (`Ast.post_route_rewrite`). If masking ran after that, a later `finalize_after_route` would rebuild SQL from the unmasked AST and silently drop the masks (`rewrite/statement/projection.rs:88-207`). Masking first means sharding, the rewrite engine and cross-shard merging all operate on the masked statement with no special cases. The AST cache is keyed by SQL text, so masked variants get distinct cache entries. That avoids the cross-user leakage that would happen if per-identity decisions were cached on the shared AST (`cache_impl.rs:113-141`).
- **Transform hook in `process_server_message`.** Every client-bound backend message passes through it: simple, extended, pipelined and COPY OUT. Multi-shard merge, sort and aggregate have already finished at that point, and helper columns have been dropped, so column indices are the ones the client sees. It must run before `cleanup_backend()` (`query.rs:319`), which resets the router state.

### 4.1 Crate layout

```

  masking-core/     # pure library: policy model, identity → profile, analyzer, rewriter, proxy masks.
                    # No pgdog dependency beyond pg_raw_parse + pgdog-postgres-types. Fully unit testable.
  masking-plugin/   # cdylib: implements pgdog_plugin::Plugin, caches, catalogs, config reload
  masking-cli/      # `pgdog-mask explain|validate|lint` using masking-core against a live DB schema
```

---

## 5. Identity and masking profiles

### 5.1 Identity sources (trusted → untrusted)

| Source | Trust | Notes |
|---|---|---|
| Authenticated PgDog user (`users.toml`) | trusted | primary key for role mapping |
| Database name | trusted | |
| mTLS client certificate subject/SAN | trusted | when `tls_client_certificate()` is present |
| Client address | trusted (network) | CIDR conditions |
| `application_name`, startup `options`, custom GUCs | **untrusted** | can only *add* masking (narrowing), never remove it |
| `SET ROLE`, `SET SESSION AUTHORIZATION` | **ignored** | see below |

The principle: a client-controlled value may make masking stricter, never weaker.

**Masking identity is fixed for the session and comes from the authenticated PgDog user. `SET ROLE` does not change it.** PgDog's tracked `role` parameter is not authenticated. `QueryEngine::set` (`query_engine/set.rs`) writes it into the `ParameterStore` before Postgres validates it. When no backend is connected, PgDog answers `SET` with a fake `CommandComplete` and never asks Postgres. In transaction pooling, the value is replayed onto server connections later. Deriving masking from it would let any client claim an exempt role.

Masking roles are therefore a PgDog-level concept, just as Snowflake roles are Snowflake's and not the source system's. A workload that needs different masking connects as a different PgDog user. Several PgDog users can share one `server_user`, so this costs no extra Postgres roles. A fixed identity also removes a class of stale-plan bugs: SQL-level `PREPARE`, `WITH HOLD` cursors and protocol prepared statements can never outlive the profile they were rewritten for.

If role switching is ever needed, it should be validated against a `pg_auth_members` snapshot in the plugin rather than taken from the tracked parameter. That is out of scope.

### 5.2 Profiles

At session start, and on policy or identity change, the plugin resolves the identity to masking roles (`[[identities]]` rules, §7). It then evaluates every policy's `cases` to produce a **profile**: a map `policy → selected mask`, which is `none` for exempt policies. The profile has a stable 64-bit hash (`profile_tag`).

- A profile where every policy resolves to `none` is the **exempt fast path**: the hook returns `Continue` immediately.
- Thousands of users typically collapse into a handful of profiles. Profiles are the cache discriminator for rewritten SQL. Prepared statements with the same rewrite share one server-side statement, so cache hit rates stay high.

---

## 6. The analyzer: resolving the AST against policies

### 6.1 Fast path

A single `walk_manual` pass over the statement collects:

- `RangeVar` names,
- whole-row references,
- `FuncCall` names,
- statement kind.

If no referenced relation is in the profile's **masked relation set**, and no function or statement is on the restricted list, the result is `Continue`. The masked relation set covers tables with masked columns, their partitions and children, and views and materialized views whose lineage reaches them. This pass is the same shape as `plugins/pgdog-primary-only-tables` and costs well under a microsecond for typical statements. The decision is cached as well (§9).

### 6.2 Scoped name resolution

This is the core of the analyzer. None of PgDog's existing helpers (`SearchContext`, `FromClause`, `Column`, `Table` in `router/parser/`) do full scoped resolution: they skip subqueries, CTE scoping, unqualified columns and `*`. `masking-core` implements a proper resolver modeled on Postgres' `parse_relation.c`:

```
Scope {
  parent: Option<&Scope>,                 // for correlated subqueries / LATERAL
  ctes:   Vec<(name, CteInfo)>,           // WITH, incl. RECURSIVE (self-ref resolves to the CTE)
  items:  Vec<RangeItem>,                 // FROM list, in order
}
RangeItem =
  | Relation { alias, oid, schema, name, columns: [ColInfo{name, type, policy}] }
  | Derived  { alias, column_aliases, outputs: [OutputLineage] }   // RangeSubselect, CTE ref, VALUES
  | Function { alias, column_defs, outputs }                        // RangeFunction (opaque → no policies)
  | Join     { left, right, using/natural merged cols, alias }      // JoinExpr
```

Resolution rules:

- **Relations** resolve against the session `search_path` (from the `ParameterStore`), with `pg_temp` first. They are looked up in the catalog PgDog sends (§8.5). An unknown relation fails closed for restricted profiles.
- **Qualified columns** (`a.col`, `s.t.col`) resolve against the matching range item. **Unqualified columns** search items in the current scope, then outer scopes. This matches Postgres. Ambiguity is a Postgres error anyway; if the catalog lacks a column that Postgres would resolve, the statement fails closed.
- **Derived tables and CTEs** are analyzed recursively first. Their outputs only carry lineage. Masks are applied *inside* them at the base reference, so outer references need no further rewriting.
- **Set operations** (`UNION`/`INTERSECT`/`EXCEPT`): each branch is resolved independently.
- Identifier case folding follows Postgres: unquoted names are lowercased.

### 6.3 Rewrite rules

The rewriter is a `pg_raw_parse::transform::Transform` implementation. It follows the existing `ReplaceTransactionTime` pattern in `rewrite/statement/non_deterministic_funcs/rewrite_transaction_time.rs`.

| Construct | Rewrite |
|---|---|
| `ColumnRef` → masked base column (any clause) | `(<mask_expr(ref)>)::<col_type>`, where `ref` is the original fully qualified reference |
| Unnamed `ResTarget` whose subtree changed | pin the output name to Postgres' `FigureColname` of the *original* expression (`ssn`, `ssn::text` → `ssn`), so clients see unchanged column names |
| `*` / `t.*` over a relation with masked columns | expand to an explicit column list in ordinal order: `t.id, (<mask>)::text AS ssn, …` |
| Whole-row ref `t` (in `row_to_json(t)`, `t::text`, `SELECT t`, `to_jsonb(t.*)`) | `ROW(t.id, (<mask>)::text, …)::schema.table`; the composite cast keeps field names |
| `COPY t TO …` / `COPY t (cols) TO …` | `COPY (SELECT <masked cols> FROM t) TO …` |
| `COPY (query) TO …` | rewrite the inner query |
| `INSERT … SELECT`, `CREATE TABLE AS`, `SELECT INTO`, `MERGE … USING` | rewrite the source query (masked data is written, as in Snowflake) |
| `UPDATE … SET a = <expr>`, `RETURNING`, `DELETE … RETURNING`, `ON CONFLICT DO UPDATE SET … = t.col` | rewrite expressions and `RETURNING`; **target** columns are untouched; `EXCLUDED.*` is the client's own input and is not masked |
| `DECLARE c CURSOR FOR …`, SQL `PREPARE p AS …`, `EXPLAIN [ANALYZE] …` | rewrite the inner statement |
| `GROUP BY`, `DISTINCT ON`, window `PARTITION BY`/`ORDER BY`, `ORDER BY` | rewrite consistently; identical rewritten expressions keep `GROUP BY` validity, including functional-dependency cases |
| Conditional mask (`using`) | reference the `using` column through the same range alias as the masked column |

Two implementation details:

- **Mask expressions are ASTs, not strings.** Each policy's SQL body is parsed once at load time as `SELECT <expr>`. The placeholder `ColumnRef`s (`val` and the names in `using`) are recorded. At rewrite time the template is copied into the statement's arena and the placeholders are substituted with the reference node. There is no string concatenation, so there is no injection surface. Templates are validated against a live database at load (§7.3).
- **Deparse once.** The full statement list is deparsed with `pg_raw_parse::deparse_stmts`. Multi-statement simple queries are handled as a unit. That closes the bypass where PgDog sends multi-statement SQL as-is on a single shard and skips plugins (`parser/query/mod.rs:353`, `cache/ast.rs:83`).

### 6.4 Type and name preservation

Masks must be **type-preserving**. Snowflake has the same requirement. The analyzer wraps every mask in an explicit cast to the column's base type, without typmod, so `varchar(11)` becomes `varchar`. This guarantees three things:

1. Operator and function resolution in the surrounding expression is unchanged.
2. `RowDescription` from `Describe(S)` is identical for masked and unmasked variants. The statement a client described keeps the same shape if a policy reload later re-prepares it under a new rewrite.
3. Binary result formats requested in `Bind` stay valid.

A policy whose mask cannot produce the input type fails to load. Examples are a text mask on an `int` column, or `partial` on `uuid`.

### 6.5 Fail-closed rules for restricted profiles

These apply only to profiles that mask at least one column referenced by the statement's relations. Some rules, marked "always", apply to any non-exempt profile. Each rule is configurable in `[settings]`; the defaults are shown.

| Situation | Default | Why |
|---|---|---|
| Unresolvable relation or column | block | can't prove safety |
| Call to a user-defined function that is not SQL-language, inlinable or allowlisted | block | opaque body could read masked columns (§6.7) |
| Query-executing built-ins: `query_to_xml*`, `cursor_to_xml*`, `table_to_xml*`, `schema_to_xml*`, `database_to_xml*`, `ts_stat`, `dblink*`, `pg_read_*`, `lo_*` | block (always) | execute SQL or read data out of band |
| `DO` blocks, `CREATE FUNCTION/PROCEDURE/RULE/TRIGGER/VIEW/MATERIALIZED VIEW`, `CALL` | block (always) | persistent or opaque bypass |
| `pg_stats`, `pg_statistic`, `pg_stat_statements` referencing masked tables | block | `most_common_vals` and query literals leak values |
| `CREATE TEMP TABLE` shadowing a masked relation name | block | resolution ambiguity |
| Replication commands (`START_REPLICATION`, `CREATE_REPLICATION_SLOT`), `COPY … TO PROGRAM/file` | block (always) | out-of-band data paths |
| Masked column is a sharding key or multi-tenant column | rejected at policy load | masking would break routing and tenant isolation (§10) |

A block returns `ErrorResponse` with SQLSTATE `42501` (insufficient_privilege) and a message naming the policy, but never the value.

### 6.6 Views, materialized views, partitions

- **Partitions and inheritance children** inherit the parent's column policies. The catalog carries each partition's parent. Querying `users_2024` directly is masked like `users`.
- **Views.** The catalog includes `pg_get_viewdef(oid)`. When a catalog arrives, the plugin parses each view definition and computes its lineage. A view that references masked columns is a *masked view*. For restricted profiles, a `RangeVar` naming a masked view in a read context is replaced by `(<masked view definition>) AS <alias or view name>`, applied recursively for nested views. Writes through masked views are blocked. If the view is `security_barrier` or `security_invoker`, or inlining is disabled (`inline_views = false`), the view is treated like a table instead: passthrough output columns inherit the base policy, and derived ones must be explicitly assigned or the statement is blocked.
- **Materialized views** hold materialized raw data. Passthrough columns inherit policies automatically. Derived columns of masked inputs without an explicit assignment raise a load-time warning, and statements touching them are blocked.

As built in P2:
- **Masked or not is decided per profile.** The plugin analyzes a view's definition with the user's masks, the same way it analyzes a statement. If nothing in it needs masking, the view is left as it is. If something does, the view is inlined: `FROM v AS x(a, b)` becomes `FROM (<definition>) AS x(<view columns, renamed by the alias>)`, and the inlined definition is masked like any subquery. Verdicts are memoized per statement, so nested and repeated views are analyzed once.
- **Definitions are schema-qualified**, because PgDog loads them with an empty `search_path` (§8.4). They're analyzed without a `search_path`.
- **Views are only inlined in FROM lists** (`SELECT`, `UPDATE … FROM`, `DELETE … USING`). A view that needs masking anywhere else, e.g. `LOCK v`, is blocked, as are `INSERT`, `UPDATE` and `DELETE` through it.
- **Views queried like tables** are materialized views, `security_barrier` and `security_invoker` views, views with masked columns of their own (`[[masked_columns]]` or tags on the view), and every view when `inline_views = false`. Their column lineage is computed when the schema loads (`analyzer/lineage.rs`), following nested views and subqueries down to tables and materialized views:
  - a column that passes a masked column through gets its policy, with conditional-mask arguments renamed to the view's columns;
  - a column computed from masked columns, or whose inputs can't be determined, is blocked for users who would see any of those inputs masked. Assigning the view column a policy unblocks it.
- **`view_allowlist`** remains as an attestation: listed views are used as they are, without analysis.
- A view without a definition in the catalog is blocked for masked users.

---

### 6.7 Functions

The catalog (§8.5) includes `pg_proc` rows for functions outside `pg_catalog` and `information_schema`. Each row carries:
- name, argument and return types, `proretset`;
- language, `prosrc`, and `pg_get_function_sqlbody` for `BEGIN ATOMIC` bodies;
- volatility, `prosecdef`, `proisstrict` and `proconfig`.

Custom operators (`pg_operator` outside `pg_catalog`) are treated as calls to their underlying function.

For a restricted profile, each call `f(args)` is handled as follows:

1. **Overload resolution.** Candidates are matched by name and arity. If several overloads match and the argument types can't be determined syntactically, every candidate is analyzed and the most restrictive outcome wins.
2. **Built-ins** (`pg_catalog`) are allowed, except the denylist in §6.5.
3. **SQL-language functions.** The body is parsed and analyzed recursively, with a depth limit and cycle detection. Names in the body are resolved under the function's `proconfig` `search_path` if it sets one, otherwise under the caller's. `BEGIN ATOMIC` bodies are already bound at creation time, and `pg_get_function_sqlbody` emits qualified names. Parameters are opaque.
   - **The body references no masked column:** the call is allowed unchanged. The verdict is cached per (function, profile, epochs).
   - **The body references masked columns and the function is inlinable:** inline it with masking applied. A function is inlinable when it has a single `SELECT` body, is not `SECURITY DEFINER`, has no `proconfig`, is not polymorphic or variadic, is `IMMUTABLE` or `STABLE`, and has no volatile arguments. This mirrors the conditions under which Postgres itself inlines SQL functions.
     - A scalar function becomes `(SELECT <masked body with parameters replaced by argument expressions>)`. A `STRICT` function also gets a `CASE WHEN <any arg> IS NULL THEN NULL ELSE … END` wrapper.
     - A set-returning function in `FROM` becomes `(<masked body>) AS alias(cols)`.
   - **Otherwise:** block. This includes every `SECURITY DEFINER` function that touches masked columns, because inlining it would change privilege semantics.
4. **Procedural languages** (PL/pgSQL, PL/Python, …) are blocked unless listed in `udf_allowlist`. An allowlist entry is the administrator's attestation that the function doesn't return masked data.

As built in P2:
- **Built-ins** are the names in the catalog's `system_functions` (`pg_catalog` functions, from `pg_proc`). A name that is neither a user-defined function in the catalog nor a built-in is blocked, which covers functions created after the catalog was loaded.
- **Candidates** are the user-defined functions with the call's name, in its schema or the `search_path`, whose arity fits (counting defaults and `VARIADIC`). Any blocked candidate blocks the call. A call is only inlined if it has a single candidate. A user-defined function that shadows a built-in name is analyzed instead of the built-in.
- **Arguments are evaluated once.** A scalar call becomes `(SELECT (<value>)::<return type> FROM (SELECT <arg>::<type> AS <param>, …) AS __pgdog_args)`, where `<value>` is `(SELECT … FROM (<masked body>) AS __pgdog_body(__pgdog_out) LIMIT 1)`: the first row, like a SQL function. Parameters are columns of the arguments subquery, so columns of the body still take precedence over parameter names, as in SQL functions; `$n` and `function.param` references are rewritten to it. Because arguments aren't duplicated, the "no volatile arguments" condition isn't needed. `STRICT` adds the `CASE WHEN <arg> IS NULL …` wrapper.
- **In FROM**, a set-returning call becomes a `LATERAL` subquery with the function's output columns (`OUT`/`TABLE` columns, or a table's columns for `SETOF table`) cast to their declared types. A scalar function in FROM becomes a one-row `LATERAL` subquery over the scalar form.
- **Not inlined, so blocked when the function reads masked columns:** calls relying on argument defaults, named arguments, `VARIADIC`, aggregate or window syntax, `ROWS FROM`, `WITH ORDINALITY`, column definition lists, set-returning calls outside FROM, and bodies that select `*` (prosrc bodies keep the `*`; `BEGIN ATOMIC` bodies are expanded by Postgres).
- **Recursive** SQL functions are blocked.
- **Extensions.** Functions owned by an extension are user-defined functions in a non-SQL language, so they're blocked unless the extension is in `extension_allowlist` or the function is in `udf_allowlist`. The §6.5 denylist (`dblink*`, `query_to_xml`, …) applies even to allowlisted functions.
- **Operators** outside `pg_catalog` that could match by name are treated as calls to their functions. Without operand types every same-named operator in the `search_path` is a candidate, so an extension operator such as `citext`'s `=` blocks every `=` for masked users until its extension is allowlisted.

Trigger functions run server-side as a consequence of writes. For example, an audit trigger may copy a raw row into a table the restricted user can read. They are not analyzed. `pgdog-mask lint` flags tables written by triggers on masked tables that restricted users can `SELECT`.

### 6.8 Searching on masked columns (`search = "raw"`)

Some applications need masked users to *find* rows by a sensitive value while still seeing it masked. For example, support looks up a patient by SSN or date of birth. A policy rule can opt in with `search = "raw"`. This deliberately weakens Snowflake semantics: it reintroduces the predicate oracle for that column and those roles. It is off by default.

**Semantics.** A reference to the column is left unmasked only when both conditions hold. Everywhere else it is masked as usual.

1. **Position.** The reference is in a `WHERE` clause, or a `JOIN … ON/USING` qualification, of `SELECT`, `UPDATE`, `DELETE` or `MERGE`. This includes sublinks inside those clauses. Projections, `RETURNING`, `GROUP BY`, `HAVING`, `ORDER BY`, window clauses, and CTE or derived-table projections are never raw.
2. **Shape.** The predicate is `col <op> operand`, where:
   - `<op>` is in the rule's `search_operators`. The default is the equality family: `=`, `<>`, `IN`, `NOT IN`, `= ANY`, `IS [NOT] DISTINCT FROM`, `IS [NOT] NULL`.
   - `operand` is a parameter, a constant, a list or array of those, or another column reference (a join key).
   - `col` may be wrapped in an allowlisted normalizer: `lower`, `upper`, `btrim`, `ltrim`, `rtrim`. The operand may be wrapped the same way.

**Why the shape restriction.** The risk users accept is an *oracle*: confirming a guessed value. The restriction prevents *direct exfiltration* through the same opening. Without it:
- `WHERE ssn::int = 0` would return the raw value inside the cast error message;
- `WHERE pg_notify('c', ssn) IS NULL` would deliver it to a `LISTEN`ing session;
- `WHERE set_config('x', ssn, false) <> ''` would leave it in a readable setting.

Casts, arithmetic, `CASE`, and arbitrary function calls around the column are therefore always masked.

Range operators (`<`, `>`, `BETWEEN`) and pattern operators (`LIKE`, `ILIKE`, `~`) are available via `search_operators`, with a load-time warning. They turn the oracle into efficient extraction: binary search, or character-by-character prefix probing, recovers a value in a few dozen queries. Low-entropy columns such as dates of birth are brute-forceable even with equality alone. `lint` warns when `search = "raw"` is set on one.

**Audit.** Every statement that uses a raw search emits an audit log line with the user, policy, column, and statement fingerprint. Parameter values are never logged.

**Side benefit.** Raw predicates stay sargable, so indexes on the sensitive column keep working for these lookups (§9).

---

## 7. Policy configuration

The configuration lives in its own TOML file, referenced from `pgdog.toml`:

```toml
[[plugins]]
name = "pgdog_mask"
config = "masking.toml"
```

It follows PgDog's config conventions:
- top-level `[[array_tables]]` with snake_case plural names;
- flat keys instead of inline tables;
- nested arrays for ordered sub-rules, like `[[sharded_tables.mapping]]`;
- tables identified by the same `database` / `schema` / `name` / `column` keys as `[[sharded_tables]]`;
- users identified by the same `name` / `database` keys as `users.toml`.

`pgdog.toml` and `users.toml` both use `deny_unknown_fields`, which is why masking settings can't live there directly without a core config change.

```toml
# masking.toml

[general]
mode = "enforce"              # enforce | shadow | off
on_unresolved = "block"       # block | allow
udf_allowlist = ["public.normalize_phone"]
extension_allowlist = ["citext"]   # extensions whose functions and operators are trusted
inline_views = true
scrub_error_detail = true
cache_size = 100000
tag_source = "config"         # config | comment | security_label (§7.4)
security_label_provider = "pgdog"

# Masking roles for PgDog users. `name` and `database` match users.toml.
[[users]]
name = "analyst"
database = "prod"
roles = ["analyst"]

[[users]]
name = "support_portal"
database = "prod"
roles = ["support"]

# Users not listed here have no masking roles, so every policy's default applies.

# A policy's top-level mask is its default. `[[policies.rules]]` are evaluated
# in order. The first rule whose `roles` intersect the user's roles wins.
[[policies]]
name = "ssn"
data_type = "text"
mask = "sql"
expression = "'XXX-XX-' || right(val, 4)"

[[policies.rules]]
roles = ["pii_admin", "billing"]
mask = "none"

[[policies.rules]]
roles = ["support"]
mask = "partial"
keep_suffix = 4
fill = "*"
search = "raw"                # §6.8
search_operators = ["=", "in"]

[[policies]]
name = "email"
data_type = "text"
mask = "email"

[[policies]]
name = "salary"
data_type = "numeric"
mask = "sql"
expression = "round(val, -4)"

[[policies.rules]]
roles = ["hr"]
mask = "none"

[[policies]]
name = "dob"
data_type = "date"
mask = "truncate"
unit = "year"

# Conditional masking: `arguments` name extra inputs, bound per column below.
[[policies]]
name = "marketing_email"
data_type = "text"
arguments = ["opted_in"]
mask = "sql"
expression = "CASE WHEN opted_in THEN val ELSE NULL END"

[[policies]]
name = "customer_id_token"
data_type = "text"
mask = "hmac_sha256"          # proxy mask (§7.2)
key_env = "PGDOG_MASK_KEY"
fallback = "null"             # SQL mask used everywhere except passthrough projections

# Column assignments. Omitting `name` applies to every table in the schema
# with that column, as `[[sharded_tables]]` does.
[[masked_columns]]
database = "prod"
schema = "public"
name = "users"
column = "ssn"
policy = "ssn"

[[masked_columns]]
database = "prod"
name = "users"
column = "email"
policy = "marketing_email"
arguments = ["marketing_opt_in"]   # positional, binds `opted_in`

[[masked_columns]]
database = "prod"
name = "patients"
column = "dob"
tag = "phi.dob"               # assign by tag instead of policy

# Tag → policy.
[[tags]]
name = "phi.dob"
policy = "dob"

[[tags]]
name = "pii.email"
policy = "email"

# Auto-tagging by column name. Matches are reported by `pgdog-mask lint`.
[[classifiers]]
database = "prod"
column_regex = "^(e_?mail|email_address)$"
tag = "pii.email"
```

### 7.1 Built-in masks

All built-ins compile to SQL templates. `none` is the identity. Parameters are flat keys next to `mask`.

| `mask` | Types | Keys | Expression (sketch) |
|---|---|---|---|
| `null` | any | | `NULL::T` |
| `constant` | any | `value` | typed literal |
| `default` | any | | type-appropriate placeholder: `'****'`, `0`, `'1970-01-01'`, `false`, nil UUID, `'{}'::jsonb` |
| `partial` | text | `keep_prefix`, `keep_suffix`, `fill` | `left(val,p) \|\| repeat(fill, greatest(length(val)-p-s,0)) \|\| right(val,s)` |
| `email` | text | | `regexp_replace(val, '^[^@]*', '****')` |
| `hash` | text, bytea | | `encode(sha256(convert_to(val,'UTF8')),'hex')`; unkeyed, so `lint` warns about dictionary attacks on low-entropy data |
| `round` | numeric | `digits` | `round(val, digits)` |
| `truncate` | date, timestamp | `unit` | `date_trunc(unit, val)::T` |
| `sql` | as declared | `expression` | user expression over `val` and `arguments` |
| `proxy` | as the proxy mask accepts | `proxy`, `options`, `fallback` | computed in code on result rows (§7.2) |

### 7.2 Proxy masks

Proxy masks are written in Rust and run in the plugin on result rows, through PgDog's column-mask hook (§8.3). They're for values SQL can't or shouldn't compute: a keyed hash whose key must never appear in statement text (where `pg_stat_statements`, logs and `EXPLAIN` would expose it), format-preserving encryption, vault tokens, or any transformation a developer writes in code.

```toml
[[policies]]
name = "card"
data_type = "character varying"
mask = "proxy"
proxy = "ff1"                                        # registered mask name
options = { key_env = "CARD_FF1_KEY" }               # passed to the mask
fallback = "partial"                                 # SQL mask everywhere else (default "null")
keep_suffix = 4
```

Built-in: `hmac_sha256` (hex HMAC, options `key_env`/`key_file`, `length`) and `ff1` (FF1 with AES, options `key_env`/`key_file` holding a hex key, `alphabet`, `tweak`; keeps non-alphabet characters, so formats like `NNNN-NNNN-NNNN-NNNN` survive). Secrets come from the environment or files and never appear in SQL or the config file.

**Custom masks.** pgdog-mask is also a library. A developer implements `proxy::ProxyMask` (`accepts`, `mask`, optionally `mask_batch`, `mask_text` and `blocking`), registers a factory under a name in a `proxy::Registry`, and builds their own plugin with `pgdog_mask::masking_plugin!`, depending on pgdog-mask with default features off. `example/custom-mask` is a vault-tokenization mask built that way. Masks get typed values (`pgdog_plugin::types::Datum`), decoded from whatever format the client asked for and encoded back into it, so they keep the column's type. Masks declared blocking run on PgDog's blocking thread pool, and `mask_batch` lets a mask make one remote call per batch of rows. `mask_text` is a faster path for text masks computed locally: it masks borrowed text into a reused buffer, without a `Datum` per value.

**Where they apply.** The analyzer only uses a proxy mask for a plain output column of a single top-level `SELECT`: a bare column, optionally aliased, at a known position, and not used for `ORDER BY` (by name or ordinal), `DISTINCT`, `GROUP BY`/`HAVING` or `SELECT INTO`. Every other reference to the column, in `WHERE`, joins, subqueries, CTEs, views, functions, set operations, `COPY` and DML, gets the SQL `fallback` through the rewrite. So `WHERE card = $1` compares against the fallback unless the rule sets `search = "raw"`, and ordering, filtering and aggregates never run on raw values.

**Mask IDs.** Each proxy mask instance gets a mask ID when the configuration loads. IDs are never reused: a reload adds new instances, and statements prepared before it keep working until PgDog checks them again at their next `Bind`.

### 7.3 Load-time validation

1. TOML schema validation and policy/type compatibility.
2. Every SQL template is parsed. Templates may reference only `val` and declared `arguments`, and may call only allowlisted (immutable or stable, built-in) functions.
3. **Live validation**: each template is prepared against the database as `SELECT (<template>)::T FROM (SELECT NULL::T AS val) s LIMIT 0`, to catch type errors before traffic does. `pgdog-mask validate` runs the same check in CI.
4. Assignments are checked against the catalog. A column that doesn't exist warns. Sharding keys and tenant columns are rejected.
5. Rules with `search = "raw"` warn when they enable range or pattern operators, or when they target a low-entropy type (`date`, `boolean`, small enums).

If validation fails at startup, `config()` returns `false`. PgDog skips the plugin and, because the plugin is configured with `required = true`, **refuses to start** (§8.2). If validation fails on reload, the plugin keeps the last good policy set.

### 7.4 Where policies and tags live

There are two layers:

| Layer | Contents | Source |
|---|---|---|
| **Policies** | mask logic, who sees what (`[[policies]]`, `[[users]]`, `[[tags]]`) | **always TOML**, owned by whoever owns PgDog config |
| **Bindings** | which column gets which policy or tag | TOML `[[masked_columns]]`/`[[classifiers]]`, *plus* optionally the database |

Policy logic never lives in the database. If it did, anyone with `ALTER` on a table, typically the migrations role, could weaken masking.

Column *tags* can live in the database, which has a real benefit. The migration that adds a PHI column can tag it in the same transaction, so tagging can't drift from the schema. This is how Snowflake's catalog-resident tags work. `tag_source` selects the source:

- **`config`** (default): TOML only.
- **`comment`**: tags are read from column comments using a reserved prefix, e.g. `COMMENT ON COLUMN users.ssn IS 'Social security number. pgdog:tag=pii.ssn'`. The prefix is parsed from anywhere in the comment, so existing documentation text is preserved. This works on every Postgres, including managed services. Some ORMs and migration tools rewrite comments, and `lint` flags tags that disappear between reloads.
- **`security_label`**: tags are read from `pg_seclabels` for `security_label_provider`, via `SECURITY LABEL FOR pgdog ON COLUMN users.ssn IS 'pii.ssn'`. This is the semantically correct Postgres feature, but it **requires a label provider loaded through `shared_preload_libraries`**. Without one, vanilla Postgres rejects `SECURITY LABEL` outright. Many managed services don't allow custom providers; `postgresql_anonymizer` registers one where it is installed.

Database tags are **additive only**. A TOML binding can't be removed or downgraded by the database. On each schema reload the plugin diffs database-sourced tags and logs removals at `warn`, because removing a tag unmasks a column.

As built in P2:
- **Precedence**: `[[masked_columns]]`, then database tags, then `[[classifiers]]`. Each later source only fills columns the earlier ones left unmasked.
- **Comments** may carry several tags, repeated (`pgdog:tag=a pgdog:tag=b`) or comma-separated (`pgdog:tag=a,b`). **Security labels** are a tag or a comma-separated list. Labels from other providers are ignored.
- A database tag with no `[[tags]]` entry can't be masked, since policies only live in TOML. It's logged at `warn` on every schema load.
- **Classifiers** match `column_regex` against the whole column name, in tables, partitions and materialized views, optionally narrowed by `database`, `schema` and `name`. The regex is validated when the config loads.

---

## 8. Plugin API extensions (core changes)

The core patch is on `masking/plugin-api` as `pgdog-plugin` **0.7.0**. PgDog's [`docs/PLUGIN_SYSTEM.md`](https://github.com/ewhauser/pgdog/blob/masking/plugin-api/docs/PLUGIN_SYSTEM.md) and the `Plugin` trait documentation are the reference; this section summarizes what the plugin relies on.

### 8.1 Capabilities

| Capability | Hooks | Used by this plugin |
|---|---|---|
| `ROUTE` | `route` | no |
| `STATEMENT` | `statement(&Session, sql) -> Verdict`, `function_call(&Session, oid) -> Access`, `generation()` | yes |
| `MASK` | `mask_rows(&MaskBatch, &mut MaskOutput)` | P3 (proxy masks) |
| `ERRORS` | `redact_error(&Session, &ErrorFields) -> Redaction` | yes |
| `CATALOG` | `catalog_parts()`, `catalog(database, &Catalog)` | yes, all parts |

Only one loaded plugin can have `STATEMENT`. `required = true` in `[[plugins]]` makes PgDog refuse to start without the plugin.

### 8.2 Sessions and verdicts

Hooks get a `Session`: the authenticated user and database, the verified TLS identity, and `search_path`. `application_name` and the client address are in `Session::client`, marked untrusted; the plugin doesn't use them.

`statement` runs for every `Query` and `Parse`, before PgDog parses, rewrites or routes. It returns `Allow`, `Rewrite { sql, columns }` or `Deny`. Verdicts must be deterministic until `generation()` changes. PgDog relies on that for prepared statements: they're checked when prepared, and at `Bind` only if the generation or `search_path` changed, in which case PgDog re-prepares under the client's statement name if the SQL changed. The plugin bumps its generation when it loads new settings or receives a new catalog. A rewrite of a `Parse` must keep its highest `$n`.

Fast-path function calls carry no SQL, so `function_call` denies them for masked users.

### 8.3 Column masks

A rewrite can name text output columns to mask in the proxy (`ColumnMask`: result set, column, `MaskId`, blocking). PgDog calls `mask_rows` with batches of the rows it already received (up to 256 rows or 1 MiB), column by column, and checks the column types on `RowDescription`. Masking failures close the session. P3 uses this for HMAC, FPE and vault tokenization; vault masks are declared blocking and run on PgDog's blocking pool.

### 8.4 Error redaction

`redact_error` sees every `ErrorResponse` and `NoticeResponse` Postgres sends to the client, as fields. PgDog always keeps the severity and SQLSTATE. The plugin removes `DETAIL` for masked users when `scrub_error_detail` is on.

### 8.5 Catalog

`catalog` receives a typed `Catalog` (defined in `pgdog-plugin`, passed by reference) for each database, when it changes: relations and columns, plus the parts the plugin asks for (`COLUMNS` from `pg_attribute` with type names, comments and security labels; `VIEWS`; `FUNCTIONS` with system function names; `OPERATORS`). Names are schema-qualified. Until a database's catalog arrives, masked users get `57P03` (fail closed).

### 8.6 Reload

`reload()` runs when PgDog reloads its configuration. The plugin re-reads its TOML, keeps the old settings if the new ones are invalid, and bumps its generation otherwise.

## 9. Caching and performance

| Path | Cost |
|---|---|
| Exempt profile | one profile lookup (hashed once per session): **~tens of ns** |
| Statement doesn't touch masked relations (cache hit) | xxh3 of SQL + LRU lookup: **~100–300 ns** |
| Cache miss, needs masking | parse (~2–10 µs) + resolve/rewrite + deparse (~1–5 µs), once per (statement, profile, epochs) |
| PgDog parse of masked SQL | prepared statements: cached per rewritten text. Simple queries are already parsed per request today, so masking adds the plugin-side parse on a miss only |
| SQL masks at execution | evaluated in Postgres; no per-row proxy work |
| Proxy masks | per-row decode → HMAC → encode of only the masked columns; vault lookups through an in-process cache |

Caches:

- **Plugin decision cache**: key `(sql, search_path, profile, settings_epoch, schema_epoch)`, value `Continue | Rewrite(sql) | Block`. Concurrency via sharded `moka`/`DashMap`; route hooks run on async worker threads, so lookups must never block.
- **Profiles**: keyed by identity hash and `policy_epoch`.
- **Prepared statements**: one server-side statement per (statement × distinct rewrite), shared across all sessions with that profile through PgDog's global cache and prepared lazily per server connection.

The real performance cost is in Postgres: `WHERE mask(ssn) = …` can't use an index on `ssn`. That is inherent to Snowflake semantics and only affects masked identities. Rules with `search = "raw"` (§6.8) keep lookups on that column sargable. Shadow mode's logs (§12) make such queries visible before enforcement is turned on.

---

## 10. Interaction with PgDog features

| Feature | Behavior |
|---|---|
| Sharding | Masking runs before routing, so shard keys are extracted from the masked SQL. Masking a sharding key is rejected at load, because the key would be unextractable and broadcast. Cross-shard sort, aggregate and `DISTINCT` operate on masked values, which is consistent with single-node semantics. |
| Multi-tenant mode | The tenant column can't be masked (load error). |
| Rewrite engine (auto id, `unique_id()`, ND functions, subqueries, sharding-key updates) | Runs on the masked SQL. Masked expressions are ordinary SQL, so no interaction. |
| Prepared statements (`prepared_statements = extended/full`) | One server-side statement per distinct rewrite (§8.2), re-checked at `Bind` only after the plugin's settings or catalog changed. Statement names stay stable for the client. With `prepared_statements = disabled`, a statement whose rewrite changes must be prepared again by the client. |
| Read/write splitting, load balancing | Unaffected. |
| Mirroring | The mirror receives the masked request, since masking runs before `backend.mirror`. Responses are discarded. |
| Dry run / query log | Logs show the original SQL. Shadow mode adds the masked SQL and the decision. |
| Session vs transaction pooling | Identity is per client, not per server connection, so both work. |
| Admin database | Not masked; admin connections have no cluster route. |

---

## 11. Threat model

**In scope:** a client connected through PgDog under a restricted identity, issuing arbitrary SQL, trying to read values of masked columns, directly or by inference through predicates, ordering, errors, side tables, catalog statistics, functions, COPY or cursors.

**Assumptions the deployment must enforce:**

1. Clients cannot reach Postgres directly.
2. The Postgres role PgDog uses for restricted identities (`server_user`) should not own the tables and should not be able to create functions or views. That is defense in depth if the analyzer has a bug. `pgdog-mask lint` checks for this.
3. Policy configuration and HMAC keys are protected like credentials.

**Known residual risks, documented for users:**

- Inference from *unmasked* columns correlated with masked ones (e.g. zip code + birth date).
- Timing side channels.
- Statements by exempt identities that copy raw data into tables restricted identities can read. This is a data-governance issue, the same as in Snowflake.
- Policies on columns whose values are also present elsewhere unmasked: denormalized copies, JSON blobs, audit tables. The classifiers and `lint` help here.

---

## 12. Observability and operations

- **Shadow mode** (`mode = "shadow"`): full analysis, with no rewrite or block. Every decision that *would* apply is logged at `info` with the user, profile, policies hit, fingerprint, and the would-be SQL. This is the recommended rollout step.
- **Decision log**: structured log line per `Rewrite`/`Block` (first occurrence per fingerprint + profile, then sampled), using the existing plugin logging init (`logging_init`).
- **Metrics**: counters for continue/rewrite/block per policy, cache hit rate, analyzer latency histogram, proxy-mask latency. They are exposed through plugin logs initially; a generic plugin-metrics API is a follow-up.
- **`pgdog-mask explain --user U [--application-name A] "SQL"`**: prints the profile, every resolved column reference with its policy, and the rewritten SQL, using a schema pulled from the target database. It is the same `masking-core` code, so its output matches production.
- **`pgdog-mask lint`**: reports unassigned columns matching classifiers, unkeyed `hash` on low-cardinality types, masked columns that are sharding keys, and the privileges of `server_user`.

---

## 13. Testing strategy

1. **`masking-core` unit tests**: a golden corpus of `(sql, profile) → expected rewritten SQL | block`. It covers every row of §6.3 and §6.5 and seeds from the ORM/job-queue query survey already in the repo (commit `59491209`, the subquery suite). Each case also asserts that the rewritten SQL parses and round-trips through `deparse`.
2. **Canary leak tests (integration)**: seed masked columns with unique canary values (`'CANARY-SSN-7f3a…'`). Run the corpus and an adversarial suite through PgDog as a restricted identity. Assert that **no canary bytes appear anywhere in the client byte stream**: rows, `RowDescription`, errors, notices, COPY data. This tests the invariant directly instead of the implementation.
3. **Equivalence tests**: for exempt profiles the rewritten SQL is byte-identical. For masked profiles, `RowDescription` names, types and formats match the unmasked query, and row counts match for queries without predicates on masked columns.
4. **Protocol matrix**: simple, extended named and unnamed, pipelined, `Execute` without `Describe`, binary result formats (pgx, JDBC, asyncpg), SQL `PREPARE`/`EXECUTE`, cursors, multi-statement, COPY text/CSV/binary. Run in `integration/` with Python, Ruby, Go and Java drivers, following the existing `integration/plugins/` harness.
5. **Sharded runs**: the same suites against the 2-shard integration setup, including cross-shard aggregates and `ORDER BY` on masked columns.
6. **Grammar fuzzing**: generate random queries over a schema with masked columns (sqlsmith-style, on top of `pg_raw_parse`), run them through the analyzer, and assert two things: the rewritten SQL never leaks a canary when executed, and every outcome is `Continue`/`Rewrite`/`Block`, never a panic.
7. **Core API tests**: capability gating, `catch_unwind` fail-closed behavior, `required` startup failure, re-preparing on a new generation, parameter checks, batched masks, mask failures closing the connection, and error redaction. These are done on `masking/plugin-api`, in-process and through a compiled plugin.

---

## 14. Delivery plan

### 14.1 Repositories

```
ewhauser/pgdog
 └─ masking/plugin-api   # narrow core patch: pgdog-plugin 0.7.0 + host hooks (§8)
ewhauser/pgdog-mask      # this plugin, depending on pgdog-plugin at a pinned masking/plugin-api commit
```

- `masking/plugin-api` is the patch to upstream into PgDog. It is a few logical commits, each building and passing tests. It contains no masking code. If the plugin needs something from core, the change goes there, and `Cargo.toml` here moves to the new commit.
- The plugin is its own project. It was developed on a `masking/plugin` branch in PgDog and extracted with its history.

### 14.2 Phases

**P1 status.** P1 is implemented in this repository, with these differences from the plan:
- **One crate, not three.** Modules `analyzer`, `config`, `profile`, `catalog`, `mask` and `engine` replace `masking-core`/`masking-plugin`. There is no `masking-cli` yet.
- **Built-in functions** were identified from an embedded list of PostgreSQL 16 `pg_catalog` function names, since the catalog had no `pg_proc` then. P2 replaced it.
- **Views failed closed** unless they were in `view_allowlist` or had masked columns of their own. P2 added view inlining.
- **`MERGE`, aliased joins, and `*` across `USING`/`NATURAL` joins** over masked columns are blocked, not rewritten.
- **Output names** of rewritten column references are pinned with `AS`, and leading comments (routing hints) are kept on rewritten statements.
- **Prepared statement re-checks** used a variant tag, the hash of the rewritten SQL. API 0.7 replaced it with the plugin's generation.
- **Tests:** an analyzer unit corpus, canary leak tests against Postgres (`tests/canary.rs`), and end-to-end tests through PgDog (`integration/run.sh`).

**P2 status.** Implemented on top of the full catalog (§8.5):
- **Views** are inlined with masks applied, or queried like tables with lineage-based masks (§6.6). `view_allowlist` is no longer the only way to read a view.
- **SQL functions** are analyzed, allowed, inlined or blocked (§6.7), and operators are treated as calls. Built-ins come from `pg_proc` through `system_functions`; the embedded PostgreSQL 16 list is only a unit-test fixture now. New setting: `extension_allowlist`.
- **Tags from the database** with `tag_source = "comment" | "security_label"` and `security_label_provider`, additive only, with removals logged at `warn` on schema reload; **`[[classifiers]]`** tag columns by name (§7.4).
- **Error and notice scrubbing** (§2, §8.4): the plugin removes `DETAIL` from every `ErrorResponse` and `NoticeResponse` masked users get. `scrub_error_detail = false` turns it off. Exempt users keep `DETAIL`.
- **Tests:** unit tests for lineage, tags, classifiers, view and function rewrites; the canary corpus covers views, functions, operators and `DETAIL` leaks (a `CHECK` violation's failing row, a trigger's notice) and loads its schema with PgDog's own catalog queries; e2e tests cover inlined views and functions, comment tags, classifiers and scrubbed errors through PgDog.
- **Not done yet:** `lint`, live template validation (§7.3), and the `explain`/`validate` CLI.


| Phase | Branch | Scope |
|---|---|---|
| **P0: API** ✅ | `masking/plugin-api` | 0.7.0: capabilities, `statement` verdicts with generations, `function_call`, batched `mask_rows`, `redact_error`, typed `catalog` with selectable parts, `reload`; `catch_unwind`, `required`, test plugins |
| **P1: MVP** ✅ | `masking/plugin` | config, users and profiles, built-in SQL masks, resolver (SELECT/CTE/subquery/join/set ops/`*`/whole-row), DML `RETURNING`, `INSERT…SELECT`, COPY, cursors, fail-closed rules, `search = "raw"`, shadow mode, `explain` CLI, canary suite |
| **P2: hardening** (mostly ✅) | `masking/plugin` | SQL-function analysis and inlining ✅, view inlining ✅, partitions ✅ (P1), conditional masking ✅ (P1), tags and classifiers (`config`/`comment`/`security_label`) ✅, error/notice scrubbing ✅, `lint`, live template validation |
| **P3: proxy masks** ✅ | this repository | typed column masks in the API, `hmac_sha256` and `ff1`, the `ProxyMask` library API and `masking_plugin!`, vault tokenization as an example of a custom mask |
| **Later** | | row access policies (inject `WHERE` predicates through the same statement hook), JSON-path masking (`jsonb_set`-based templates) |

---

## 15. Decisions and open questions

### Decided

1. **Config format.** TOML in PgDog's own style (§7): `[[array_tables]]`, flat keys, `database`/`schema`/`name`/`column`. Policies always live in TOML. Column tags may also come from the database, through comments or security labels, additively (§7.4).
2. **Searching masked columns.** Supported as an opt-in per policy rule (`search = "raw"`). It is restricted to direct comparison shapes so that it only allows an oracle, never direct exfiltration, and it is audited (§6.8).
3. **Identity changes mid-session.** Not supported. Masking identity comes from the authenticated PgDog user and is fixed for the session. `SET ROLE` is ignored because PgDog acknowledges it before Postgres validates it (§5.1).
4. **SQL-language functions.** Their bodies are analyzed, and inlined with masks applied when they touch masked columns. Procedural-language functions are allowlist-only (§6.7).
5. **Upstreaming.** The plugin API does not ship first. It is a narrow patch on its own branch, with the plugin on a branch built on top of it (§14.1).

### Open

1. **Rate limiting raw searches.** Equality-only search on low-entropy columns is still brute-forceable. Is audit logging enough, or does the plugin need per-user rate limits on raw-search statements?
2. **Database-sourced tag removal.** Removing a database tag unmasks a column after the next schema reload. Should that require an explicit `allow_tag_removal` acknowledgement in TOML instead of only logging a warning?
