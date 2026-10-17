---
title: Dynamic data masking for PgDog
description: Mask sensitive Postgres columns per user, in PgDog, without changing your application or your database.
tableOfContents: false
hero:
  title: Dynamic data masking for PgDog
  tagline: Apply column masking policies by authenticated user. SQL masks rewrite column references before execution; proxy masks mask result columns in code, and outputs computed from them return NULL.
  actions:
    - text: Install the plugin
      link: ./start/install/
      icon: right-arrow
    - text: How masking works
      link: ./start/overview/
      variant: secondary
    - text: Configuration reference
      link: ./reference/configuration/
      variant: minimal
---

:::caution[Requires a PgDog fork]
pgdog-mask uses PgDog's plugin API 0.8, which is only on the
[`ewhauser/pgdog`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api)
fork. It has been proposed upstream in
[pgdogdev/pgdog#1835](https://github.com/pgdogdev/pgdog/issues/1835), but
there's no guarantee it will be accepted, or accepted in this form. Build
PgDog from the commit pgdog-mask pins. See [compatibility](./reference/compatibility/).
:::

## Masking that holds up against real SQL

pgdog-mask is a [PgDog](https://github.com/pgdogdev/pgdog) plugin modeled on Snowflake's dynamic data masking. Policies are attached to columns, and each policy chooses a mask based on who is asking. The stored data never changes.

A column is masked in one of two ways:

- **SQL masks**, in the statement. References to the column, in the select list, `WHERE`, joins, `ORDER BY`, aggregates, subqueries, `RETURNING` or `COPY`, are replaced with the policy's mask before PgDog sends the statement on, so filters, sorting and aggregates work on masked values. Statements the plugin can't mask safely are blocked.
- **Proxy masks**, in the results. Postgres runs the statement unchanged, on real values, with the same plan, and the plugin replaces each output column that passes the column through with a value computed in code: keyed hashes, format-preserving encryption, vault tokens or your own Rust. Outputs computed from the column return `NULL`. Conditions and ordering use real values, so proxy masks are for trusted roles, such as engineers debugging production queries.

```sql
-- With an SQL mask on ssn, a support agent sends:
SELECT name, ssn FROM users WHERE ssn LIKE '123%';
-- and Postgres receives:
SELECT name, ('XXX-XX-' || right(ssn, 4))::text AS ssn
FROM users WHERE ('XXX-XX-' || right(ssn, 4))::text LIKE '123%';
```

Statements that don't touch masked columns, and statements of users nothing is masked for, pass through unchanged. See [how masking works](./start/overview/) for both.

1. Check the [prerequisites](./start/prerequisites/), then [install the plugin](./start/install/) and load it into PgDog.
2. [Mask your first column](./start/first-policy/) and check it as a masked user.
3. [Roll out with shadow mode](./start/shadow-mode/) before you enforce.

## Find what you need

| I want to… | Start here |
| --- | --- |
| Give different users different masks | [Users and roles](./configure/users/) · [Policies and rules](./configure/policies/) |
| Mask columns by name, tag or database comment | [Choose masked columns](./configure/columns/) |
| Let support find rows by a column's real value, while still seeing it masked | [Search on masked columns](./configure/raw-search/) |
| Mask with a secret key, FPE or a vault | [Proxy masks](./configure/proxy-masks/) |
| Write a mask in Rust | [Write a proxy mask](./develop/proxy-masks/) |
| Understand what's blocked and why | [What masked users can’t do](./reference/limitations/) · [Security model](./reference/security/) |
| Know what the logs cover | [Logs and maintenance](./operate/logs/) |
| Fix an error | [Troubleshoot](./operate/troubleshoot/) |
