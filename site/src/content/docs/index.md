---
title: Dynamic data masking for PgDog
description: Mask sensitive Postgres columns per user, in every statement, without changing your application or your database.
tableOfContents: false
hero:
  title: Dynamic data masking for PgDog
  tagline: Define masking policies once. pgdog-mask rewrites every statement a masked user sends, so Postgres only ever returns masked values to them.
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
pgdog-mask uses PgDog's plugin API 0.7, which is on the
[`ewhauser/pgdog`](https://github.com/ewhauser/pgdog/tree/masking/plugin-api)
fork until it's merged upstream. Build PgDog from the commit pgdog-mask pins.
See [compatibility](./reference/compatibility/).
:::

## Masking that holds up against real SQL

pgdog-mask is a [PgDog](https://github.com/pgdogdev/pgdog) plugin modeled on Snowflake's dynamic data masking. Policies are attached to columns, and each policy chooses a mask based on who is asking. The stored data never changes.

A column is masked in one of two ways:

- **SQL masks**, in the statement. Every reference to the column, in the select list, `WHERE`, joins, `ORDER BY`, aggregates, subqueries, `RETURNING` or `COPY`, is replaced with the policy's mask before PgDog sends the statement on, so filters, sorting and aggregates can't be used to recover real values.
- **Proxy masks**, in the results. The plugin computes the masked value in code, for keyed hashes, format-preserving encryption, vault tokens or your own Rust, and replaces the real value in the rows Postgres returns.

```sql
-- With an SQL mask on ssn, a support agent sends:
SELECT name, ssn FROM users WHERE ssn LIKE '123%';
-- and Postgres receives:
SELECT name, ('XXX-XX-' || right(ssn, 4))::text AS ssn
FROM users WHERE ('XXX-XX-' || right(ssn, 4))::text LIKE '123%';
```

See [how masking works](./start/overview/) for both.

1. [Install the plugin](./start/install/) and load it into PgDog.
2. [Mask your first column](./start/first-policy/) and check it as a masked user.
3. [Roll out with shadow mode](./start/shadow-mode/) before you enforce.

## Find what you need

| I want to… | Start here |
| --- | --- |
| Give different users different masks | [Users and roles](./configure/users/) · [Policies and rules](./configure/policies/) |
| Mask columns by name, tag or database comment | [Choose masked columns](./configure/columns/) |
| Let support look rows up by a masked value | [Search on masked columns](./configure/raw-search/) |
| Mask with a secret key, FPE or a vault | [Proxy masks](./configure/proxy-masks/) |
| Write a mask in Rust | [Write a proxy mask](./develop/proxy-masks/) |
| Understand what's blocked and why | [What masked users can’t do](./reference/limitations/) · [Security model](./reference/security/) |
| Fix an error | [Troubleshoot](./operate/troubleshoot/) |
