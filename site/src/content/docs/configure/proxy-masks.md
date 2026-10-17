---
title: Proxy masks
description: Mask columns in code, in the plugin, with keyed hashes, format-preserving encryption, vault tokens or your own logic.
---

SQL masks are expressions Postgres evaluates. Some masks shouldn't or can't be written that way:

- a **keyed hash** whose key must never appear in a statement, where `pg_stat_statements`, server logs and `EXPLAIN` would expose it;
- **format-preserving encryption**, which Postgres doesn't implement;
- **tokens from a vault**, which Postgres can't call;
- any **logic you write in Rust**.

A proxy mask is computed by the plugin, on the rows Postgres returns, before they reach the client.

```toml
[[policies]]
name = "card"
data_type = "character varying"
mask = "proxy"
proxy = "ff1"                              # the proxy mask's registered name
options = { key_env = "CARD_FF1_KEY" }     # passed to the mask
fallback = "partial"                       # SQL mask for every other reference
keep_suffix = 4                            # used by the fallback

[[policies.rules]]
roles = ["pii_admin"]
mask = "none"
```

## Where proxy masks apply

A proxy mask applies to a column **output by a single top-level `SELECT`**, as a plain column reference, optionally aliased, or through `*`. Every other reference to the column gets the policy's SQL `fallback` (`null` by default):

| Statement | `card` gets |
| --- | --- |
| `SELECT id, card FROM payments` | the proxy mask |
| `SELECT card AS c FROM payments WHERE id = $1` | the proxy mask |
| `SELECT * FROM payments` | the proxy mask |
| `SELECT … WHERE card = $1`, joins on `card` | the fallback, in the condition |
| `SELECT card … ORDER BY card` or `ORDER BY 1` | the fallback: ordering would use real values |
| `SELECT DISTINCT card`, `GROUP BY`, `HAVING` | the fallback |
| `upper(card)`, `card \|\| ''` | the fallback |
| subqueries, CTEs, views, functions, `UNION` | the fallback |
| `COPY`, `INSERT … SELECT`, `SELECT INTO`, `RETURNING` | the fallback |
| several statements in one query | the fallback |

So filtering, ordering, grouping and aggregates work on the fallback, not on real values, as with SQL masks. A rule with [`search = "raw"`](../raw-search/) can still search on the real value.

## Built-in proxy masks

| `proxy` | Types | Options | Result |
| --- | --- | --- | --- |
| `hmac_sha256` | text types | `key_env` or `key_file`; `length` (1–64) | Hex HMAC-SHA256 of the value, optionally truncated to `length` digits. The same value always gives the same result under the same key, so clients can join, group and count the tokens they receive. SQL can't: `GROUP BY`, joins and conditions on the column get the fallback. |
| `ff1` | text types | `key_env` or `key_file`: a hex AES key of 16, 24 or 32 bytes; `alphabet`: `digits` (default), `alphanumeric`, or the characters themselves; `tweak` | NIST FF1 format-preserving encryption. Characters in the alphabet are encrypted in place and others kept, so `4111-1111-1111-1111` stays `NNNN-NNNN-NNNN-NNNN`. Values with too few alphabet characters for FF1 (fewer than 6 digits) are replaced with `*`. |

Keys come from the environment variable named by `key_env`, or the file named by `key_file`, so they don't appear in the configuration file. They're read each time the configuration loads; see [rotating keys](../../operate/logs/#rotate-proxy-mask-keys). A mask that can't be built, for example because its key is missing, is a configuration error.

## Your own masks

Proxy masks are Rust code registered by name. To add your own, build the plugin with them: see [Write a proxy mask](../../develop/proxy-masks/).

## Behavior

- **Types and formats.** A proxy mask returns a value of the column's type. Values are decoded from, and encoded back into, whatever format the client requested, text or binary.
- **Batches.** The plugin masks rows in batches of up to 256 rows that have already arrived from Postgres, so it doesn't wait for more rows before sending the ones it has.
- **Failures.** If a proxy mask fails, the query is canceled and the client's connection is closed with a `FATAL` error, since some rows may already have been sent.
- **Cost.** Every masked value goes through the plugin. Prefer SQL masks where a keyed or coded mask isn't needed.
