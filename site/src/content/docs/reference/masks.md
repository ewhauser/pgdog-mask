---
title: Masks
description: Every mask, the types it supports, and its keys.
---

A mask is set with `mask` and its keys, on a policy or a rule. Every SQL mask is an expression over the column's value, cast back to the column's type.

## SQL masks

| `mask` | Types | Keys | Result |
| --- | --- | --- | --- |
| `none` | any | | The real value: not masked. |
| `null` | any | | `NULL`. |
| `constant` | any | `value`, a TOML string | `value` as a string literal, cast to the column's type. |
| `default` | any | | A placeholder for the type: `'****'` for text, `0` for numbers, `1970-01-01` for dates, `1970-01-01 00:00:00` for timestamps, `00:00:00` for times, `false`, the nil UUID, `'{}'` for JSON, empty `bytea`, `NULL` otherwise. |
| `partial` | text | `keep_prefix` (default 0), `keep_suffix` (default 0), `fill` (default `*`) | Keeps the first and last characters and fills the rest: `left(val, p) \|\| repeat(fill, greatest(length(val) - p - s, 0)) \|\| right(val, s)`. |
| `email` | text | | Masks the local part: `regexp_replace(val, '^[^@]*', '****')`, so `alice@example.com` becomes `****@example.com`. |
| `hash` | text, `bytea` | | SHA-256, hex for text. Unkeyed, so low-entropy values can be found by hashing guesses; use the `hmac_sha256` proxy mask for a keyed hash. |
| `round` | numeric | `digits` (default 0) | `round(val::numeric, digits)`, cast back to the column's type. Negative `digits` round to tens, hundreds, and so on. |
| `truncate` | date, timestamp | `unit` (default `year`) | `date_trunc(unit, val)`. |
| `sql` | as declared | `expression` | Your expression over `val` and the policy's `arguments`. No subqueries or other columns. |

"Text" includes `text`, `character varying`, `character`, `name` and `citext`. "Numeric" includes the integer, `numeric` and floating-point types.

`constant`'s `value` is always a TOML string, whatever the column's type. Postgres converts it with the cast:

```toml
[[policies]]
name = "salary"
data_type = "numeric"
mask = "constant"
value = "0"          # a string, not 0: becomes '0'::numeric
```

## Proxy masks

Proxy masks mask output columns that pass the column through, in the results. Outputs computed from the column return `NULL`, and conditions, joins and ordering use real values. See [Proxy masks](../../configure/proxy-masks/).

| Key | Description |
| --- | --- |
| `mask = "proxy"` | Compute the mask in the plugin. |
| `proxy` | Name of the proxy mask: `hmac_sha256`, `ff1`, or [one you registered](../../develop/proxy-masks/). |
| `options` | Table passed to the proxy mask. |
| `fallback` | Removed: a configuration error. Proxy masks no longer rewrite other references to the column. |

The SQL mask keys, `value`, `keep_prefix`, `keep_suffix`, `fill`, `digits`, `unit` and `expression`, don't apply to `mask = "proxy"`, and neither do `search = "raw"` and `search_operators`: proxy rules always search real values. Each is a configuration error on a proxy rule.

### `hmac_sha256`

Text types. Hex HMAC-SHA256 of the value.

| Option | Description |
| --- | --- |
| `key_env` or `key_file` | The key: an environment variable, or a file whose contents (without trailing whitespace) are the key. |
| `length` | Keep only the first `length` hex digits, 1–64. |

### `ff1`

Text types. Format-preserving encryption with NIST SP 800-38G FF1 and AES.

| Option | Description |
| --- | --- |
| `key_env` or `key_file` | The key: a hex-encoded AES key of 16, 24 or 32 bytes. |
| `alphabet` | Characters to encrypt: `digits` (default), `alphanumeric`, or the characters themselves. Others are kept in place. |
| `tweak` | An optional string mixed into the encryption, so the same value encrypts differently under different tweaks. |

Values with fewer alphabet characters than FF1 requires (6 digits, for `digits`) have those characters replaced with `*`.
