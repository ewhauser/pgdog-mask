---
title: Error details
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

For masked users, the plugin removes `DETAIL` from **every** `ErrorResponse` and `NoticeResponse` Postgres sends, not only those of statements on masked tables: triggers and functions can raise errors about other tables. The severity and SQLSTATE always reach the client unchanged, so applications keep handling errors correctly. Exempt users keep `DETAIL`.

To keep `DETAIL` for everyone, turn it off:

```toml
[general]
scrub_error_detail = false
```

## Other fields

Only `DETAIL` is removed. Masking makes most other leaks impossible: for example `SELECT ssn::int FROM users` casts the masked value, so its error quotes the mask, not the real value. Messages from functions in `udf_allowlist` are your responsibility.
