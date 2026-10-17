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

In `enforce` mode, the plugin removes `DETAIL` from every `ErrorResponse` and `NoticeResponse` Postgres sends a masked user, not only those of statements on masked tables: triggers and functions can raise errors about other tables. The severity and SQLSTATE reach the client unchanged, so applications keep handling errors correctly. Exempt users keep `DETAIL`, and so does everyone in `shadow` mode, which doesn't change what clients receive.

To keep `DETAIL` for everyone, turn it off:

```toml
[general]
scrub_error_detail = false
```

## Other fields

Only `DETAIL` is removed. Other fields, such as the message itself, are left as they are. Masking prevents most leaks through them: for example `SELECT ssn::int FROM users` casts the masked value, so its error quotes the mask, not the real value. Messages from functions in `udf_allowlist` and extensions in `extension_allowlist` are your responsibility.
