---
title: Security model
description: What pgdog-mask protects against, and what your deployment must enforce.
---

## What it protects

A client connected through PgDog as a masked user, sending arbitrary SQL, can't read the values of masked columns: not directly, and not by inference through filters, ordering, aggregates, errors, side tables, statistics, functions, views, `COPY` or cursors. The plugin rewrites what it can mask and blocks what it can't prove safe.

Leaks are tested directly: the canary suite seeds masked columns with unique values, runs an adversarial corpus as a masked user against Postgres, and fails if a canary appears anywhere in rows, errors, notices or `COPY` output.

## What your deployment must enforce

1. **Clients can't reach Postgres directly.** Masking only applies to connections through PgDog. Enforce this with network policy and credentials.
2. **The Postgres role masked users run as doesn't own the masked tables, and can't create functions or views.** This is defense in depth, should the analyzer have a bug: a role that can't create code can't hide a leak in it.
3. **Configuration and keys are protected like credentials.** Whoever can change the configuration can unmask any column. Keep proxy mask keys in environment variables or files readable only by PgDog.
4. **PgDog runs with `required = true`** for the plugin, so it never serves traffic without masking.

## Identity

Masking decisions use the PgDog user the client authenticated as. `SET ROLE` and client-supplied values such as `application_name` never change them. See [Users and roles](../../configure/users/#which-identity-counts).

## Known limits

- **Inference from unmasked columns** correlated with masked ones.
- **Timing side channels.**
- **Raw search** deliberately allows confirming guesses, for the roles you give it to. See [Search on masked columns](../../configure/raw-search/#what-youre-allowing).
- **Copies of masked data** elsewhere, unmasked: denormalized columns, JSON documents, audit tables, or tables exempt users fill. Classifiers help find columns by name.
- **Allowlisted code** (`udf_allowlist`, `extension_allowlist`, `view_allowlist`) runs without analysis. Only list code that can't return masked data.
