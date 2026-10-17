---
title: Roll out with shadow mode
description: Run the full analysis on production traffic and log what would change, before you enforce masking.
---

Masking changes results and blocks statements the plugin can't prove safe. Before enforcing it on existing applications, run it in **shadow mode**: statements are analyzed as in enforcement, but sent unchanged, and the decisions are logged.

```toml
[general]
mode = "shadow"
```

## What shadow mode logs

Statements are logged normalized, with literals replaced by placeholders, so searched values never reach the logs.

- Statements that would be rewritten, at `info`:

  ```text
  [pgdog_mask] (shadow) would rewrite statement for user "support_app", masked {"public.users.ssn"}: SELECT name, ssn FROM users WHERE id = $1
  ```

- Statements that would be blocked, at `warn`, with the reason:

  ```text
  [pgdog_mask] (shadow) blocked statement for user "support_app": function public.lookup_ssn() is written in plpgsql and can't be analyzed; add it to udf_allowlist if it's safe [SELECT public.lookup_ssn($1)]
  ```

- Searches on raw values, for rules with `search = "raw"`, at `info`.

Each statement is logged when it's analyzed: the first time it's seen for a masking profile, not every time it runs. Statements that differ only in literal values share one message, and prepared statements are logged when they're prepared. Shadow-mode logs show which kinds of statements would change, not how often. See [what the logs cover](../../operate/logs/#analysis-logs-not-an-audit-trail).

:::note[Proxy masks aren't logged]
A statement that would only be masked by [proxy masks](../../configure/proxy-masks/), in its results, logs nothing in shadow mode, because the statement itself wouldn't change. To see proxy masks working, test them with `mode = "enforce"` outside production.
:::

## Roll out

1. Deploy with `mode = "shadow"` and `required = true`.
2. Watch the logs for blocked statements. For each, decide whether to change the application, allowlist a function or view that can't return masked data (`udf_allowlist`, `view_allowlist`, `extension_allowlist`), or accept the block.
3. Review rewrites on hot paths. A masked column in a `WHERE` clause can't use its index; see [performance](../../operate/performance/#indexes).
4. Switch to `mode = "enforce"` and [reload](../../operate/reload/).

`mode = "off"` disables the plugin's decisions entirely while keeping it loaded.
