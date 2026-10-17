---
title: Upgrade a deployment
description: Deploy a new version of pgdog-mask, and the PgDog build it needs, to running PgDog instances.
---

Each pgdog-mask commit pins the PgDog commit it's built against. PgDog skips a plugin built against another plugin API version or by another Rust compiler, and with `required = true`, refuses to start. So pgdog-mask and PgDog are always upgraded together.

1. **Build both.** Build PgDog from the commit the new pgdog-mask's `Cargo.toml` pins, and the plugin, with the toolchain in `rust-toolchain.toml`, as in [Install the plugin](../../start/install/). If you build [your own plugin](../../develop/proxy-masks/), rebuild it against the new pgdog-mask.
2. **Read what changed.** The analyzer may block or rewrite statements differently between versions, and configuration keys may change.
3. **Test with your configuration.** Start the new build with your `masking.toml` outside production. The plugin validates the file at startup; with `required = true`, PgDog doesn't start if it's invalid, and logs why. Then run your application's statements against it, ideally in [shadow mode](../../start/shadow-mode/) first, to find statements the new version would block.
4. **Deploy by restarting.** Plugins are loaded at startup, so replacing the library needs a restart; a reload doesn't load the new plugin. Replace PgDog and the plugin on each instance together, and restart them one at a time if your clients can reconnect to another instance.
5. **Check each instance.** Look for `loaded "pgdog_mask" plugin` and the plugin's `loaded … policies` line in the log; see [Logs and maintenance](../logs/#confirm-the-active-configuration).

Keep the previous PgDog binary and plugin library to roll back. Roll them back together, for the same reason.

Moving pgdog-mask itself to a new PgDog commit is a development task: see [Maintain the PgDog dependency](../../develop/pgdog-dependency/).
