# Documentation site

Astro + Starlight user documentation for pgdog-mask, published to
https://ewhauser.github.io/pgdog-mask/ by `.github/workflows/site.yml`.

```sh
pnpm install --frozen-lockfile
pnpm dev     # sync, then serve http://localhost:4321/pgdog-mask/
pnpm build   # sync, build, build search, validate internal links
```

Write pages in `src/content/docs/{start,configure,develop,operate,reference,contribute}`;
the homepage is `src/content/docs/index.md` and the sidebar is in `astro.config.mjs`.

`pnpm sync` runs before dev and build. It publishes `../docs/DESIGN.md` as
`contribute/design`, which is ignored by git: edit the repository source.

Check a documentation change by reading it against the current code, running
`pnpm build`, and opening the result on desktop and a narrow viewport. For another
host, override both `SITE_URL` and `SITE_BASE`.
