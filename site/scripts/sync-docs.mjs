// Publish the repository's design document as a Contribute page.
//
// Everything this script writes is ignored by git (see site/.gitignore); the
// source of truth stays in ../docs. Links to other repository files become
// links to GitHub.
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoDir = path.resolve(siteDir, '..');
const contentDir = path.join(siteDir, 'src/content/docs');
const repoUrl = 'https://github.com/ewhauser/pgdog-mask';

/** Repository documents published on the site, with their pages. */
const pages = [
	{
		source: 'docs/DESIGN.md',
		target: 'contribute/design.md',
		title: 'Design notes',
		description: 'How pgdog-mask and the PgDog plugin API it uses were designed, and why: the original plan, with notes on what was built.',
		// A design record, not a reference: keep it out of search, so readers
		// looking up behavior land on the guides.
		search: false,
		banner: [
			':::caution[Design record]',
			'This is the plan pgdog-mask was built from, with notes on what changed. It isn\'t a reference: some features it describes are **not implemented**, and it\'s left out of search. For current behavior, see the [guides](../../start/overview/) and the [reference](../../reference/configuration/).',
			'',
			`Generated from [\`docs/DESIGN.md\`](${repoUrl}/blob/main/docs/DESIGN.md). Edit it there.`,
			':::',
		],
	},
];

/** Repository files with a hand-written page instead. Relative to the page. */
const routes = new Map([
	['README.md', '../../start/overview/'],
]);

const rewriteLink = (target, sourceRel) => {
	if (/^(https?:|mailto:|#)/.test(target)) return target;
	const [rawPath, fragment] = target.split('#');
	const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(sourceRel), rawPath));
	if (routes.has(resolved)) return routes.get(resolved);
	const absolute = path.join(repoDir, resolved);
	if (!existsSync(absolute)) {
		console.warn(`${sourceRel}: unresolved link ${target}`);
		return target;
	}
	const kind = statSync(absolute).isDirectory() ? 'tree' : 'blob';
	const url = `${repoUrl}/${kind}/main/${resolved}`;
	return fragment ? `${url}#${fragment}` : url;
};

for (const page of pages) {
	let markdown = readFileSync(path.join(repoDir, page.source), 'utf8');
	// The page title comes from frontmatter.
	markdown = markdown.replace(/^# .*\n+/, '');
	// Links outside code: [text](target).
	markdown = markdown.replace(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewriteLink(target, page.source)})`);

	const frontmatter = [
		'---',
		`title: ${JSON.stringify(page.title)}`,
		`description: ${JSON.stringify(page.description)}`,
		`editUrl: ${JSON.stringify(`${repoUrl}/edit/main/${page.source}`)}`,
		...(page.search === false ? ['pagefind: false'] : []),
		'---',
		'',
		...(page.banner ?? [
			`:::note[Engineering document]`,
			`This page is generated from [\`${page.source}\`](${repoUrl}/blob/main/${page.source}). Edit it there.`,
			':::',
		]),
		'',
	].join('\n');

	const target = path.join(contentDir, page.target);
	mkdirSync(path.dirname(target), { recursive: true });
	writeFileSync(target, frontmatter + markdown);
}
