// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

const repo = 'https://github.com/ewhauser/pgdog-mask';
// GitHub Pages serves a project site under /pgdog-mask. Override both for a
// custom domain: SITE_URL=https://docs.example.com SITE_BASE=/ pnpm build
const site = process.env.SITE_URL ?? 'https://ewhauser.github.io';
const base = process.env.SITE_BASE ?? '/pgdog-mask';

export default defineConfig({
	site,
	base,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'pgdog-mask',
			description: 'Dynamic data masking for PgDog: column policies applied by authenticated user, in the statement or in its results.',
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: repo }],
			editLink: { baseUrl: `${repo}/edit/main/site/` },
			lastUpdated: true,
			customCss: ['./src/styles/custom.css'],
			components: {
				SiteTitle: './src/components/SiteTitle.astro',
				Footer: './src/components/Footer.astro',
			},
			head: [
				{ tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.googleapis.com' } },
				{ tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' } },
				{
					tag: 'link',
					attrs: {
						rel: 'stylesheet',
						href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;450;500;550;600;650&display=swap',
					},
				},
			],
			plugins: [
				starlightLinksValidator({
					errorOnRelativeLinks: false,
					errorOnLocalLinks: false,
				}),
			],
			sidebar: [
				{ label: 'Get started', items: [
					{ label: 'How masking works', slug: 'start/overview' },
					{ label: 'Prerequisites', slug: 'start/prerequisites' },
					{ label: 'Install the plugin', slug: 'start/install' },
					{ label: 'Mask your first column', slug: 'start/first-policy' },
					{ label: 'Roll out with shadow mode', slug: 'start/shadow-mode' },
				] },
				{ label: 'Configure', collapsed: true, items: [
					{ label: 'Users and roles', slug: 'configure/users' },
					{ label: 'Policies and rules', slug: 'configure/policies' },
					{ label: 'Choose masked columns', slug: 'configure/columns' },
					{ label: 'Proxy masks', slug: 'configure/proxy-masks' },
					{ label: 'Search on masked columns', slug: 'configure/raw-search' },
					{ label: 'Views and functions', slug: 'configure/views-functions' },
					{ label: 'Error and notice redaction', slug: 'configure/errors' },
				] },
				{ label: 'Operate', collapsed: true, items: [
					{ label: 'Validate a configuration', slug: 'operate/validate' },
					{ label: 'Reload configuration', slug: 'operate/reload' },
					{ label: 'Logs and maintenance', slug: 'operate/logs' },
					{ label: 'Upgrade a deployment', slug: 'operate/upgrade' },
					{ label: 'Performance', slug: 'operate/performance' },
					{ label: 'Troubleshoot', slug: 'operate/troubleshoot' },
				] },
				{ label: 'Develop', collapsed: true, items: [
					{ label: 'Write a proxy mask', slug: 'develop/proxy-masks' },
					{ label: 'Development and tests', slug: 'contribute' },
					{ label: 'Maintain the PgDog dependency', slug: 'develop/pgdog-dependency' },
					{ label: 'Design notes', slug: 'contribute/design' },
				] },
				{ label: 'Reference', collapsed: true, items: [
					{ label: 'Configuration', slug: 'reference/configuration' },
					{ label: 'Masks', slug: 'reference/masks' },
					{ label: 'What masked users can’t do', slug: 'reference/limitations' },
					{ label: 'Security model', slug: 'reference/security' },
					{ label: 'Compatibility', slug: 'reference/compatibility' },
				] },
			],
		}),
	],
});
