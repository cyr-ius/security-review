/** Published documentation of the project (English at the root, French under `fr/`). */
export const DOCS_URL = 'https://cyr-ius.github.io/security-review/';

/**
 * Page of the documentation explaining a screen or a section, with the anchor of its heading
 * in each language (anchors follow the titles, so they differ between languages).
 */
export interface DocLink {
  path: string;
  anchor?: { en: string; fr: string };
}

export const DOC_LINKS = {
  projects: { path: 'usage/projects/' },
  triage: { path: 'usage/triage/' },
  acceptances: {
    path: 'usage/triage/',
    anchor: { en: 'risk-acceptances', fr: 'acceptations-de-risque' },
  },
  rules: { path: 'review/rules/' },
  checklists: { path: 'review/checklists/' },
  standards: { path: 'review/standards/' },
  settings: {
    path: 'advanced/architecture/controller/',
    anchor: { en: 'settings-stored-in-the-database', fr: 'reglages-enregistres-en-base' },
  },
  users: { path: 'usage/user-accounts/' },
  groups: { path: 'usage/access-control/', anchor: { en: 'groups', fr: 'groupes' } },
  roles: { path: 'usage/access-control/', anchor: { en: 'roles', fr: 'roles' } },
  tokens: { path: 'usage/tokens/' },
  personalTokens: {
    path: 'usage/tokens/',
    anchor: { en: 'personal-tokens', fr: 'jetons-personnels' },
  },
  oauthClients: {
    path: 'advanced/mcp-oauth/',
    anchor: { en: 'administration', fr: 'administration' },
  },
  oauthGrants: {
    path: 'advanced/mcp-oauth/',
    anchor: { en: 'connected-clients', fr: 'clients-connectes' },
  },
  sso: { path: 'usage/sso/' },
  osv: {
    path: 'review/analysis/dependencies/',
    anchor: {
      en: 'automatic-update-by-the-controller',
      fr: 'mise-a-jour-automatique-par-le-controleur',
    },
  },
  connectors: { path: 'usage/connectors/' },
  audit: { path: 'usage/audit-metrics/' },
  syslog: {
    path: 'usage/audit-metrics/',
    anchor: { en: 'forwarding-to-syslog', fr: 'envoi-vers-syslog' },
  },
} satisfies Record<string, DocLink>;

export type DocTopic = keyof typeof DOC_LINKS;
