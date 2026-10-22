import { LANGUAGES, Language } from '../catalog';
import { about } from './about';
import { acceptances } from './acceptances';
import { account } from './account';
import { audit } from './audit';
import { checklists } from './checklists';
import { common } from './common';
import { layout } from './layout';
import { login } from './login';
import { projects } from './projects';
import { reports } from './reports';
import { rules } from './rules';
import { standards } from './standards';
import { users } from './users';
import { tokens } from './tokens';
import { sso } from './sso';
import { access } from './access';
import { settings } from './settings';
import { trend } from './trend';
import { ticketing } from './ticketing';

/** Messages of every screen; add the catalog of a new screen here. */
const CATALOGS = [
  common,
  layout,
  login,
  account,
  about,
  projects,
  reports,
  acceptances,
  rules,
  checklists,
  standards,
  users,
  tokens,
  audit,
  sso,
  access,
  settings,
  trend,
  ticketing,
] as const;

type KeysOf<C> = C extends { en: Record<infer K, string> } ? K : never;

/** Key of a message of the web interface (checked by the compiler, also in templates). */
export type MessageKey = KeysOf<(typeof CATALOGS)[number]>;

/** Every message, by language then by key. */
export const MESSAGES = Object.fromEntries(
  LANGUAGES.map((language) => [
    language,
    Object.assign({}, ...CATALOGS.map((catalog) => catalog[language])),
  ]),
) as Record<Language, Record<MessageKey, string>>;
