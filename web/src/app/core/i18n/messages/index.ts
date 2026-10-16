import { LANGUAGES, Language } from '../catalog';
import { account } from './account';
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
import { mappings } from './mappings';
import { settings } from './settings';
import { trend } from './trend';

/** Messages of every screen; add the catalog of a new screen here. */
const CATALOGS = [
  common,
  layout,
  login,
  account,
  projects,
  reports,
  rules,
  checklists,
  standards,
  users,
  tokens,
  mappings,
  settings,
  trend,
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
