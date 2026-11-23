import {
  FINDING_STATUS_FILTERS,
  FindingStatusFilter,
  FindingStatus,
  SEVERITIES,
  Severity,
} from '../../core/models/api.models';

/** Longest text sent to the search of the findings or of the reports (the API refuses more). */
export const MAX_SEARCH_CHARS = 200;

/** Projects offered for one search (each one gives three entries). */
const MAX_PROJECTS = 3;

/** Filters typed in the search (``project:``, ``severity:``, ``status:``). */
export interface SearchFilters {
  /** Project of the findings or the reports (lowercase, as stored). */
  project?: string;
  /** Any of these severities (risk level for the reports; empty: every one). */
  severity: Severity[];
  /** Any of these statuses of the findings (empty: the default, open findings). */
  status: FindingStatusFilter[];
}

/** What a search of the top bar can open. */
export type SearchTarget =
  /** The page of one report, its findings searched for ``text`` ('': all of them). */
  | { kind: 'report'; id: number; text: string }
  /** One finding among the findings of its project (``project`` when already known). */
  | { kind: 'finding'; id: number; project?: string }
  /** The list of the reports, searched for ``text`` ('': every report). */
  | { kind: 'reports'; text: string; filters: SearchFilters }
  /** The list of the findings, searched for ``text`` ('': every finding). */
  | { kind: 'findings'; text: string; filters: SearchFilters }
  /** The page of a project. */
  | { kind: 'project'; name: string }
  /** The findings of a project. */
  | { kind: 'projectFindings'; name: string }
  /** The reports of a project. */
  | { kind: 'projectReports'; name: string }
  /** The rules, searched for a text, an id (``#PY-004``) or the ids starting so (``#AI*``). */
  | { kind: 'rules'; search: string }
  /** The checklists, searched the same way (``#PY-01``). */
  | { kind: 'checklists'; search: string }
  /** The development standards, searched for a text. */
  | { kind: 'standards'; search: string };

/** ``#report:<value>`` or ``#finding:<value>`` (case-insensitive). */
const QUALIFIER = /^#(report|finding)s?:(.*)$/i;

/** ``project:``, ``severity:`` (``sev:``), ``status:``, ``rule:`` or ``cwe:`` and its value. */
const FILTER = /^(project|severity|sev|status|rule|cwe):(.+)$/i;

/** A number of a report or a finding (no sign, no decimals, within the safe integers). */
const ID = /^#?(\d{1,15})$/;

/**
 * ``#R7`` / ``#F12`` (report 7, finding 12, numbered as the interface shows them) and ``#R*`` /
 * ``#F*``: short for ``#report:`` and ``#finding:`` (case-insensitive); the ``#`` tells them from
 * words such as "R2" or "F5".
 */
const SHORT_QUALIFIER = /^#([RF])(\*|\d{1,15})$/i;

/** A word with ``#R``/``#F`` written out as ``#report:``/``#finding:``. */
function expand(word: string): string {
  const short = SHORT_QUALIFIER.exec(word);
  if (!short) {
    return word;
  }
  return `#${short[1].toUpperCase() === 'R' ? 'report' : 'finding'}:${short[2]}`;
}

/** ``author:alice`` / ``author:ali*``: the reports and findings of that author (server side). */
const AUTHOR = /^author:\S+$/i;

/** ``#F1*`` / ``#R2*``: the findings or the reports whose number starts with 1 or 2. */
const NUMBER_PREFIX = /^#([RF])\d{1,15}\*$/i;

/**
 * ``#PY-004`` alone: the id of a scan rule or of a checklist item, ``#AI*`` the ids starting with
 * AI (a letter first, then letters, digits and the separators of the ids); a rule has three
 * digits or more by convention, a checklist item two. ``#F…`` / ``#R…`` numbers excluded.
 */
const RULE_ID = /^#([A-Z][\w.:-]{0,59}\*?)$/i;
const NUMBER_LIKE = /^#[RF]\d*\*?$/i;

/** ``#GEN-007``, ``#AI*``: a rule id (a digit or the ``*`` required: "#include" stays text). */
function isRuleId(word: string): boolean {
  const found = NUMBER_LIKE.test(word) || QUALIFIER.test(word) ? null : RULE_ID.exec(word);
  return !!found && /[\d*]/.test(found[1]);
}

/** ``#F12``: a finding by its number, searched with other words (``xss #F12``). */
const FINDING_NUMBER = /^#F\d{1,15}$/i;

/** ``#5`` alone: a number without its letter, either the finding or the report. */
const BARE_ID = /^#(\d{1,15})$/;

/** What the user typed, split into its parts. */
interface ParsedSearch {
  /** A ``#…`` word only the findings have (rule id, finding number), sent with the text. */
  findingsOnly?: boolean;
  /** ``#report:`` or ``#finding:``, with its value (the first one only). */
  qualifier?: { scope: 'report' | 'finding'; value: string };
  filters: SearchFilters;
  /** Words searched as text, spaces collapsed, ``*`` alone for everything. */
  text: string;
  /** Nothing but text: the projects may be offered. */
  plain: boolean;
}

/** Values of a filter (``high,critical``) that belong to ``known``; null if one does not. */
function values<T extends string>(value: string, known: readonly T[]): T[] | null {
  const given = value.toLowerCase().split(',').filter(Boolean);
  const kept = known.filter((item) => given.includes(item));
  return kept.length === given.length ? kept : null;
}

function parse(raw: string): ParsedSearch {
  const filters: SearchFilters = { severity: [], status: [] };
  const words: string[] = [];
  let qualifier: ParsedSearch['qualifier'];
  let plain = true;
  let findingsOnly = false;
  const typedWords = raw.trim().split(/\s+/).filter(Boolean);
  for (const typed of typedWords) {
    if (typedWords.length > 1 && (isRuleId(typed) || FINDING_NUMBER.test(typed))) {
      // "scan code #GEN-007", "xss #F12": the server reads the word, with the text
      words.push(typed.toUpperCase());
      findingsOnly = true;
      plain = false;
      continue;
    }
    if (AUTHOR.test(typed)) {
      // "author:alice": a filter of the reports and the findings, read by the server
      words.push(typed);
      plain = false;
      continue;
    }
    if (NUMBER_PREFIX.test(typed) && !qualifier) {
      // "#F1*": the findings (or reports) numbered from 1, a search the server reads
      const scope = typed[1].toUpperCase() === 'R' ? 'report' : 'finding';
      qualifier = { scope, value: '*' };
      plain = false;
      words.push(typed.toUpperCase());
      continue;
    }
    const word = expand(typed);
    const prefixed = QUALIFIER.exec(word);
    if (prefixed && !qualifier) {
      const scope = prefixed[1].toLowerCase() === 'report' ? 'report' : 'finding';
      qualifier = { scope, value: prefixed[2] };
      plain = false;
      // A text value stays in the searched text, where it was typed
      if (prefixed[2] && prefixed[2] !== '*' && !ID.test(prefixed[2])) {
        words.push(prefixed[2]);
      }
      continue;
    }
    const filter = FILTER.exec(word);
    const key = filter?.[1].toLowerCase();
    const value = filter?.[2] ?? '';
    if (key === 'project') {
      filters.project = value.toLowerCase();
    } else if (key === 'severity' || key === 'sev') {
      const severities = values(value, SEVERITIES);
      if (!severities) {
        words.push(word);
        continue;
      }
      filters.severity = severities;
    } else if (key === 'status') {
      const statuses = values(value, FINDING_STATUS_FILTERS);
      if (!statuses) {
        words.push(word);
        continue;
      }
      filters.status = statuses;
    } else if (key === 'rule' || key === 'cwe') {
      // The rule and the CWE are among the searched columns
      words.push(value);
    } else {
      words.push(word);
      continue;
    }
    plain = false;
  }
  const joined = words.join(' ');
  const text = joined === '*' ? '' : joined.slice(0, MAX_SEARCH_CHARS);
  return { qualifier, filters, text, plain, findingsOnly };
}

/**
 * Targets of what the user typed, the first one opened by Enter. ``#R7`` alone opens report 7
 * and ``#F12`` alone finding 12, as the interface numbers them; ``#5`` alone offers finding 5
 * and report 5; ``#PY-004`` alone offers the rule, the checklist item and the findings of that
 * id; plain text also offers the rules, the checklists and the standards containing it. One qualifier, anywhere:
 * - ``#report:<number>``: that report, its findings searched for the rest of the text
 *   (``xss #report:1``: "xss" in report 1);
 * - ``#finding:<number>``: that finding, in its report;
 * - ``#report:*`` / ``#finding:*`` (or nothing after ``:``): the reports or the findings
 *   containing the rest of the text, every one without text;
 * - ``#report:<text>`` / ``#finding:<text>``: the reports or the findings containing the text;
 * - no qualifier: the findings, then the reports containing the text (``*``: every one).
 *
 * Filters narrow the lists: ``project:<name>``, ``severity:<s>`` or ``sev:<s>`` (several
 * separated by commas; the risk level of the reports), ``status:<s>`` (the findings only);
 * ``rule:<id>`` and ``cwe:<n>`` are searched as text. An unknown value is searched as text.
 */
export function parseSearch(raw: string): SearchTarget[] {
  if (!raw.trim()) {
    return [];
  }
  const typed = raw.trim();
  const ruleId = isRuleId(typed) ? RULE_ID.exec(typed) : null;
  if (ruleId) {
    // A rule or a checklist item: both offered, the likely one first, then the findings of the
    // rule (the server reads "#PY-004" and "#AI*" as rule ids, not as text)
    const id = ruleId[1].toUpperCase();
    const rule: SearchTarget = { kind: 'rules', search: `#${id}` };
    const item: SearchTarget = { kind: 'checklists', search: `#${id}` };
    const likelyItem = /-\d{1,2}$/.test(id);
    return [
      ...(likelyItem ? [item, rule] : [rule, item]),
      { kind: 'findings', text: `#${id}`, filters: { severity: [], status: [] } },
    ];
  }
  const bare = BARE_ID.exec(raw.trim());
  if (bare) {
    // "#5" alone: finding F5 or report R5, both offered (findings first, as for a text)
    const id = Number(bare[1]);
    return [
      { kind: 'finding', id },
      { kind: 'report', id, text: '' },
    ];
  }
  const { qualifier, filters, text, findingsOnly, plain } = parse(raw);
  if (findingsOnly) {
    // "#R12 #PY-004": the findings of report 12 for that rule, all read by the server
    const report = qualifier?.scope === 'report' ? ID.exec(qualifier.value) : null;
    return [{ kind: 'findings', text: report ? `#R${report[1]} ${text}` : text, filters }];
  }
  const id = qualifier && ID.exec(qualifier.value);
  if (qualifier && id) {
    return qualifier.scope === 'report'
      ? [{ kind: 'report', id: Number(id[1]), text }]
      : [{ kind: 'finding', id: Number(id[1]) }];
  }
  if (qualifier?.scope === 'report') {
    return [{ kind: 'reports', text, filters }];
  }
  if (qualifier?.scope === 'finding' || filters.status.length) {
    // A status only applies to the findings
    return [{ kind: 'findings', text, filters }];
  }
  // Plain text: also the rules, the checklists and the standards (their pages search it)
  const references: SearchTarget[] =
    plain && text
      ? [
          { kind: 'rules', search: text },
          { kind: 'checklists', search: text },
          { kind: 'standards', search: text },
        ]
      : [];
  return [{ kind: 'findings', text, filters }, { kind: 'reports', text, filters }, ...references];
}

/**
 * ``#report:<number>`` or ``#R<number>`` typed in the search of a list of findings, anywhere: the
 * number of that report and the rest of the text (``xss #R12``: "xss" in report 12). Without it,
 * or with another value, the whole text is searched (``#F12`` alone: finding 12, by the server).
 */
export function reportSearch(raw: string): { reportId?: number; text: string } {
  let reportId: number | undefined;
  const words: string[] = [];
  for (const word of raw.trim().split(/\s+/).filter(Boolean)) {
    const prefixed = QUALIFIER.exec(expand(word));
    const id = prefixed?.[1].toLowerCase() === 'report' ? ID.exec(prefixed[2]) : null;
    if (id && reportId === undefined) {
      reportId = Number(id[1]);
    } else {
      words.push(word);
    }
  }
  return { reportId, text: words.join(' ') };
}

/**
 * Projects whose name contains the query (text only), at most three: the exact name first.
 * Each one can be opened, or give its findings or its reports.
 */
export function projectTargets(raw: string, projects: readonly string[]): SearchTarget[] {
  const { plain, text } = parse(raw);
  const query = text.toLowerCase();
  if (!plain || !query) {
    return [];
  }
  return projects
    .filter((name) => name.toLowerCase().includes(query))
    .sort((a, b) => Number(b.toLowerCase() === query) - Number(a.toLowerCase() === query))
    .slice(0, MAX_PROJECTS)
    .flatMap((name): SearchTarget[] => [
      { kind: 'project', name },
      { kind: 'projectFindings', name },
      { kind: 'projectReports', name },
    ]);
}

/** True when the query is exactly the name of one of the projects (it then comes first). */
export function isProjectName(raw: string, projects: readonly string[]): boolean {
  const query = raw.trim().toLowerCase();
  return projects.some((name) => name.toLowerCase() === query);
}
