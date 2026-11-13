import {
  FINDING_STATUSES,
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
  status: FindingStatus[];
}

/** What a search of the top bar can open. */
export type SearchTarget =
  /** The page of one report, its findings searched for ``text`` ('': all of them). */
  | { kind: 'report'; id: number; text: string }
  /** The report holding one finding, scrolled to it (``reportId`` when already known). */
  | { kind: 'finding'; id: number; reportId?: number }
  /** The list of the reports, searched for ``text`` ('': every report). */
  | { kind: 'reports'; text: string; filters: SearchFilters }
  /** The list of the findings, searched for ``text`` ('': every finding). */
  | { kind: 'findings'; text: string; filters: SearchFilters }
  /** The page of a project. */
  | { kind: 'project'; name: string }
  /** The findings of a project. */
  | { kind: 'projectFindings'; name: string }
  /** The reports of a project. */
  | { kind: 'projectReports'; name: string };

/** ``#report:<value>`` or ``#finding:<value>`` (case-insensitive). */
const QUALIFIER = /^#(report|finding)s?:(.*)$/i;

/** ``project:``, ``severity:`` (``sev:``), ``status:``, ``rule:`` or ``cwe:`` and its value. */
const FILTER = /^(project|severity|sev|status|rule|cwe):(.+)$/i;

/** A number of a report or a finding (no sign, no decimals, within the safe integers). */
const ID = /^#?(\d{1,15})$/;

/** What the user typed, split into its parts. */
interface ParsedSearch {
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
  for (const word of raw.trim().split(/\s+/).filter(Boolean)) {
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
      const statuses = values(value, FINDING_STATUSES);
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
  return { qualifier, filters, text, plain };
}

/**
 * Targets of what the user typed, the first one opened by Enter. One qualifier, anywhere:
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
  const { qualifier, filters, text } = parse(raw);
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
  return [
    { kind: 'findings', text, filters },
    { kind: 'reports', text, filters },
  ];
}

/**
 * ``#report:<number>`` typed in the search of a list of findings, anywhere: the number of that
 * report and the rest of the text (``xss #report:12``: "xss" in report 12). Without it, or
 * with another value, the whole text is searched.
 */
export function reportSearch(raw: string): { reportId?: number; text: string } {
  let reportId: number | undefined;
  const words: string[] = [];
  for (const word of raw.trim().split(/\s+/).filter(Boolean)) {
    const prefixed = QUALIFIER.exec(word);
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
