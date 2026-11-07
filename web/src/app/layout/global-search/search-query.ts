/** Longest text sent to the search of the findings or of the reports (the API refuses more). */
export const MAX_SEARCH_CHARS = 200;

/** What a search of the top bar can open. */
export type SearchTarget =
  /** The page of one report. */
  | { kind: 'report'; id: number }
  /** The report holding one finding, scrolled to it. */
  | { kind: 'finding'; id: number }
  /** The list of the reports, searched for ``text`` ('': every report). */
  | { kind: 'reports'; text: string }
  /** The list of the findings, searched for ``text`` ('': every finding). */
  | { kind: 'findings'; text: string };

/** ``#report:<value>`` or ``#finding:<value>`` (case-insensitive, spaces allowed after ``:``). */
const PREFIXED = /^#(report|finding)s?:\s*(.*)$/i;

/** A number of a report or a finding (no sign, no decimals, within the safe integers). */
const ID = /^#?(\d{1,15})$/;

/**
 * Targets of what the user typed, the first one opened by Enter:
 * - ``#report:<number>`` / ``#finding:<number>``: that report or finding;
 * - ``#report:*`` / ``#finding:*`` (or nothing after ``:``): every report or finding;
 * - ``#report:<text>`` / ``#finding:<text>``: the reports or the findings containing the text;
 * - ``*``: every finding, then every report;
 * - any other text: the findings, then the reports containing it.
 */
export function parseSearch(raw: string): SearchTarget[] {
  const query = raw.trim();
  if (!query) {
    return [];
  }
  const prefixed = PREFIXED.exec(query);
  if (prefixed) {
    const scope = prefixed[1].toLowerCase() === 'report' ? 'report' : 'finding';
    const value = prefixed[2].trim();
    const id = ID.exec(value);
    if (id) {
      return [{ kind: scope, id: Number(id[1]) }];
    }
    const text = value === '*' ? '' : value.slice(0, MAX_SEARCH_CHARS);
    return [{ kind: scope === 'report' ? 'reports' : 'findings', text }];
  }
  const text = query === '*' ? '' : query.slice(0, MAX_SEARCH_CHARS);
  return [
    { kind: 'findings', text },
    { kind: 'reports', text },
  ];
}
