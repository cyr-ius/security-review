import { Severity } from '../../core/models/api.models';

/** Severity of the findings of an OpenGrep rule, as engines/opengrep.py maps it. */
const SEVERITY_OF: Record<string, Severity> = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };

/** Longest message kept for the table (the editor shows the whole file). */
const MAX_MESSAGE_CHARS = 300;

/** What the table shows of a rule file: read from its first rule, for display only. */
export interface OpenGrepRuleSummary {
  languages: string[];
  /** Severity of its findings; null when the file does not say. */
  severity: Severity | null;
  message: string;
  cwe: string;
}

/** A line holding a key. */
interface KeyLine {
  /** Column of the key itself (after the indent and the "- " of a list item). */
  column: number;
  /** Text after ``key:``. */
  value: string;
  /** Index of the end of the line in the file. */
  end: number;
}

/**
 * Reads the languages, the severity, the message and the CWE of the first rule of a YAML file
 * (no YAML parser in the interface): enough for the usual layout of the rules, and an empty value
 * for a field written otherwise. OpenGrep, not this function, checks the file. Every pattern here
 * runs in linear time, whatever the file (up to 256 KiB).
 */
export function summarizeRule(content: string): OpenGrepRuleSummary {
  const severity = unquote(findKey(content, 'severity')?.value ?? '').toUpperCase();
  return {
    languages: languagesOf(content),
    severity: SEVERITY_OF[severity] ?? null,
    message: messageOf(content),
    cwe: /\bCWE-\d+/i.exec(content)?.[0].toUpperCase() ?? '',
  };
}

/** First line where ``key:`` starts the line, or follows the "- " of a list item. */
function findKey(content: string, key: string): KeyLine | null {
  // Blanks, then an optional "-" followed by at least one blank: no two quantifiers compete
  const match = new RegExp(`^([ \\t]*(?:-[ \\t]+)?)${key}:(.*)$`, 'm').exec(content);
  if (!match) {
    return null;
  }
  return { column: match[1].length, value: match[2].trim(), end: match.index + match[0].length };
}

/** The lines after a key that belong to its value: indented more than the key. */
function valueLines(content: string, key: KeyLine, sequence = false): string[] {
  const lines: string[] = [];
  for (const line of content.slice(key.end + 1).split('\n')) {
    const indent = line.length - line.trimStart().length;
    // A block sequence may also start at the column of its key ("- item")
    const inside =
      indent > key.column ||
      (sequence && indent === key.column && line.trimStart().startsWith('-'));
    if (line.trim() && !inside) {
      break;
    }
    lines.push(line);
  }
  return lines;
}

function unquote(value: string): string {
  const text = value.trim();
  const quote = text[0];
  return (quote === '"' || quote === "'") && text.length > 1 && text.endsWith(quote)
    ? text.slice(1, -1)
    : text;
}

/** ``languages: [a, b]``, or a block list of "- a" lines under ``languages:``. */
function languagesOf(content: string): string[] {
  const key = findKey(content, 'languages');
  if (!key) {
    return [];
  }
  if (key.value.startsWith('[')) {
    return key.value.replace(/[[\]]/g, '').split(',').map(unquote).filter(Boolean);
  }
  return valueLines(content, key, true)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('-'))
    .map((line) => unquote(line.slice(1)))
    .filter(Boolean);
}

/** ``message:`` on one line, or a folded / literal block (``>-``, ``|``) joined into one line. */
function messageOf(content: string): string {
  const key = findKey(content, 'message');
  if (!key) {
    return '';
  }
  let text = key.value;
  if (/^[>|][-+]?$/.test(text)) {
    text = valueLines(content, key)
      .map((line) => line.trim())
      .join(' ');
  }
  text = unquote(text).replace(/\s+/g, ' ').trim();
  return text.length > MAX_MESSAGE_CHARS ? `${text.slice(0, MAX_MESSAGE_CHARS - 1)}…` : text;
}
