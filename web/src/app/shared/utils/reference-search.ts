import { ChecklistItem, CustomRule } from '../../core/models/api.models';
import { idSearch } from './table-utils';

/** Text of a rule searched by the Rules page and by the global search. */
export function ruleSearchText(rule: CustomRule): string {
  return [rule.id, rule.title, rule.cwe, rule.languages.join(' '), rule.pattern, rule.advice].join(
    ' ',
  );
}

/** Text of a checklist item searched by the Checklists page and by the global search. */
export function checklistSearchText(item: ChecklistItem): string {
  return [item.domain, item.id, item.title, item.what_to_look_for, item.cwe].join(' ');
}

/**
 * Whether a rule or a checklist item matches a search: ``#PY-004`` / ``#AI*`` its id (or the ids
 * starting so), else the text, case-insensitive; an empty search matches everything.
 */
export function referenceMatches(id: string, text: string, query: string): boolean {
  const byId = idSearch(query);
  if (byId) {
    return byId(id);
  }
  const normalized = query.trim().toLocaleLowerCase();
  return !normalized || text.toLocaleLowerCase().includes(normalized);
}
