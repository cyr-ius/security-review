export type TableSortDirection = 'asc' | 'desc';

/** Filter rows by searchable text, then sort a copy without mutating the source collection. */
/**
 * ``#PY-004`` (that id) or ``#AI*`` (the ids starting with AI), case-insensitive, typed alone in
 * the search of a list of rules or checklist items; null for a text search.
 */
export function idSearch(query: string): ((id: string) => boolean) | null {
  const found = /^#([A-Za-z][\w.:-]{0,59})(\*?)$/.exec(query.trim());
  if (!found) {
    return null;
  }
  const name = found[1].toUpperCase();
  return found[2] ? (id) => id.toUpperCase().startsWith(name) : (id) => id.toUpperCase() === name;
}

export function filterAndSortRows<T>(
  rows: readonly T[],
  query: string,
  direction: TableSortDirection,
  searchableText: (row: T) => string,
  compare: (left: T, right: T) => number,
): T[] {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  return rows
    .filter(
      (row) =>
        !normalizedQuery || searchableText(row).toLocaleLowerCase().includes(normalizedQuery),
    )
    .sort((left, right) => {
      const result = compare(left, right);
      return direction === 'asc' ? result : -result;
    });
}

/** Compare user-facing strings naturally, ignoring case and accents. */
export function compareTableText(left: string, right: string): number {
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: 'base' });
}
