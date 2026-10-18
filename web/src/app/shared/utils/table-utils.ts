export type TableSortDirection = 'asc' | 'desc';

/** Filter rows by searchable text, then sort a copy without mutating the source collection. */
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
