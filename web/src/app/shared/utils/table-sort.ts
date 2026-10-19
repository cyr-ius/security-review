import { Signal, computed, signal } from '@angular/core';
import { TableSortDirection } from './table-utils';

/** Prefix of the browser storage keys that remember the sort of each table. */
const STORAGE_PREFIX = 'secreview.sort.';

/** Column and direction a table is sorted by. */
export interface TableSortState<K extends string> {
  key: K;
  direction: TableSortDirection;
}

/**
 * Sort of a table, chosen by clicking its column headers and remembered by the browser.
 *
 * Clicking the sorted column reverses the direction; clicking another column sorts it
 * ascending. The state is stored under `secreview.sort.<id>` and read back on the next
 * visit; an unknown column or direction falls back to the default.
 */
export class TableSort<K extends string> {
  private readonly state;
  readonly key: Signal<K>;
  readonly direction: Signal<TableSortDirection>;

  constructor(
    readonly id: string,
    readonly keys: readonly K[],
    defaultKey: K,
    defaultDirection: TableSortDirection,
    /** Called after a click changed the sort (a paginated list goes back to its first page). */
    private readonly changed?: () => void,
  ) {
    this.state = signal<TableSortState<K>>(
      this.stored() ?? { key: defaultKey, direction: defaultDirection },
    );
    this.key = computed(() => this.state().key);
    this.direction = computed(() => this.state().direction);
  }

  /** Whether the table can be sorted by this column. */
  has(key: string): key is K {
    return (this.keys as readonly string[]).includes(key);
  }

  /** Sort by a column: reverse the direction if it is already the sorted one. */
  toggle(key: K): void {
    if (!this.has(key)) {
      return;
    }
    const current = this.state();
    const direction: TableSortDirection =
      current.key === key && current.direction === 'asc' ? 'desc' : 'asc';
    this.state.set({ key, direction });
    try {
      localStorage.setItem(STORAGE_PREFIX + this.id, JSON.stringify(this.state()));
    } catch {
      // Not remembered by the browser
    }
    this.changed?.();
  }

  /** Sort remembered by the browser, if it is still valid. */
  private stored(): TableSortState<K> | null {
    try {
      const value: unknown = JSON.parse(localStorage.getItem(STORAGE_PREFIX + this.id) ?? 'null');
      if (typeof value !== 'object' || value === null) {
        return null;
      }
      const { key, direction } = value as Record<string, unknown>;
      return typeof key === 'string' &&
        this.has(key) &&
        (direction === 'asc' || direction === 'desc')
        ? { key, direction }
        : null;
    } catch {
      return null;
    }
  }
}
