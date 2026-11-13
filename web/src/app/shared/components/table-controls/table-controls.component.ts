import { Component, input, output } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { MultiSelectDropdownComponent } from '../multi-select-dropdown/multi-select-dropdown.component';

export interface TableControlOption {
  value: string;
  label: string;
}

/** Filter keeping several values at once (none selected: no filter, ``allLabel``). */
export interface TableControlMultiFilter {
  key: string;
  label: string;
  allLabel: string;
  values: readonly string[];
  options: TableControlOption[];
}

export interface TableControlMultiFilterChange {
  key: string;
  values: string[];
}

/** A filter menu offers a search field only beyond this number of options. */
const FILTER_SEARCH_FROM = 5;

/**
 * Search and filter controls shared by collection tables (columns sort: SortHeaderComponent), on
 * one line: the projected content (count, selection) on the left, the search and the filters on
 * the right. An element marked ``control`` (a filter the page handles itself) follows the search.
 */
@Component({
  selector: 'app-table-controls',
  imports: [MultiSelectDropdownComponent, TranslatePipe],
  templateUrl: './table-controls.component.html',
  styleUrl: './table-controls.component.css',
})
export class TableControlsComponent {
  readonly idPrefix = input.required<string>();
  readonly search = input('');
  /** Placeholder and accessible name of the search field (empty: "Search"). */
  readonly searchPlaceholder = input('');
  readonly multiFilters = input<TableControlMultiFilter[]>([]);
  readonly searchFrom = FILTER_SEARCH_FROM;

  readonly searchChange = output<string>();
  readonly multiFilterChange = output<TableControlMultiFilterChange>();

  onSearch(event: Event): void {
    this.searchChange.emit((event.target as HTMLInputElement).value);
  }

  /** Empty the search and give the focus back to its field. */
  clearSearch(field: HTMLInputElement): void {
    field.value = '';
    this.searchChange.emit('');
    field.focus();
  }
}

/** The known values among those of a filter, in the order of ``known`` (others dropped). */
export function knownValues<T extends string>(values: readonly string[], known: readonly T[]): T[] {
  return known.filter((value) => values.includes(value));
}

/** True when no value is selected (no filter) or when ``value`` is one of them. */
export function matchesFilter<T>(selected: readonly T[], value: T): boolean {
  return selected.length === 0 || selected.includes(value);
}
