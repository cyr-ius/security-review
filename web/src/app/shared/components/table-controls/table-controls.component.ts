import { Component, input, output } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { MultiSelectDropdownComponent } from '../multi-select-dropdown/multi-select-dropdown.component';

export interface TableControlOption {
  value: string;
  label: string;
}

export interface TableControlFilter {
  key: string;
  label: string;
  value: string;
  options: TableControlOption[];
}

export interface TableControlFilterChange {
  key: string;
  value: string;
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
  readonly filters = input<TableControlFilter[]>([]);
  readonly multiFilters = input<TableControlMultiFilter[]>([]);

  readonly searchChange = output<string>();
  readonly filterChange = output<TableControlFilterChange>();
  readonly multiFilterChange = output<TableControlMultiFilterChange>();

  onSearch(event: Event): void {
    this.searchChange.emit((event.target as HTMLInputElement).value);
  }

  onFilter(key: string, event: Event): void {
    this.filterChange.emit({ key, value: (event.target as HTMLSelectElement).value });
  }
}
