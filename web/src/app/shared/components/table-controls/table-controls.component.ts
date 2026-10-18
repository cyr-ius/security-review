import { Component, input, output } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

export type TableSortDirection = 'asc' | 'desc';

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

/** Search, sort and filter controls shared by collection tables. */
@Component({
  selector: 'app-table-controls',
  imports: [TranslatePipe],
  templateUrl: './table-controls.component.html',
  styleUrl: './table-controls.component.css',
})
export class TableControlsComponent {
  readonly idPrefix = input.required<string>();
  readonly search = input('');
  readonly sort = input('');
  readonly direction = input<TableSortDirection>('asc');
  readonly sortOptions = input<TableControlOption[]>([]);
  readonly filters = input<TableControlFilter[]>([]);

  readonly searchChange = output<string>();
  readonly sortChange = output<string>();
  readonly directionChange = output<TableSortDirection>();
  readonly filterChange = output<TableControlFilterChange>();

  onSearch(event: Event): void {
    this.searchChange.emit((event.target as HTMLInputElement).value);
  }

  onSort(event: Event): void {
    this.sortChange.emit((event.target as HTMLSelectElement).value);
  }

  onFilter(key: string, event: Event): void {
    this.filterChange.emit({ key, value: (event.target as HTMLSelectElement).value });
  }

  toggleDirection(): void {
    this.directionChange.emit(this.direction() === 'asc' ? 'desc' : 'asc');
  }
}
