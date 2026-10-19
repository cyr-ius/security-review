import { Component, input, output } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

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

/** Search and filter controls shared by collection tables (columns sort: SortHeaderComponent). */
@Component({
  selector: 'app-table-controls',
  imports: [TranslatePipe],
  templateUrl: './table-controls.component.html',
  styleUrl: './table-controls.component.css',
})
export class TableControlsComponent {
  readonly idPrefix = input.required<string>();
  readonly search = input('');
  readonly filters = input<TableControlFilter[]>([]);

  readonly searchChange = output<string>();
  readonly filterChange = output<TableControlFilterChange>();

  onSearch(event: Event): void {
    this.searchChange.emit((event.target as HTMLInputElement).value);
  }

  onFilter(key: string, event: Event): void {
    this.filterChange.emit({ key, value: (event.target as HTMLSelectElement).value });
  }
}
