import { NgTemplateOutlet } from '@angular/common';
import { Component, computed, input } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { TableSort } from '../../utils/table-sort';

/**
 * Column header that sorts its table when clicked, with an arrow on the sorted column.
 *
 * Use it on a `th`: `<th scope="col" [appSortHeader]="sort" sortKey="name">Name</th>`. A
 * column the table cannot be sorted by stays a plain header.
 */
@Component({
  selector: 'th[appSortHeader]',
  imports: [NgTemplateOutlet, TranslatePipe],
  templateUrl: './sort-header.component.html',
  styleUrl: './sort-header.component.css',
  host: { '[attr.aria-sort]': 'ariaSort()' },
})
export class SortHeaderComponent<K extends string> {
  readonly sort = input.required<TableSort<K>>({ alias: 'appSortHeader' });
  readonly sortKey = input.required<K>();

  readonly sortable = computed(() => this.sort().has(this.sortKey()));
  /** Direction of this column, or null when the table is sorted by another one. */
  readonly active = computed(() =>
    this.sort().key() === this.sortKey() ? this.sort().direction() : null,
  );
  readonly ariaSort = computed(() => {
    const active = this.active();
    if (!this.sortable()) {
      return null;
    }
    return active === 'asc' ? 'ascending' : active === 'desc' ? 'descending' : 'none';
  });

  toggle(): void {
    this.sort().toggle(this.sortKey());
  }
}
