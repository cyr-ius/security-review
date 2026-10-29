import { Component, ElementRef, computed, inject, input, output, signal } from '@angular/core';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

export interface MultiSelectOption {
  value: string;
  label: string;
}

/**
 * Filter that keeps several values at once: a button showing the selection and a menu of
 * checkboxes. No value selected means no filter (``allLabel``).
 */
@Component({
  selector: 'app-multi-select-dropdown',
  imports: [TranslatePipe],
  templateUrl: './multi-select-dropdown.component.html',
  styleUrl: './multi-select-dropdown.component.css',
  host: {
    '(document:click)': 'onDocumentClick($event)',
    '(keydown.escape)': 'close()',
  },
})
export class MultiSelectDropdownComponent {
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly i18n = inject(I18nService);

  /** Id of the button (a <label for> may target it). */
  readonly id = input.required<string>();
  /** Accessible name of the filter. */
  readonly label = input.required<string>();
  /** Text shown when no value is selected. */
  readonly allLabel = input.required<string>();
  readonly options = input.required<readonly MultiSelectOption[]>();
  readonly selected = input<readonly string[]>([]);

  readonly selectedChange = output<string[]>();

  readonly open = signal(false);

  readonly summary = computed(() => {
    const selected = this.selected();
    if (selected.length === 0) {
      return this.allLabel();
    }
    if (selected.length === 1) {
      return this.options().find((o) => o.value === selected[0])?.label ?? selected[0];
    }
    return this.i18n.translate('common.selectedCount', { count: selected.length });
  });

  isSelected(value: string): boolean {
    return this.selected().includes(value);
  }

  /** Add or remove a value, keeping the order of the options. */
  toggle(value: string): void {
    const selected = new Set(this.selected());
    if (selected.has(value)) {
      selected.delete(value);
    } else {
      selected.add(value);
    }
    this.selectedChange.emit(
      this.options()
        .map((o) => o.value)
        .filter((v) => selected.has(v)),
    );
  }

  clear(): void {
    this.selectedChange.emit([]);
  }

  close(): void {
    this.open.set(false);
  }

  onDocumentClick(event: MouseEvent): void {
    if (this.open() && !this.host.nativeElement.contains(event.target as Node)) {
      this.close();
    }
  }
}
