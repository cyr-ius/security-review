import {
  Component,
  DestroyRef,
  ElementRef,
  computed,
  inject,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** Largest height of the menu, in rem (it scrolls beyond). */
const MENU_MAX_HEIGHT_REM = 20;
/** Space kept between the menu and the edge of the window, in pixels. */
const VIEWPORT_MARGIN_PX = 8;

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
  /**
   * Fixed position of the menu, computed from the button: an absolute menu would be cut by a
   * scrolling container (a table, a list of limited height).
   */
  readonly menuStyle = signal<Record<string, string>>({});

  private readonly button = viewChild.required<ElementRef<HTMLButtonElement>>('button');
  private readonly menu = viewChild<ElementRef<HTMLElement>>('menu');

  constructor() {
    // A scroll does not bubble: listen in the capture phase to follow any scrolling container.
    const onScroll = (event: Event): void => {
      if (this.open() && !this.menu()?.nativeElement.contains(event.target as Node)) {
        this.position();
      }
    };
    const onResize = (): void => {
      if (this.open()) {
        this.position();
      }
    };
    document.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onResize);
    inject(DestroyRef).onDestroy(() => {
      document.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onResize);
    });
  }

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

  toggleOpen(): void {
    if (this.open()) {
      this.close();
      return;
    }
    this.position();
    this.open.set(true);
  }

  /** Place the menu under the button, or above it when the window lacks room below. */
  private position(): void {
    const rect = this.button().nativeElement.getBoundingClientRect();
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
    const wanted = MENU_MAX_HEIGHT_REM * rem;
    const below = window.innerHeight - rect.bottom - VIEWPORT_MARGIN_PX;
    const above = rect.top - VIEWPORT_MARGIN_PX;
    const upward = below < wanted && above > below;
    const style: Record<string, string> = {
      position: 'fixed',
      left: `${rect.left}px`,
      'min-width': `${rect.width}px`,
      'max-height': `${Math.max(Math.min(wanted, upward ? above : below), 0)}px`,
    };
    if (upward) {
      style['bottom'] = `${window.innerHeight - rect.top}px`;
    } else {
      style['top'] = `${rect.bottom}px`;
    }
    this.menuStyle.set(style);
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
