import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { MessageKey } from '../../core/i18n/messages';
import { MessageParams } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { MAX_SEARCH_CHARS, SearchTarget, parseSearch } from './search-query';

/** One entry of the list under the field. */
interface Suggestion {
  target: SearchTarget;
  icon: string;
  label: MessageKey;
  params: MessageParams;
}

/** Syntax reminded while the field is empty. */
const SYNTAX: readonly { example: string; label: MessageKey }[] = [
  { example: 'sql injection', label: 'layout.searchHelpText' },
  { example: '#report:12', label: 'layout.searchHelpReport' },
  { example: '#finding:34', label: 'layout.searchHelpFinding' },
  { example: '#report:*', label: 'layout.searchHelpAll' },
];

/**
 * Search field of the top bar: plain text searches the findings and the reports, ``#report:<n>``
 * and ``#finding:<n>`` open one of them, ``*`` lists them all. Ctrl+K (⌘K) focuses it.
 */
@Component({
  selector: 'app-global-search',
  imports: [TranslatePipe],
  templateUrl: './global-search.component.html',
  styleUrl: './global-search.component.css',
  host: { '(document:keydown)': 'onShortcut($event)' },
})
export class GlobalSearchComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  private readonly field = viewChild.required<ElementRef<HTMLInputElement>>('field');

  readonly maxLength = MAX_SEARCH_CHARS + 20;
  readonly syntax = SYNTAX;

  readonly query = signal('');
  readonly open = signal(false);
  readonly active = signal(0);
  /** Error of the last opened target (finding not found...). */
  readonly error = signal<{ label: MessageKey; params: MessageParams } | null>(null);
  readonly busy = signal(false);

  /** Targets of the typed text the user may open (the findings list needs reports.read). */
  readonly suggestions = computed<Suggestion[]>(() =>
    parseSearch(this.query())
      .filter((target) => target.kind !== 'findings' || this.auth.can('reports.read'))
      .map(describe),
  );

  /** Close the list when the focus leaves the field and its list. */
  onFocusOut(event: FocusEvent): void {
    const next = event.relatedTarget as Node | null;
    if (!next || !(event.currentTarget as HTMLElement).contains(next)) {
      this.open.set(false);
    }
  }

  onInput(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
    this.active.set(0);
    this.error.set(null);
    this.open.set(true);
  }

  onKeydown(event: KeyboardEvent): void {
    const count = this.suggestions().length;
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        this.open.set(true);
        this.active.update((index) => (count ? (index + 1) % count : 0));
        break;
      case 'ArrowUp':
        event.preventDefault();
        this.active.update((index) => (count ? (index - 1 + count) % count : 0));
        break;
      case 'Enter': {
        event.preventDefault();
        const chosen = this.suggestions()[this.active()];
        if (chosen) {
          void this.go(chosen.target);
        }
        break;
      }
      case 'Escape':
        if (this.open()) {
          // The layout closes its menu on Escape too: the list closes first
          event.stopPropagation();
          this.open.set(false);
        }
        break;
    }
  }

  /** Ctrl+K or ⌘K focuses the field, wherever the focus is. */
  onShortcut(event: KeyboardEvent): void {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      this.field().nativeElement.focus();
      this.field().nativeElement.select();
      this.open.set(true);
    }
  }

  /** Open a target; the list closes once the page is shown. */
  async go(target: SearchTarget): Promise<void> {
    this.error.set(null);
    switch (target.kind) {
      case 'report':
        await this.router.navigate(['/reports', target.id]);
        break;
      case 'reports':
        await this.router.navigate(['/reports'], {
          queryParams: target.text ? { search: target.text } : {},
        });
        break;
      case 'findings':
        await this.router.navigate(['/findings'], {
          queryParams: target.text ? { search: target.text } : {},
        });
        break;
      case 'finding':
        if (!(await this.openFinding(target.id))) {
          return;
        }
        break;
    }
    this.open.set(false);
    this.field().nativeElement.blur();
  }

  /** Open the report of a finding at its card; false when it cannot be shown. */
  private async openFinding(id: number): Promise<boolean> {
    this.busy.set(true);
    try {
      const finding = await firstValueFrom(this.api.projectFinding(id));
      await this.router.navigate(['/reports', finding.report_id], {
        fragment: `finding-${finding.id}`,
      });
      return true;
    } catch (error) {
      const missing = error instanceof HttpErrorResponse && error.status === 404;
      this.error.set({
        label: missing ? 'layout.searchFindingNotFound' : 'layout.searchError',
        params: { id },
      });
      this.open.set(true);
      return false;
    } finally {
      this.busy.set(false);
    }
  }
}

/** Icon and label of a target. */
function describe(target: SearchTarget): Suggestion {
  switch (target.kind) {
    case 'report':
      return {
        target,
        icon: 'bi-file-earmark-text',
        label: 'layout.searchOpenReport',
        params: { id: target.id },
      };
    case 'finding':
      return {
        target,
        icon: 'bi-bug',
        label: 'layout.searchOpenFinding',
        params: { id: target.id },
      };
    case 'reports':
      return {
        target,
        icon: 'bi-files',
        label: target.text ? 'layout.searchReports' : 'layout.searchAllReports',
        params: { text: target.text },
      };
    case 'findings':
      return {
        target,
        icon: 'bi-shield-check',
        label: target.text ? 'layout.searchFindings' : 'layout.searchAllFindings',
        params: { text: target.text },
      };
  }
}
