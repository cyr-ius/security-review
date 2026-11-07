import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  DestroyRef,
  ElementRef,
  computed,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Params, Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { MessageParams } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge.component';
import {
  MAX_SEARCH_CHARS,
  SearchFilters,
  SearchTarget,
  isProjectName,
  parseSearch,
  projectTargets,
} from './search-query';
import {
  Suggestion,
  SuggestionSection,
  describe,
  foundFinding,
  foundReport,
} from './search-suggestions';

/** Pause after the last key stroke before the findings and reports found are loaded. */
const PREVIEW_DELAY_MS = 300;

/** Findings and reports shown under the field for a search. */
const PREVIEW_FINDINGS = 5;
const PREVIEW_REPORTS = 3;

/** Title of each group of the list (the actions have none). */
const SECTION_TITLES: Record<SuggestionSection, MessageKey | null> = {
  actions: null,
  findings: 'layout.findings',
  reports: 'layout.reports',
};

/** Syntax reminded while the field is empty. */
const SYNTAX: readonly { example: string; label: MessageKey }[] = [
  { example: 'sql injection', label: 'layout.searchHelpText' },
  { example: '#report:12', label: 'layout.searchHelpReport' },
  { example: 'toto #report:12', label: 'layout.searchHelpInReport' },
  { example: '#finding:34', label: 'layout.searchHelpFinding' },
  { example: '#report:*', label: 'layout.searchHelpAll' },
  { example: 'project:shop sev:high,critical', label: 'layout.searchHelpFilters' },
  { example: 'status:accepted', label: 'layout.searchHelpStatus' },
];

/**
 * Search field of the top bar: plain text searches the findings and the reports (the first ones
 * found are listed under the field) and offers the projects whose name contains it,
 * ``#report:<n>`` and ``#finding:<n>`` open one of them (``toto #report:<n>`` searches the
 * report), ``project:``, ``severity:`` and ``status:`` filter, ``*`` lists them all. Ctrl+K (⌘K)
 * focuses it.
 */
@Component({
  selector: 'app-global-search',
  imports: [DatePipe, SeverityBadgeComponent, TranslatePipe],
  templateUrl: './global-search.component.html',
  styleUrl: './global-search.component.css',
  host: { '(document:keydown)': 'onShortcut($event)' },
})
export class GlobalSearchComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  private readonly field = viewChild.required<ElementRef<HTMLInputElement>>('field');

  readonly maxLength = MAX_SEARCH_CHARS + 100;
  readonly syntax = SYNTAX;
  readonly sectionTitles = SECTION_TITLES;

  readonly query = signal('');
  /** The query once typing pauses: the findings and reports found are loaded for it. */
  private readonly settled = signal('');
  private previewTimer?: ReturnType<typeof setTimeout>;

  readonly open = signal(false);
  private readonly activeIndex = signal(0);
  /** Error of the last opened target (finding not found...). */
  readonly error = signal<{ label: MessageKey; params: MessageParams } | null>(null);
  readonly busy = signal(false);

  /** Set once the field gets the focus: the projects are loaded then, not with every page. */
  private readonly wanted = signal(false);

  /** Names of the projects the user sees, offered when the text is in one of them. */
  private readonly projects = rxResource({
    params: () => (this.wanted() ? true : undefined),
    stream: () => this.api.projects(),
  });
  private readonly projectNames = computed(() =>
    (this.projects.value() ?? []).map((project) => project.project),
  );

  /** Targets of the typed text the user may open (the findings list needs reports.read). */
  private readonly targets = computed<SearchTarget[]>(() => {
    const query = this.query();
    const names = this.projectNames();
    const searches = parseSearch(query);
    const projects = projectTargets(query, names);
    // A project typed in full comes first: Enter opens it
    const targets = isProjectName(query, names)
      ? [...projects, ...searches]
      : [...searches, ...projects];
    return targets.filter((target) => target.kind !== 'findings' || this.auth.can('reports.read'));
  });

  /** Searches of the settled query whose first results are listed. */
  private readonly previewed = computed(() => {
    const targets = this.open() ? parseSearch(this.settled()) : [];
    return {
      findings: this.auth.can('reports.read')
        ? targets.find((target) => target.kind === 'findings')
        : undefined,
      reports: targets.find((target) => target.kind === 'reports'),
    };
  });

  /** First findings found (open ones unless a status is typed), worst first. */
  private readonly foundFindings = rxResource({
    params: () => {
      const target = this.previewed().findings;
      return target && { text: target.text, filters: target.filters };
    },
    stream: ({ params }) =>
      this.api.projectFindings({
        project: params.filters.project,
        status: params.filters.status.length ? params.filters.status : ['open'],
        severity: params.filters.severity,
        reviewType: [],
        search: params.text || undefined,
        limit: PREVIEW_FINDINGS,
        offset: 0,
      }),
  });

  /** Latest reports found. */
  private readonly foundReports = rxResource({
    params: () => {
      const target = this.previewed().reports;
      return target && { text: target.text, filters: target.filters };
    },
    stream: ({ params }) =>
      this.api.reports({
        project: params.filters.project ? [params.filters.project] : [],
        risk_level: params.filters.severity,
        search: params.text || undefined,
        limit: PREVIEW_REPORTS,
        offset: 0,
      }),
  });

  readonly loading = computed(
    () => this.busy() || this.foundFindings.isLoading() || this.foundReports.isLoading(),
  );

  /** Entries of the list: what to open, then the findings and the reports found. */
  readonly suggestions = computed<Suggestion[]>(() => {
    // Results of an older query are not shown with the new one
    const current = this.query() === this.settled();
    const findings = current && this.foundFindings.hasValue() ? this.foundFindings.value() : null;
    const reports = current && this.foundReports.hasValue() ? this.foundReports.value() : [];
    return [
      ...this.targets().map((target) =>
        describe(target, target.kind === 'findings' ? findings?.total : undefined),
      ),
      ...(findings?.findings ?? []).map(foundFinding),
      ...reports.map(foundReport),
    ];
  });

  /** The entries by group, each with its place in the whole list (keyboard selection). */
  readonly groups = computed(() => {
    const entries = this.suggestions().map((suggestion, index) => ({ suggestion, index }));
    return (['actions', 'findings', 'reports'] as const)
      .map((section) => ({
        section,
        entries: entries.filter((entry) => entry.suggestion.section === section),
      }))
      .filter((group) => group.entries.length);
  });

  /** Entry selected with the arrows (kept within the list when it shrinks). */
  readonly active = computed(() =>
    Math.min(this.activeIndex(), Math.max(this.suggestions().length - 1, 0)),
  );

  constructor() {
    inject(DestroyRef).onDestroy(() => clearTimeout(this.previewTimer));
  }

  onFocus(): void {
    this.wanted.set(true);
    this.open.set(true);
  }

  /** Close the list when the focus leaves the field and its list. */
  onFocusOut(event: FocusEvent): void {
    const next = event.relatedTarget as Node | null;
    if (!next || !(event.currentTarget as HTMLElement).contains(next)) {
      this.open.set(false);
    }
  }

  onInput(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.query.set(value);
    this.activeIndex.set(0);
    this.error.set(null);
    this.open.set(true);
    clearTimeout(this.previewTimer);
    this.previewTimer = setTimeout(() => this.settled.set(value), PREVIEW_DELAY_MS);
  }

  select(index: number): void {
    this.activeIndex.set(index);
  }

  onKeydown(event: KeyboardEvent): void {
    const count = this.suggestions().length;
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        this.open.set(true);
        this.activeIndex.set(count ? (this.active() + 1) % count : 0);
        break;
      case 'ArrowUp':
        event.preventDefault();
        this.activeIndex.set(count ? (this.active() - 1 + count) % count : 0);
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
      this.onFocus();
    }
  }

  /** Open a target; the list closes once the page is shown. */
  async go(target: SearchTarget): Promise<void> {
    this.error.set(null);
    switch (target.kind) {
      case 'report':
        await this.router.navigate(['/reports', target.id], {
          queryParams: target.text ? { search: target.text } : {},
        });
        break;
      case 'reports':
        await this.router.navigate(['/reports'], {
          queryParams: reportParams(target.text, target.filters),
        });
        break;
      case 'findings':
        await this.router.navigate(
          target.filters.project
            ? ['/projects', target.filters.project, 'findings']
            : ['/findings'],
          { queryParams: findingParams(target.text, target.filters) },
        );
        break;
      case 'project':
        await this.router.navigate(['/projects', target.name]);
        break;
      case 'projectFindings':
        await this.router.navigate(['/projects', target.name, 'findings']);
        break;
      case 'projectReports':
        await this.router.navigate(['/reports'], { queryParams: { project: target.name } });
        break;
      case 'finding':
        if (!(await this.openFinding(target.id, target.reportId))) {
          return;
        }
        break;
    }
    this.open.set(false);
    this.field().nativeElement.blur();
  }

  /** Open the report of a finding at its card; false when it cannot be shown. */
  private async openFinding(id: number, reportId?: number): Promise<boolean> {
    this.busy.set(true);
    try {
      const report = reportId ?? (await firstValueFrom(this.api.projectFinding(id))).report_id;
      await this.router.navigate(['/reports', report], { fragment: `finding-${id}` });
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

/** Query parameters of the findings page for a search (empty values left out). */
function findingParams(text: string, filters: SearchFilters): Params {
  return {
    search: text || undefined,
    status: filters.status.length ? filters.status : undefined,
    severity: filters.severity.length ? filters.severity : undefined,
  };
}

/** Query parameters of the reports page for a search (empty values left out). */
function reportParams(text: string, filters: SearchFilters): Params {
  return {
    search: text || undefined,
    project: filters.project,
    risk: filters.severity.length ? filters.severity : undefined,
  };
}
