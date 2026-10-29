import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import {
  Finding,
  RiskAcceptance,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { SortHeaderComponent } from '../../../shared/components/sort-header/sort-header.component';
import {
  TableControlMultiFilter,
  TableControlMultiFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { TableSort } from '../../../shared/utils/table-sort';
import { filterAndSortRows } from '../../../shared/utils/table-utils';
import { RiskAcceptanceDetailComponent } from '../risk-acceptance-detail/risk-acceptance-detail.component';

/** Acceptances loaded per request (the server caps it with SECREVIEW_MAX_LIST_LIMIT). */
const PAGE_SIZE = 100;

type SortKey = 'severity' | 'title' | 'project' | 'approver' | 'accepted' | 'expires' | 'comments';
type AcceptanceState = 'active' | 'expired';
const STATES: readonly AcceptanceState[] = ['active', 'expired'];

/**
 * Every risk acceptance of a project (or of every project, at /risk-acceptances), expired ones
 * included: a triager reads and adds comments, changes the expiry date or removes the
 * acceptance in the details of a row.
 */
@Component({
  selector: 'app-risk-acceptance-list',
  imports: [
    HelpLinkComponent,
    DatePipe,
    RouterLink,
    RefreshButtonComponent,
    RiskAcceptanceDetailComponent,
    SeverityBadgeComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './risk-acceptance-list.component.html',
  styleUrl: './risk-acceptance-list.component.css',
})
export class RiskAcceptanceListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  readonly auth = inject(AuthService);

  /** Route parameter :project (undefined at /risk-acceptances: every project in the scope). */
  readonly project = input<string>();

  readonly severityMeta = SEVERITY_META;

  readonly firstPage = rxResource({
    params: () => ({ project: this.project(), limit: PAGE_SIZE, offset: 0 }),
    stream: ({ params }) => this.api.riskAcceptances(params),
  });

  /** Loaded acceptances: the first page, then the pages added by "load more" and the changes. */
  readonly acceptances = linkedSignal<RiskAcceptance[]>(
    () => this.firstPage.value()?.acceptances ?? [],
  );
  readonly total = computed(() => this.firstPage.value()?.total ?? 0);
  /** Acceptances removed on this page (they left the list on the server). */
  readonly removedCount = signal(0);
  readonly hasMore = computed(() => this.acceptances().length + this.removedCount() < this.total());
  readonly loadingMore = signal(false);
  readonly loadMoreFailed = signal(false);
  readonly notice = signal<Message | null>(null);

  /** Id of the acceptance whose details are open. */
  readonly selectedId = signal<number | null>(null);

  readonly forbidden = computed(() => {
    const error = this.firstPage.error();
    return error instanceof HttpErrorResponse && error.status === 404;
  });

  readonly search = signal('');
  readonly stateFilter = signal<AcceptanceState[]>([]);
  readonly severityFilter = signal<Severity[]>([]);
  readonly sort = new TableSort<SortKey>(
    'risk-acceptances',
    ['severity', 'title', 'project', 'approver', 'accepted', 'expires', 'comments'],
    'expires',
    'asc',
  );
  readonly filters = computed<TableControlMultiFilter[]>(() => [
    {
      key: 'state',
      label: this.i18n.translate('acceptances.state'),
      allLabel: this.i18n.translate('common.all'),
      values: this.stateFilter(),
      options: [
        { value: 'active', label: this.i18n.translate('acceptances.active') },
        { value: 'expired', label: this.i18n.translate('acceptances.expired') },
      ],
    },
    {
      key: 'severity',
      label: this.i18n.translate('report.filterSeverity'),
      allLabel: this.i18n.translate('report.allSeverities'),
      values: this.severityFilter(),
      options: SEVERITIES.map((severity) => ({
        value: severity,
        label: this.i18n.translate(SEVERITY_META[severity].label),
      })),
    },
  ]);

  readonly visible = computed(() => {
    const states = this.stateFilter();
    const severities = this.severityFilter();
    const rows = this.acceptances().filter(
      (row) =>
        (!states.length || states.includes(row.expired ? 'expired' : 'active')) &&
        (!severities.length || severities.includes(row.severity)),
    );
    const key = this.sort.key();
    return filterAndSortRows(
      rows,
      this.search(),
      this.sort.direction(),
      (row) =>
        [row.title, row.project, row.rule_id, row.file_path, row.status_approver, row.status_reason]
          .filter(Boolean)
          .join(' '),
      (a, b) => compare(a, b, key),
    );
  });

  onFilter(change: TableControlMultiFilterChange): void {
    if (change.key === 'state') {
      this.stateFilter.set(STATES.filter((state) => change.values.includes(state)));
    } else if (change.key === 'severity') {
      this.severityFilter.set(SEVERITIES.filter((severity) => change.values.includes(severity)));
    }
  }

  refresh(): void {
    this.notice.set(null);
    this.removedCount.set(0);
    this.firstPage.reload();
  }

  toggle(id: number): void {
    this.selectedId.update((current) => (current === id ? null : id));
  }

  /** Append the next page to the list. */
  async loadMore(): Promise<void> {
    this.loadingMore.set(true);
    this.loadMoreFailed.set(false);
    try {
      const page = await firstValueFrom(
        this.api.riskAcceptances({
          project: this.project(),
          limit: PAGE_SIZE,
          // Removed acceptances left the list on the server
          offset: this.acceptances().length + this.removedCount(),
        }),
      );
      const known = new Set(this.acceptances().map((row) => row.id));
      this.acceptances.update((all) => [
        ...all,
        ...page.acceptances.filter((row) => !known.has(row.id)),
      ]);
    } catch {
      this.loadMoreFailed.set(true);
    } finally {
      this.loadingMore.set(false);
    }
  }

  /** Keep the new expiry date of an acceptance. */
  onChanged(updated: Finding): void {
    const expired =
      !!updated.status_expires_at && new Date(updated.status_expires_at).getTime() <= Date.now();
    this.acceptances.update((all) =>
      all.map((row) => (row.id === updated.id ? { ...row, ...updated, expired } : row)),
    );
  }

  /** Drop a removed acceptance from the list. */
  onRemoved(removed: Finding): void {
    this.acceptances.update((all) => all.filter((row) => row.id !== removed.id));
    this.removedCount.update((count) => count + 1);
    this.selectedId.set(null);
    this.notice.set(msg('acceptances.removed', { id: removed.id }));
  }

  /** Count the comment added to an acceptance. */
  onCommented(id: number): void {
    this.acceptances.update((all) =>
      all.map((row) => (row.id === id ? { ...row, comments_total: row.comments_total + 1 } : row)),
    );
  }
}

/** Order of two acceptances on a column (no expiry date: after every date). */
function compare(a: RiskAcceptance, b: RiskAcceptance, key: SortKey): number {
  const text = (left: string | null, right: string | null) =>
    (left ?? '').localeCompare(right ?? '', undefined, { numeric: true, sensitivity: 'base' });
  switch (key) {
    case 'severity':
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    case 'title':
      return text(a.title, b.title);
    case 'project':
      return text(a.project, b.project);
    case 'approver':
      return text(a.status_approver, b.status_approver);
    case 'accepted':
      return text(a.status_changed_at, b.status_changed_at);
    case 'comments':
      return a.comments_total - b.comments_total;
    case 'expires':
      return text(a.status_expires_at ?? '9999', b.status_expires_at ?? '9999');
  }
}
