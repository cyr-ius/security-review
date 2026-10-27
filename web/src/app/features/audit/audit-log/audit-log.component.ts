import { DatePipe } from '@angular/common';
import { Component, computed, inject, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { I18nService } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { AUDIT_ACTIONS, AuditAction, AuditEvent } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { SortHeaderComponent } from '../../../shared/components/sort-header/sort-header.component';
import { TableSort } from '../../../shared/utils/table-sort';
import { AuditSyslogComponent } from '../audit-syslog/audit-syslog.component';

/** Events loaded per page (the server caps it with SECREVIEW_MAX_LIST_LIMIT). */
const PAGE_SIZE = 50;
type AuditSortKey = 'created_at' | 'action' | 'actor' | 'target' | 'project';

/**
 * Administrator page of the audit log: triage decisions, agent proposals, tokens and
 * project requests, newest first. Read only: nobody edits an audit event. The holders of
 * settings.manage also set there the syslog server the events are forwarded to.
 */
@Component({
  selector: 'app-audit-log',
  imports: [
    HelpLinkComponent,
    AuditSyslogComponent,
    DatePipe,
    RefreshButtonComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './audit-log.component.html',
})
export class AuditLogComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  private readonly auth = inject(AuthService);

  /** The syslog button is shown to the holders of settings.manage only. */
  readonly canManageSyslog = computed(() => this.auth.can('settings.manage'));

  readonly actions = AUDIT_ACTIONS;
  readonly actionFilter = signal<AuditAction | ''>('');
  readonly projectFilter = signal('');
  readonly search = signal('');
  readonly sort = new TableSort<AuditSortKey>(
    'audit',
    ['created_at', 'action', 'actor', 'target', 'project'],
    'created_at',
    'desc',
  );
  readonly filters = computed<TableControlFilter[]>(() => [
    {
      key: 'action',
      label: this.i18n.translate('audit.action'),
      value: this.actionFilter(),
      options: [
        { value: '', label: this.i18n.translate('audit.allActions') },
        ...this.actions.map((action) => ({
          value: action,
          label: this.i18n.translate(this.actionLabel(action)),
        })),
      ],
    },
  ]);

  /** First page for the current filters. */
  readonly firstPage = rxResource({
    params: () => ({
      action: this.actionFilter() || null,
      project: this.projectFilter().trim() || null,
      search: this.search().trim() || null,
      sort_by: this.sort.key(),
      sort_direction: this.sort.direction(),
      limit: PAGE_SIZE,
      offset: 0,
    }),
    stream: ({ params }) => this.api.auditEvents(params),
  });

  /** Loaded events: the first page, then the pages added by "load more". */
  readonly events = linkedSignal<AuditEvent[]>(() => this.firstPage.value()?.events ?? []);
  readonly total = computed(() => this.firstPage.value()?.total ?? 0);
  readonly hasMore = computed(() => this.events().length < this.total());
  readonly loadingMore = signal(false);
  readonly loadMoreFailed = signal(false);

  /** Message key of the label of an action. */
  actionLabel(action: AuditAction): MessageKey {
    return `audit.action.${action}` as MessageKey;
  }

  /** Details of an event as one line of key=value pairs (null values left out). */
  describe(event: AuditEvent): string {
    return Object.entries(event.details)
      .filter(([, value]) => value !== null && value !== undefined && value !== '')
      .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(', ') : String(value)}`)
      .join(' · ');
  }

  onActionFilter(event: Event): void {
    this.actionFilter.set((event.target as HTMLSelectElement).value as AuditAction | '');
  }

  onTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'action') {
      this.actionFilter.set(
        this.actions.includes(change.value as AuditAction) ? (change.value as AuditAction) : '',
      );
    }
  }

  onProjectFilter(event: Event): void {
    this.projectFilter.set((event.target as HTMLInputElement).value);
  }

  /** Append the next page (events are append-only: the offset stays valid). */
  async loadMore(): Promise<void> {
    this.loadingMore.set(true);
    this.loadMoreFailed.set(false);
    const request = this.api.auditEvents({
      action: this.actionFilter() || null,
      project: this.projectFilter().trim() || null,
      search: this.search().trim() || null,
      sort_by: this.sort.key(),
      sort_direction: this.sort.direction(),
      limit: PAGE_SIZE,
      offset: this.events().length,
    });
    try {
      const page = await firstValueFrom(request);
      const known = new Set(this.events().map((item) => item.id));
      this.events.update((all) => [...all, ...page.events.filter((e) => !known.has(e.id))]);
    } catch {
      this.loadMoreFailed.set(true);
    } finally {
      this.loadingMore.set(false);
    }
  }
}
