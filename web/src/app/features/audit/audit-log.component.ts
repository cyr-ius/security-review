import { DatePipe } from '@angular/common';
import { Component, computed, inject, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AUDIT_ACTIONS, AuditAction, AuditEvent } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/** Events loaded per page (the server caps it with SECREVIEW_MAX_LIST_LIMIT). */
const PAGE_SIZE = 50;

/**
 * Administrator page of the audit log: triage decisions, agent proposals, tokens and
 * enrollment requests, newest first. Read only: nobody edits an audit event.
 */
@Component({
  selector: 'app-audit-log',
  imports: [DatePipe, RefreshButtonComponent, TranslatePipe],
  templateUrl: './audit-log.component.html',
})
export class AuditLogComponent {
  private readonly api = inject(ApiService);

  readonly actions = AUDIT_ACTIONS;
  readonly actionFilter = signal<AuditAction | ''>('');
  readonly projectFilter = signal('');

  /** First page for the current filters. */
  readonly firstPage = rxResource({
    params: () => ({
      action: this.actionFilter() || null,
      project: this.projectFilter().trim() || null,
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

  onProjectFilter(event: Event): void {
    this.projectFilter.set((event.target as HTMLInputElement).value);
  }

  /** Append the next page (events are append-only: the offset stays valid). */
  loadMore(): void {
    this.loadingMore.set(true);
    this.loadMoreFailed.set(false);
    this.api
      .auditEvents({
        action: this.actionFilter() || null,
        project: this.projectFilter().trim() || null,
        limit: PAGE_SIZE,
        offset: this.events().length,
      })
      .subscribe({
        next: (page) => {
          const known = new Set(this.events().map((item) => item.id));
          this.events.update((all) => [...all, ...page.events.filter((e) => !known.has(e.id))]);
          this.loadingMore.set(false);
        },
        error: () => {
          this.loadMoreFailed.set(true);
          this.loadingMore.set(false);
        },
      });
  }
}
