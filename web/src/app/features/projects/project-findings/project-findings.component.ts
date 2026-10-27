import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom, of } from 'rxjs';
import { REVIEW_TYPE_META, SEVERITY_META, STATUS_META } from '../../../core/constants/labels';
import { Message } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import {
  FINDING_STATUSES,
  Finding,
  FindingStatus,
  ProjectFinding,
  REVIEW_TYPES,
  ReviewType,
  SEVERITIES,
  Severity,
  ConnectorKind,
} from '../../../core/models/api.models';
import { AuthService } from '../../../core/services/auth.service';
import { ExportService, kindsByProject, systemNames } from '../../../core/services/export.service';
import { TriageChange, TriageService } from '../../../core/services/triage.service';
import { ApiService } from '../../../core/services/api.service';
import { FindingCardComponent } from '../../../shared/components/finding-card/finding-card.component';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';

/** Findings loaded per request (the server caps it with SECREVIEW_MAX_LIST_LIMIT). */
const PAGE_SIZE = 50;

/**
 * Every open finding of a project (or of every project, at /findings), across all reports, worst
 * first: the list a security expert reviews and triages. Other statuses can be listed to re-check
 * past decisions.
 */
@Component({
  selector: 'app-project-findings',
  imports: [
    HelpLinkComponent,
    RouterLink,
    DatePipe,
    FindingCardComponent,
    RefreshButtonComponent,
    TranslatePipe,
  ],
  templateUrl: './project-findings.component.html',
  styleUrl: './project-findings.component.css',
})
export class ProjectFindingsComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);
  readonly triage = inject(TriageService);
  readonly exports = inject(ExportService);

  /** Route parameter :project (undefined at /findings: every project in the scope). */
  readonly project = input<string>();

  readonly severities = SEVERITIES;
  readonly statuses = FINDING_STATUSES;
  readonly severityMeta = SEVERITY_META;
  readonly statusMeta = STATUS_META;
  readonly reviewTypes = REVIEW_TYPES;
  readonly reviewTypeMeta = REVIEW_TYPE_META;

  readonly statusFilter = signal<FindingStatus>('open');
  readonly severityFilter = signal<Severity | ''>('');
  readonly reviewTypeFilter = signal<ReviewType | ''>('');

  /** First page for the current filters. */
  readonly firstPage = rxResource({
    params: () => ({
      project: this.project(),
      status: this.statusFilter(),
      severity: this.severityFilter(),
      reviewType: this.reviewTypeFilter(),
      limit: PAGE_SIZE,
      offset: 0,
    }),
    stream: ({ params }) => this.api.projectFindings(params),
  });

  /** Names of the connectors, to label the exports. */
  readonly systems = rxResource({ stream: () => this.api.connectorSystems() });
  readonly systemNames = computed(() => systemNames(this.systems.value() ?? []));

  /** Systems the user may send findings to, by project (none without findings.triage). */
  readonly destinations = rxResource({
    params: () => ({ triage: this.auth.canTriage() }),
    stream: ({ params }) => (params.triage ? this.api.connectorDestinations() : of([])),
  });
  readonly exportKinds = computed(() => kindsByProject(this.destinations.value() ?? []));
  readonly noKinds: readonly ConnectorKind[] = [];

  /** Loaded findings: the first page, then the pages added by "load more" and triage updates. */
  readonly findings = linkedSignal<ProjectFinding[]>(() => this.firstPage.value()?.findings ?? []);
  readonly total = computed(() => this.firstPage.value()?.total ?? 0);
  readonly hasMore = computed(() => this.findings().length < this.total());

  readonly loadingMore = signal(false);
  readonly loadMoreFailed = signal(false);
  readonly triageError = signal<Message | null>(null);

  /** Findings whose status changed on this page (they stay listed until the next reload). */
  readonly triagedCount = computed(
    () => this.findings().filter((f) => f.status !== this.statusFilter()).length,
  );

  readonly forbidden = computed(() => {
    const error = this.firstPage.error();
    return error instanceof HttpErrorResponse && error.status === 404;
  });

  onStatusFilter(event: Event): void {
    this.statusFilter.set((event.target as HTMLSelectElement).value as FindingStatus);
  }

  onSeverityFilter(event: Event): void {
    this.severityFilter.set((event.target as HTMLSelectElement).value as Severity | '');
  }

  onReviewTypeFilter(event: Event): void {
    this.reviewTypeFilter.set((event.target as HTMLSelectElement).value as ReviewType | '');
  }

  /** Append the next page to the list. */
  async loadMore(): Promise<void> {
    this.loadingMore.set(true);
    this.loadMoreFailed.set(false);
    const request = this.api.projectFindings({
      project: this.project(),
      status: this.statusFilter(),
      severity: this.severityFilter(),
      reviewType: this.reviewTypeFilter(),
      limit: PAGE_SIZE,
      // Triaged findings left the filtered set on the server: skipping them in the offset
      // keeps the next page from jumping over findings not yet seen
      offset: this.findings().length - this.triagedCount(),
    });
    try {
      const page = await firstValueFrom(request);
      const known = new Set(this.findings().map((f) => f.id));
      this.findings.update((all) => [...all, ...page.findings.filter((f) => !known.has(f.id))]);
    } catch {
      this.loadMoreFailed.set(true);
    } finally {
      this.loadingMore.set(false);
    }
  }

  /** Save the triage decision of a finding card (``null``: reject the agent proposal). */
  async decide(finding: Finding, decision: TriageChange | null): Promise<void> {
    this.triageError.set(null);
    const result = await this.triage.decide(finding, decision);
    if ('error' in result) {
      this.triageError.set(result.error);
    } else {
      this.onUpdated(result.finding);
    }
  }

  /** Send a finding through a connector and show its record. */
  async exportFinding(finding: ProjectFinding, kind: ConnectorKind): Promise<void> {
    this.triageError.set(null);
    const result = await this.exports.send(finding, kind);
    if ('error' in result) {
      this.triageError.set(result.error);
    } else {
      this.onUpdated(result.finding);
    }
  }

  /** Keep the triage decision saved by a finding card, and the report context of the row. */
  onUpdated(updated: Finding): void {
    this.triageError.set(null);
    this.findings.update((all) => all.map((f) => (f.id === updated.id ? { ...f, ...updated } : f)));
  }
}
