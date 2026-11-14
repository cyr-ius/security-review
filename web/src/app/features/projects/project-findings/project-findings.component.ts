import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  Component,
  DestroyRef,
  computed,
  inject,
  input,
  linkedSignal,
  signal,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom, of } from 'rxjs';
import { REVIEW_TYPE_META, SEVERITY_META, STATUS_META } from '../../../core/constants/labels';
import { I18nService, Message } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import {
  FINDING_STATUSES,
  Finding,
  FindingDecision,
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
import { MultiSelectOption } from '../../../shared/components/multi-select-dropdown/multi-select-dropdown.component';
import {
  TableControlMultiFilter,
  TableControlMultiFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { BulkTriageComponent } from './bulk-triage/bulk-triage.component';
import { reloadOnReturn } from '../../../shared/utils/reload-on-return';
import { reportSearch } from '../../../layout/global-search/search-query';
import { PackageGroup, groupByPackage } from '../../../shared/utils/package-groups';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';

/** Findings loaded per request (the server caps it with SECREVIEW_MAX_LIST_LIMIT). */
const PAGE_SIZE = 50;

/** Pause after the last key stroke before the search reloads the list. */
const SEARCH_DELAY_MS = 300;

/**
 * Every open finding of a project (or of every project, at /findings), across all reports, worst
 * first: the list a security expert reviews and triages. Other statuses can be listed to re-check
 * past decisions.
 */
@Component({
  selector: 'app-project-findings',
  imports: [
    BulkTriageComponent,
    HelpLinkComponent,
    RouterLink,
    DatePipe,
    FindingCardComponent,
    NgTemplateOutlet,
    RefreshButtonComponent,
    SeverityBadgeComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './project-findings.component.html',
  styleUrl: './project-findings.component.css',
})
export class ProjectFindingsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  readonly auth = inject(AuthService);
  readonly triage = inject(TriageService);
  readonly exports = inject(ExportService);

  /** Route parameter :project (undefined at /findings: every project in the scope). */
  readonly project = input<string>();

  readonly reviewTypeMeta = REVIEW_TYPE_META;

  /** Query parameters ?status=&severity= (set by the search of the top bar, may be repeated). */
  readonly status = input<string | string[]>();
  readonly severity = input<string | string[]>();

  /** Selected values of each filter (none: no filter, every status for the status). */
  readonly statusFilter = linkedSignal<FindingStatus[]>(() => {
    const statuses = known(this.status(), FINDING_STATUSES);
    return statuses.length ? statuses : ['open'];
  });
  readonly severityFilter = linkedSignal<Severity[]>(() => known(this.severity(), SEVERITIES));
  readonly reviewTypeFilter = signal<ReviewType[]>([]);

  /** Only the findings with a status proposed by an agent. */
  readonly proposedOnly = signal(false);

  /** Query parameter ?search= (set by the search field of the top bar). */
  readonly search = input<string>();

  /** Text typed in the search field, and the search applied once typing pauses. */
  readonly searchInput = linkedSignal(() => this.search() ?? '');
  readonly appliedSearch = linkedSignal(() => (this.search() ?? '').trim());
  private searchTimer?: ReturnType<typeof setTimeout>;

  /** Applied search split into ``#report:<number>`` (the findings of that report) and text. */
  private readonly searchQuery = computed(() => {
    const { reportId, text } = reportSearch(this.appliedSearch());
    return { reportId, search: text || undefined };
  });

  /** Statuses listed: the selected ones, or all of them. */
  private readonly statuses = computed(() =>
    this.statusFilter().length ? this.statusFilter() : FINDING_STATUSES,
  );

  readonly statusOptions = computed<MultiSelectOption[]>(() =>
    FINDING_STATUSES.map((status) => ({
      value: status,
      label: this.i18n.translate(STATUS_META[status].label),
    })),
  );
  readonly severityOptions = computed<MultiSelectOption[]>(() =>
    SEVERITIES.map((severity) => ({
      value: severity,
      label: this.i18n.translate(SEVERITY_META[severity].label),
    })),
  );
  readonly reviewTypeOptions = computed<MultiSelectOption[]>(() =>
    REVIEW_TYPES.map((reviewType) => ({
      value: reviewType,
      label: this.i18n.translate(REVIEW_TYPE_META[reviewType].label),
    })),
  );

  /** Filters of the list (ids findings-filter-status, -severity and -review-type). */
  readonly filters = computed<TableControlMultiFilter[]>(() => [
    {
      key: 'status',
      label: this.i18n.translate('report.filterStatus'),
      allLabel: this.i18n.translate('report.allStatuses'),
      values: this.statusFilter(),
      options: this.statusOptions(),
    },
    {
      key: 'severity',
      label: this.i18n.translate('report.filterSeverity'),
      allLabel: this.i18n.translate('report.allSeverities'),
      values: this.severityFilter(),
      options: this.severityOptions(),
    },
    {
      key: 'review-type',
      label: this.i18n.translate('report.filterReviewType'),
      allLabel: this.i18n.translate('report.allReviewTypes'),
      values: this.reviewTypeFilter(),
      options: this.reviewTypeOptions(),
    },
  ]);

  /** No filter but the default one (open findings). */
  readonly defaultFilters = computed(
    () =>
      this.statusFilter().length === 1 &&
      this.statusFilter()[0] === 'open' &&
      !this.severityFilter().length &&
      !this.reviewTypeFilter().length &&
      !this.proposedOnly() &&
      !this.appliedSearch(),
  );

  /** First page for the current filters. */
  readonly firstPage = rxResource({
    params: () => ({
      project: this.project(),
      status: this.statuses(),
      severity: this.severityFilter(),
      reviewType: this.reviewTypeFilter(),
      ...this.searchQuery(),
      proposed: this.proposedOnly(),
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

  /** Type the context of the finding card template (``let-`` variables are not typed). */
  asFinding(finding: ProjectFinding): ProjectFinding {
    return finding;
  }

  /** Loaded findings, the advisories of one vulnerable package gathered in a group. */
  readonly entries = computed(() => groupByPackage(this.findings()));
  readonly hasMore = computed(() => this.findings().length < this.total());

  readonly loadingMore = signal(false);
  readonly loadMoreFailed = signal(false);
  readonly triageError = signal<Message | null>(null);

  /** Findings whose status changed on this page (they stay listed until the next reload). */
  readonly triagedCount = computed(
    () => this.findings().filter((f) => !this.statuses().includes(f.status)).length,
  );

  /** Ids picked for a bulk decision (cleared when the filters change or the list reloads). */
  readonly selectedIds = linkedSignal<unknown, ReadonlySet<number>>({
    source: () => this.firstPage.value(),
    computation: () => new Set(),
  });

  /** Loaded findings a decision applies to (a finding reported again is triaged on its latest). */
  readonly triageable = computed(() => this.findings().filter((f) => f.superseded_by === null));

  /** Loaded findings picked for a bulk decision. */
  readonly selectedFindings = computed(() =>
    this.triageable().filter((f) => this.selectedIds().has(f.id)),
  );

  /** Every loaded finding that can be triaged is picked. */
  readonly allSelected = computed(
    () =>
      this.triageable().length > 0 && this.selectedFindings().length === this.triageable().length,
  );

  constructor() {
    inject(DestroyRef).onDestroy(() => clearTimeout(this.searchTimer));
    // Not after "load more" or a triage: the reload would drop those rows
    reloadOnReturn(
      () => this.firstPage.reload(),
      () => this.findings().length <= PAGE_SIZE && !this.triagedCount(),
    );
  }

  readonly forbidden = computed(() => {
    const error = this.firstPage.error();
    return error instanceof HttpErrorResponse && error.status === 404;
  });

  onFilter({ key, values }: TableControlMultiFilterChange): void {
    if (key === 'status') {
      this.statusFilter.set(FINDING_STATUSES.filter((status) => values.includes(status)));
    } else if (key === 'severity') {
      this.severityFilter.set(SEVERITIES.filter((severity) => values.includes(severity)));
    } else if (key === 'review-type') {
      this.reviewTypeFilter.set(REVIEW_TYPES.filter((reviewType) => values.includes(reviewType)));
    }
  }

  /** List only the findings with a proposal of an agent, or every finding. */
  toggleProposed(event: Event): void {
    this.proposedOnly.set((event.target as HTMLInputElement).checked);
  }

  /** Keep the typed text and search it once typing pauses. */
  onSearch(value: string): void {
    this.searchInput.set(value);
    clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.appliedSearch.set(value.trim()), SEARCH_DELAY_MS);
  }

  /** Append the next page to the list. */
  async loadMore(): Promise<void> {
    this.loadingMore.set(true);
    this.loadMoreFailed.set(false);
    const request = this.api.projectFindings({
      project: this.project(),
      status: this.statuses(),
      severity: this.severityFilter(),
      reviewType: this.reviewTypeFilter(),
      ...this.searchQuery(),
      proposed: this.proposedOnly(),
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

  /** Pick or leave a finding for a bulk decision. */
  select(finding: Finding, picked: boolean): void {
    this.selectedIds.update((ids) => {
      const next = new Set(ids);
      if (picked) {
        next.add(finding.id);
      } else {
        next.delete(finding.id);
      }
      return next;
    });
  }

  /** Findings of a group a decision applies to (a finding reported again is triaged on its latest). */
  groupTriageable(group: PackageGroup<ProjectFinding>): ProjectFinding[] {
    return group.findings.filter((f) => f.superseded_by === null);
  }

  /** Every finding of a group that can be triaged is picked. */
  groupSelected(group: PackageGroup<ProjectFinding>): boolean {
    const findings = this.groupTriageable(group);
    return findings.length > 0 && findings.every((f) => this.selectedIds().has(f.id));
  }

  /** Some, but not every, finding of a group is picked. */
  groupPartlySelected(group: PackageGroup<ProjectFinding>): boolean {
    return (
      !this.groupSelected(group) &&
      this.groupTriageable(group).some((f) => this.selectedIds().has(f.id))
    );
  }

  /** Pick or leave every finding of a group for a bulk decision. */
  selectGroup(group: PackageGroup<ProjectFinding>, event: Event): void {
    const picked = (event.target as HTMLInputElement).checked;
    this.selectedIds.update((ids) => {
      const next = new Set(ids);
      for (const finding of this.groupTriageable(group)) {
        if (picked) {
          next.add(finding.id);
        } else {
          next.delete(finding.id);
        }
      }
      return next;
    });
  }

  /** Pick every loaded finding that can be triaged, or none. */
  selectAll(event: Event): void {
    const picked = (event.target as HTMLInputElement).checked;
    this.selectedIds.set(new Set(picked ? this.triageable().map((f) => f.id) : []));
  }

  clearSelection(): void {
    this.selectedIds.set(new Set());
  }

  /** Save the same decision on every picked finding (all or nothing), then clear the pick. */
  async decideMany(decision: FindingDecision): Promise<void> {
    this.triageError.set(null);
    const result = await this.triage.decideMany(this.selectedFindings(), decision);
    if ('error' in result) {
      this.triageError.set(result.error);
      return;
    }
    const saved = new Map(result.findings.map((f) => [f.id, f]));
    this.findings.update((all) =>
      all.map((f) => {
        const updated = saved.get(f.id);
        return updated ? { ...f, ...updated } : f;
      }),
    );
    this.clearSelection();
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

/** Known values of a query parameter given once or repeated, in their usual order. */
function known<T extends string>(value: string | string[] | undefined, values: readonly T[]): T[] {
  const given = Array.isArray(value) ? value : [value ?? ''];
  return values.filter((item) => given.includes(item));
}
