import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom, of } from 'rxjs';
import {
  CHECKLIST_OUTCOME_META,
  REVIEW_TYPE_META,
  SEVERITY_META,
  STATUS_META,
} from '../../../core/constants/labels';
import {
  CHECKLIST_OUTCOMES,
  FINDING_STATUSES,
  Finding,
  FindingStatus,
  PROMPT_REVIEW_TYPES,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
  TicketKind,
} from '../../../core/models/api.models';
import { Message } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { AuthService } from '../../../core/services/auth.service';
import { TicketService, kindsByProject, systemNames } from '../../../core/services/ticket.service';
import { TriageChange, TriageService } from '../../../core/services/triage.service';
import { ApiService, saveBlob } from '../../../core/services/api.service';
import { FindingCardComponent } from '../../../shared/components/finding-card/finding-card.component';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';

/** One report: metadata, summary and findings, with triage for triagers. */
@Component({
  selector: 'app-report-detail',
  imports: [RouterLink, DatePipe, FindingCardComponent, SeverityBadgeComponent, TranslatePipe],
  templateUrl: './report-detail.component.html',
  styleUrl: './report-detail.component.css',
})
export class ReportDetailComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);
  readonly triage = inject(TriageService);
  readonly tickets = inject(TicketService);

  /** Route parameter :id */
  readonly id = input.required<string>();

  readonly severities = SEVERITIES;
  readonly statuses = FINDING_STATUSES;
  readonly severityMeta = SEVERITY_META;
  readonly statusMeta = STATUS_META;
  readonly reviewTypeMeta = REVIEW_TYPE_META;
  readonly outcomeMeta = CHECKLIST_OUTCOME_META;

  readonly reportId = computed(() => Number.parseInt(this.id(), 10));

  readonly report = rxResource({
    params: () => ({ id: this.reportId() }),
    stream: ({ params }) => this.api.report(params.id),
  });

  /** Names of the ticketing systems, to label the tickets. */
  readonly systems = rxResource({ stream: () => this.api.ticketSystems() });
  readonly systemNames = computed(() => systemNames(this.systems.value() ?? []));

  /** Systems the user may send findings to, by project (none without findings.triage). */
  readonly destinations = rxResource({
    params: () => ({ triage: this.auth.canTriage() }),
    stream: ({ params }) => (params.triage ? this.api.ticketDestinations() : of([])),
  });

  /** Systems the findings of this report may be sent to. */
  readonly ticketKinds = computed<readonly TicketKind[]>(() => {
    const project = this.report.value()?.project;
    const destinations = this.destinations.value() ?? [];
    return project ? (kindsByProject(destinations).get(project) ?? []) : [];
  });

  /** Local copy of the findings, updated in place after a triage decision. */
  readonly findings = linkedSignal<Finding[]>(() => this.report.value()?.findings ?? []);

  readonly severityFilter = signal<Severity | ''>('');
  readonly statusFilter = signal<FindingStatus | ''>('');

  /** Last triage error. */
  readonly triageError = signal<Message | null>(null);

  readonly notFound = computed(() => {
    const error = this.report.error();
    return error instanceof HttpErrorResponse && error.status === 404;
  });

  readonly visibleFindings = computed(() =>
    this.findings()
      .filter((f) => !this.severityFilter() || f.severity === this.severityFilter())
      .filter((f) => !this.statusFilter() || f.status === this.statusFilter())
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id - b.id),
  );

  /** Declared coverage: checklist items by outcome (attention first) and the scan leads. */
  readonly coverage = computed(() => {
    const data = this.report.value();
    if (!data) {
      return null;
    }
    const items = [...data.checklist_results].sort(
      (a, b) =>
        CHECKLIST_OUTCOMES.indexOf(a.outcome) - CHECKLIST_OUTCOMES.indexOf(b.outcome) ||
        a.item_id.localeCompare(b.item_id),
    );
    const counts = CHECKLIST_OUTCOMES.map((outcome) => ({
      outcome,
      count: items.filter((r) => r.outcome === outcome).length,
    })).filter((entry) => entry.count > 0);
    const cited = new Set(data.findings.map((f) => f.rule_id?.trim().toUpperCase()));
    const leads = data.scan_rules.map((rule) => ({ rule, dismissed: !cited.has(rule) }));
    const declared = items.length > 0 || leads.length > 0;
    const expected = !!data.review_type && PROMPT_REVIEW_TYPES.includes(data.review_type);
    return declared || expected ? { items, counts, leads, declared } : null;
  });

  readonly openCount = computed(() => this.findings().filter((f) => f.status === 'open').length);

  onSeverityFilter(event: Event): void {
    this.severityFilter.set((event.target as HTMLSelectElement).value as Severity | '');
  }

  onStatusFilter(event: Event): void {
    this.statusFilter.set((event.target as HTMLSelectElement).value as FindingStatus | '');
  }

  /** Save the triage decision of a finding card (``null``: reject the agent proposal). */
  async decide(finding: Finding, decision: TriageChange | null): Promise<void> {
    this.triageError.set(null);
    const result = await this.triage.decide(finding, decision);
    if ('error' in result) {
      this.triageError.set(result.error);
    } else if (decision && 'severity' in decision) {
      // A raised severity may raise the risk level of the report too
      this.report.reload();
    } else {
      this.onUpdated(result.finding);
    }
  }

  /** Send a finding to a ticketing system and show its ticket. */
  async sendTicket(finding: Finding, kind: TicketKind): Promise<void> {
    this.triageError.set(null);
    const result = await this.tickets.send(finding, kind);
    if ('error' in result) {
      this.triageError.set(result.error);
      // A failure is stored on the finding: show it
      this.report.reload();
    } else {
      this.onUpdated(result.finding);
    }
  }

  /** Keep the triage decision saved by a finding card. */
  onUpdated(updated: Finding): void {
    this.triageError.set(null);
    this.findings.update((all) => all.map((f) => (f.id === updated.id ? updated : f)));
  }

  async downloadMarkdown(): Promise<void> {
    const id = this.reportId();
    saveBlob(await firstValueFrom(this.api.reportMarkdown(id)), `report-${id}.md`);
  }

  async downloadSarif(): Promise<void> {
    const id = this.reportId();
    saveBlob(await firstValueFrom(this.api.sarif({ report_id: id })), `report-${id}.sarif`);
  }
}
