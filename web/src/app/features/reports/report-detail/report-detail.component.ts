import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { REVIEW_TYPE_META, SEVERITY_META, STATUS_META } from '../../../core/constants/labels';
import {
  FINDING_STATUSES,
  Finding,
  FindingStatus,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
} from '../../../core/models/api.models';
import { Message } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
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

  /** Route parameter :id */
  readonly id = input.required<string>();

  readonly severities = SEVERITIES;
  readonly statuses = FINDING_STATUSES;
  readonly severityMeta = SEVERITY_META;
  readonly statusMeta = STATUS_META;
  readonly reviewTypeMeta = REVIEW_TYPE_META;

  readonly reportId = computed(() => Number.parseInt(this.id(), 10));

  readonly report = rxResource({
    params: () => ({ id: this.reportId() }),
    stream: ({ params }) => this.api.report(params.id),
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

  readonly openCount = computed(() => this.findings().filter((f) => f.status === 'open').length);

  onSeverityFilter(event: Event): void {
    this.severityFilter.set((event.target as HTMLSelectElement).value as Severity | '');
  }

  onStatusFilter(event: Event): void {
    this.statusFilter.set((event.target as HTMLSelectElement).value as FindingStatus | '');
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
