import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { SEVERITY_META, STATUS_META } from '../../../core/constants/labels';
import {
  FINDING_STATUSES,
  Finding,
  FindingStatus,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
} from '../../../core/models/api.models';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService, saveBlob } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../../../shared/components/status-badge/status-badge.component';

/** One report: metadata, summary and findings, with triage for triagers. */
@Component({
  selector: 'app-report-detail',
  imports: [RouterLink, DatePipe, SeverityBadgeComponent, StatusBadgeComponent, TranslatePipe],
  templateUrl: './report-detail.component.html',
  styleUrl: './report-detail.component.css',
})
export class ReportDetailComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);

  /** Route parameter :id */
  readonly id = input.required<string>();

  readonly severities = SEVERITIES;
  readonly statuses = FINDING_STATUSES;
  readonly severityMeta = SEVERITY_META;
  readonly statusMeta = STATUS_META;

  readonly reportId = computed(() => Number.parseInt(this.id(), 10));

  readonly report = rxResource({
    params: () => ({ id: this.reportId() }),
    stream: ({ params }) => this.api.report(params.id),
  });

  /** Local copy of the findings, updated in place after a triage decision. */
  readonly findings = linkedSignal<Finding[]>(() => this.report.value()?.findings ?? []);

  readonly severityFilter = signal<Severity | ''>('');
  readonly statusFilter = signal<FindingStatus | ''>('');

  /** Finding ids whose status is being saved, and the last triage error. */
  readonly saving = signal<ReadonlySet<number>>(new Set());
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

  /** Save a new status for a finding (triagers and administrators only). */
  changeStatus(finding: Finding, event: Event): void {
    const select = event.target as HTMLSelectElement;
    const status = select.value as FindingStatus;
    if (status === finding.status) {
      return;
    }
    this.triageError.set(null);
    this.saving.update((ids) => new Set(ids).add(finding.id));
    this.api.updateFindingStatus(finding.id, status).subscribe({
      next: (updated) => {
        this.findings.update((all) => all.map((f) => (f.id === updated.id ? updated : f)));
        this.doneSaving(finding.id);
      },
      error: (err: unknown) => {
        // Put the select back on the stored value
        select.value = finding.status;
        this.triageError.set(
          err instanceof HttpErrorResponse && err.status === 403
            ? msg('report.triageForbidden')
            : msg('report.triageFailed', { id: finding.id }),
        );
        this.doneSaving(finding.id);
      },
    });
  }

  downloadMarkdown(): void {
    this.api
      .reportMarkdown(this.reportId())
      .subscribe((blob) => saveBlob(blob, `report-${this.reportId()}.md`));
  }

  downloadSarif(): void {
    this.api
      .sarif({ report_id: this.reportId() })
      .subscribe((blob) => saveBlob(blob, `report-${this.reportId()}.sarif`));
  }

  /** "file.py:10-12" */
  location(finding: Finding): string | null {
    if (!finding.file_path) {
      return null;
    }
    let location = finding.file_path;
    if (finding.line_start) {
      location += `:${finding.line_start}`;
      if (finding.line_end && finding.line_end !== finding.line_start) {
        location += `-${finding.line_end}`;
      }
    }
    return location;
  }

  /** Link to the MITRE description of a CWE ("CWE-89" -> .../89.html). */
  cweUrl(cwe: string): string | null {
    const id = /^CWE-(\d+)$/.exec(cwe)?.[1];
    return id ? `https://cwe.mitre.org/data/definitions/${id}.html` : null;
  }

  private doneSaving(id: number): void {
    this.saving.update((ids) => {
      const next = new Set(ids);
      next.delete(id);
      return next;
    });
  }
}
