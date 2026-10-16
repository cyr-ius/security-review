import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, output, signal } from '@angular/core';
import { STATUS_META } from '../../../core/constants/labels';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { FINDING_STATUSES, Finding, FindingStatus } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { SeverityBadgeComponent } from '../severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../status-badge/status-badge.component';

/**
 * One finding: description, evidence and recommendation, with a status select for triagers.
 * Extra details (report link...) can be projected at the end of the metadata line.
 */
@Component({
  selector: 'app-finding-card',
  imports: [DatePipe, SeverityBadgeComponent, StatusBadgeComponent, TranslatePipe],
  templateUrl: './finding-card.component.html',
  styleUrl: './finding-card.component.css',
})
export class FindingCardComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);

  readonly finding = input.required<Finding>();

  /** The saved finding, after a triage decision. */
  readonly updated = output<Finding>();
  /** Why a triage decision could not be saved. */
  readonly failed = output<Message>();

  readonly statuses = FINDING_STATUSES;
  readonly statusMeta = STATUS_META;
  readonly saving = signal(false);

  /** "file.py:10-12" */
  readonly location = computed(() => {
    const finding = this.finding();
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
  });

  /** Link to the MITRE description of the CWE ("CWE-89" -> .../89.html). */
  readonly cweUrl = computed(() => {
    const id = /^CWE-(\d+)$/.exec(this.finding().cwe ?? '')?.[1];
    return id ? `https://cwe.mitre.org/data/definitions/${id}.html` : null;
  });

  /** Save a new status (triagers and administrators only). */
  changeStatus(event: Event): void {
    const finding = this.finding();
    const select = event.target as HTMLSelectElement;
    const status = select.value as FindingStatus;
    if (status === finding.status) {
      return;
    }
    this.saving.set(true);
    this.api.updateFindingStatus(finding.id, status).subscribe({
      next: (saved) => {
        this.saving.set(false);
        this.updated.emit(saved);
      },
      error: (err: unknown) => {
        // Put the select back on the stored value
        select.value = finding.status;
        this.saving.set(false);
        this.failed.emit(
          err instanceof HttpErrorResponse && err.status === 403
            ? msg('report.triageForbidden')
            : msg('report.triageFailed', { id: finding.id }),
        );
      },
    });
  }
}
