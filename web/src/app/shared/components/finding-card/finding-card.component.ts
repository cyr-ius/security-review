import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, output, signal } from '@angular/core';
import { STATUS_META } from '../../../core/constants/labels';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  DISMISSED_STATUSES,
  FINDING_STATUSES,
  Finding,
  FindingDecision,
  FindingStatus,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { SeverityBadgeComponent } from '../severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../status-badge/status-badge.component';

/** Default validity of an acceptance or a false positive, in days (the server caps it). */
const DEFAULT_DISMISSAL_DAYS = 90;

/** YYYY-MM-DD of today plus ``days``, in UTC like the server. */
function isoDay(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

/**
 * One finding: description, evidence and recommendation, with a status select for triagers.
 * Accepting a risk or marking a false positive asks for a reason and an expiry date; a status
 * proposed by an agent is shown apart, for the triager to apply or reject.
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

  /** Accepted or false positive being decided: the form asks for a reason and an expiry. */
  readonly pendingStatus = signal<FindingStatus | null>(null);
  readonly reason = signal('');
  readonly expiresOn = signal(isoDay(DEFAULT_DISMISSAL_DAYS));
  readonly minExpiry = isoDay(1);

  /** The acceptance or false positive has expired: the finding counts as open again. */
  readonly expired = computed(() => {
    const finding = this.finding();
    return (
      finding.status === 'open' &&
      !!finding.status_expires_at &&
      new Date(finding.status_expires_at).getTime() <= Date.now()
    );
  });

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

  /** Status select: open and fixed are saved at once, a dismissal opens the form. */
  changeStatus(event: Event): void {
    const finding = this.finding();
    const select = event.target as HTMLSelectElement;
    const status = select.value as FindingStatus;
    // The select keeps showing the stored status until a decision is saved
    select.value = finding.status;
    if (status === finding.status) {
      return;
    }
    if (DISMISSED_STATUSES.includes(status)) {
      this.openDismissal(status);
      return;
    }
    this.save({ status });
  }

  /** Open the reason and expiry form for an acceptance or a false positive. */
  openDismissal(status: FindingStatus): void {
    this.reason.set('');
    this.expiresOn.set(isoDay(DEFAULT_DISMISSAL_DAYS));
    this.pendingStatus.set(status);
  }

  cancelDismissal(): void {
    this.pendingStatus.set(null);
  }

  submitDismissal(): void {
    const status = this.pendingStatus();
    if (status) {
      this.save({ status, reason: this.reason().trim(), expires_on: this.expiresOn() });
    }
  }

  /** Apply the status proposed by an agent: a dismissal still needs the triager's reason. */
  applyProposal(): void {
    const proposed = this.finding().proposed_status;
    if (!proposed) {
      return;
    }
    if (DISMISSED_STATUSES.includes(proposed)) {
      this.openDismissal(proposed);
    } else {
      this.save({ status: proposed });
    }
  }

  rejectProposal(): void {
    const finding = this.finding();
    this.saving.set(true);
    this.api.rejectFindingProposal(finding.id).subscribe({
      next: (saved) => this.saved(saved),
      error: (err: unknown) => this.refused(err, finding.id),
    });
  }

  private save(decision: FindingDecision): void {
    const finding = this.finding();
    this.saving.set(true);
    this.api.updateFindingStatus(finding.id, decision).subscribe({
      next: (saved) => this.saved(saved),
      error: (err: unknown) => this.refused(err, finding.id),
    });
  }

  private saved(finding: Finding): void {
    this.saving.set(false);
    this.pendingStatus.set(null);
    this.updated.emit(finding);
  }

  private refused(err: unknown, id: number): void {
    this.saving.set(false);
    const code = err instanceof HttpErrorResponse ? err.status : 0;
    this.failed.emit(
      code === 403
        ? msg('report.triageForbidden')
        : code === 422
          ? msg('report.triageInvalid', { id })
          : msg('report.triageFailed', { id }),
    );
  }
}
