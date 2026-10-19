import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, linkedSignal, output, signal } from '@angular/core';
import { FormField, form, maxLength, required, validate } from '@angular/forms/signals';
import { STATUS_META } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  DISMISSED_STATUSES,
  FINDING_STATUSES,
  Finding,
  FindingDecision,
  FindingStatus,
} from '../../../core/models/api.models';
import { SeverityBadgeComponent } from '../severity-badge/severity-badge.component';
import { StatusBadgeComponent } from '../status-badge/status-badge.component';

/** Default validity of an acceptance or a false positive, in days (the server caps it). */
const DEFAULT_DISMISSAL_DAYS = 90;

/** Shortest reason of an acceptance or a false positive (services.MIN_STATUS_REASON_CHARS). */
const MIN_REASON_CHARS = 10;
/** Longest reason accepted by the server (models.MAX_STATUS_REASON_CHARS). */
const MAX_REASON_CHARS = 1000;

/** Reason and expiry of an acceptance or a false positive. */
interface DismissalFormModel {
  reason: string;
  expiresOn: string;
  /** Acceptance without an expiry date (only offered for ``accepted``). */
  noExpiry: boolean;
}

/** YYYY-MM-DD of today plus ``days``, in UTC like the server. */
function isoDay(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

/**
 * One finding: description, evidence and recommendation, with a status select for triagers.
 * Accepting a risk or marking a false positive asks for a reason and an expiry date (an
 * acceptance may have none when ``permanentAcceptance`` is set); a status
 * proposed by an agent is shown apart, for the triager to apply or reject.
 * Extra details (report link...) can be projected at the end of the metadata line.
 *
 * The card only shows and asks: the page saves the decision it emits (see TriageService) and
 * passes the saved finding back, which closes the form.
 */
@Component({
  selector: 'app-finding-card',
  imports: [DatePipe, FormField, SeverityBadgeComponent, StatusBadgeComponent, TranslatePipe],
  templateUrl: './finding-card.component.html',
  styleUrl: './finding-card.component.css',
})
export class FindingCardComponent {
  private readonly i18n = inject(I18nService);

  readonly finding = input.required<Finding>();
  /** The user may record triage decisions (findings.triage). */
  readonly canTriage = input(false);
  /** A risk may be accepted without an expiry date (server setting). */
  readonly permanentAcceptance = input(false);
  /** A decision on this finding is being saved. */
  readonly saving = input(false);

  /** A triage decision to save. */
  readonly decided = output<FindingDecision>();
  /** The status proposed by an agent is rejected. */
  readonly proposalRejected = output<void>();

  readonly statuses = FINDING_STATUSES;
  readonly statusMeta = STATUS_META;

  /**
   * Accepted or false positive being decided: the form asks for a reason and an expiry. It
   * closes when the page passes the saved finding back.
   */
  readonly pendingStatus = linkedSignal<Finding, FindingStatus | null>({
    source: this.finding,
    computation: () => null,
  });
  readonly minExpiry = isoDay(1);
  readonly dismissalModel = signal<DismissalFormModel>(newDismissal());
  readonly dismissalForm = form(this.dismissalModel, (path) => {
    // Counted without the surrounding spaces, like the server
    validate(path.reason, ({ value }) =>
      value().trim().length < MIN_REASON_CHARS
        ? {
            kind: 'minLength',
            message: this.i18n.translate('report.dismissReasonHelp'),
          }
        : undefined,
    );
    maxLength(path.reason, MAX_REASON_CHARS);
    required(path.expiresOn, { when: () => !this.withoutExpiry() });
    validate(path.expiresOn, ({ value }) =>
      !this.withoutExpiry() && value() && value() < this.minExpiry
        ? { kind: 'minDate', message: this.i18n.translate('report.dismissExpiryHelp') }
        : undefined,
    );
  });

  /** The "No expiry" choice is offered: an acceptance, while the server allows it. */
  readonly noExpiryOffered = computed(
    () => this.permanentAcceptance() && this.pendingStatus() === 'accepted',
  );

  /** The decision being made has no expiry date. */
  readonly withoutExpiry = computed(() => this.noExpiryOffered() && this.dismissalModel().noExpiry);

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
    this.dismissalForm().reset(newDismissal());
    this.pendingStatus.set(status);
  }

  cancelDismissal(): void {
    this.pendingStatus.set(null);
  }

  submitDismissal(event: Event): void {
    event.preventDefault();
    const status = this.pendingStatus();
    if (!status || this.dismissalForm().invalid()) {
      this.dismissalForm().markAsTouched();
      return;
    }
    const { reason, expiresOn } = this.dismissalModel();
    const expires_on = this.withoutExpiry() ? null : expiresOn;
    this.save({ status, reason: reason.trim(), expires_on });
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
    this.proposalRejected.emit();
  }

  private save(decision: FindingDecision): void {
    this.decided.emit(decision);
  }
}

/** Empty reason, default expiry. */
function newDismissal(): DismissalFormModel {
  return { reason: '', expiresOn: isoDay(DEFAULT_DISMISSAL_DAYS), noExpiry: false };
}
