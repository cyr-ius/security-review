import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, linkedSignal, output, signal } from '@angular/core';
import { FormField, form, maxLength, required, validate } from '@angular/forms/signals';
import { SEVERITY_META, STATUS_META } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  DISMISSED_STATUSES,
  FINDING_STATUSES,
  Finding,
  FindingDecision,
  FindingStatus,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
  TicketKind,
  plainAcceptance,
} from '../../../core/models/api.models';
import { TriageChange } from '../../../core/services/triage.service';
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

/** Severity raised by an analyst, with its justification. */
interface SeverityFormModel {
  severity: Severity;
  reason: string;
}

/** YYYY-MM-DD of today plus ``days``, in UTC like the server. */
function isoDay(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

/**
 * One finding: description, evidence and recommendation, with a status select for triagers.
 * Accepting a risk asks for a reason and an expiry date (none when ``permanentAcceptance`` is
 * set), except a risk less severe than ``riskAcceptanceMinSeverity``, accepted at once like a
 * fix; marking a false positive asks for a reason only, with no expiry date. A status
 * proposed by an agent is shown apart, for the triager to apply or reject. A triager (a security
 * analyst) may also raise the severity, with a justification, never below the report's one.
 * Extra details (report link...) can be projected at the end of the metadata line.
 *
 * The card only shows and asks: the page saves the decision it emits (see TriageService) and
 * passes the saved finding back, which closes the form. Likewise, it shows the tickets of the
 * finding and offers to send it to the systems of ``ticketKinds`` (see TicketService).
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
  /** Lowest severity whose acceptance needs a reason and an expiry date (null: every one). */
  readonly riskAcceptanceMinSeverity = input<Severity | null>(null);
  /** A decision on this finding is being saved. */
  readonly saving = input(false);
  /** Ticketing systems the user may send this finding to (its project has a destination). */
  readonly ticketKinds = input<readonly TicketKind[]>([]);
  /** The finding is being sent to a ticketing system. */
  readonly ticketSending = input(false);
  /** Names of the ticketing systems by kind (a ticket of an unknown kind shows its kind). */
  readonly ticketSystemNames = input<ReadonlyMap<string, string>>(new Map());

  /** A triage decision (status or raised severity) to save. */
  readonly decided = output<TriageChange>();
  /** The status proposed by an agent is rejected. */
  readonly proposalRejected = output<void>();
  /** Send the finding to a ticketing system. */
  readonly ticketRequested = output<TicketKind>();

  readonly statuses = FINDING_STATUSES;
  readonly statusMeta = STATUS_META;
  readonly severityMeta = SEVERITY_META;

  /** Name of a ticketing system. */
  systemName(kind: TicketKind): string {
    return this.ticketSystemNames().get(kind) ?? kind;
  }

  /** Systems offered: those without a ticket for this finding yet. */
  readonly sendableKinds = computed(() => {
    const sent = new Set(
      this.finding()
        .tickets.filter((t) => t.state === 'sent')
        .map((t) => t.kind),
    );
    return this.ticketKinds().filter((kind) => !sent.has(kind));
  });

  /** Severity form open (closed when the page passes the saved finding back). */
  readonly severityOpen = linkedSignal<Finding, boolean>({
    source: this.finding,
    computation: () => false,
  });
  readonly severityModel = signal<SeverityFormModel>({ severity: 'critical', reason: '' });
  readonly severityForm = form(this.severityModel, (path) => {
    validate(path.reason, ({ value }) =>
      value().trim().length < MIN_REASON_CHARS
        ? { kind: 'minLength', message: this.i18n.translate('report.severityReasonHelp') }
        : undefined,
    );
    maxLength(path.reason, MAX_REASON_CHARS);
    validate(path.severity, ({ value }) =>
      value() === this.finding().severity
        ? { kind: 'unchanged', message: this.i18n.translate('report.severityHelp') }
        : undefined,
    );
  });

  /** Severity given by the report: the floor of an escalation. */
  readonly reportSeverity = computed(
    () => this.finding().original_severity ?? this.finding().severity,
  );

  /** Severities an analyst may choose: the report's one (undo) and every higher one. */
  readonly raisableSeverities = computed(() =>
    SEVERITIES.filter((s) => SEVERITY_RANK[s] >= SEVERITY_RANK[this.reportSeverity()]),
  );

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

  /** Accepting this risk is a plain validation, saved at once with no reason and no expiry. */
  readonly plainAcceptance = computed(() =>
    plainAcceptance(this.finding().severity, this.riskAcceptanceMinSeverity()),
  );

  /** A false positive states a fact about the code: it is saved with no expiry date. */
  readonly expiryAsked = computed(() => this.pendingStatus() !== 'false_positive');

  /** The decision being made has no expiry date. */
  readonly withoutExpiry = computed(
    () => !this.expiryAsked() || (this.noExpiryOffered() && this.dismissalModel().noExpiry),
  );

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

  /**
   * Status select: open, fixed and a plain acceptance are saved at once, a dismissal opens the
   * form.
   */
  changeStatus(event: Event): void {
    const finding = this.finding();
    const select = event.target as HTMLSelectElement;
    const status = select.value as FindingStatus;
    // The select keeps showing the stored status until a decision is saved
    select.value = finding.status;
    if (status === finding.status) {
      return;
    }
    this.decide(status);
  }

  /** Open the reason and expiry form for an acceptance or a false positive. */
  openDismissal(status: FindingStatus): void {
    this.dismissalForm().reset(newDismissal());
    this.severityOpen.set(false);
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

  /** Open the severity form on the next severity above the current one. */
  openSeverity(): void {
    const current = this.finding().severity;
    const higher = SEVERITIES.filter((s) => SEVERITY_RANK[s] > SEVERITY_RANK[current]);
    this.severityForm().reset({ severity: higher.at(-1) ?? current, reason: '' });
    this.pendingStatus.set(null);
    this.severityOpen.set(true);
  }

  cancelSeverity(): void {
    this.severityOpen.set(false);
  }

  submitSeverity(event: Event): void {
    event.preventDefault();
    if (this.severityForm().invalid()) {
      this.severityForm().markAsTouched();
      return;
    }
    const { severity, reason } = this.severityModel();
    this.decided.emit({ severity, reason: reason.trim() });
  }

  /** Apply the status proposed by an agent: a dismissal still needs the triager's reason. */
  applyProposal(): void {
    const proposed = this.finding().proposed_status;
    if (!proposed) {
      return;
    }
    this.decide(proposed);
  }

  rejectProposal(): void {
    this.proposalRejected.emit();
  }

  /** Save ``status`` at once, or open the form when it needs a reason and an expiry. */
  private decide(status: FindingStatus): void {
    const plain = status === 'accepted' && this.plainAcceptance();
    if (DISMISSED_STATUSES.includes(status) && !plain) {
      this.openDismissal(status);
    } else {
      this.save({ status });
    }
  }

  private save(decision: FindingDecision): void {
    this.decided.emit(decision);
  }
}

/** Empty reason, default expiry. */
function newDismissal(): DismissalFormModel {
  return { reason: '', expiresOn: isoDay(DEFAULT_DISMISSAL_DAYS), noExpiry: false };
}
