import { Component, computed, inject, input, output, signal } from '@angular/core';
import { FormField, form, maxLength, required, validate } from '@angular/forms/signals';
import { STATUS_META } from '../../../../core/constants/labels';
import { I18nService } from '../../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../../core/i18n/translate.pipe';
import {
  FINDING_STATUSES,
  Finding,
  FindingDecision,
  FindingStatus,
  Severity,
  plainAcceptance,
} from '../../../../core/models/api.models';

/** Default validity of an acceptance, in days (the server caps it). */
const DEFAULT_DISMISSAL_DAYS = 90;
/** Shortest reason of an acceptance (services.MIN_STATUS_REASON_CHARS). */
const MIN_REASON_CHARS = 10;
/** Longest reason accepted by the server (models.MAX_STATUS_REASON_CHARS). */
const MAX_REASON_CHARS = 1000;
/** Most findings of one decision accepted by the server (services.MAX_BULK_FINDINGS). */
const MAX_BULK_FINDINGS = 1000;

/** One decision for every selected finding. */
interface BulkFormModel {
  status: FindingStatus;
  reason: string;
  expiresOn: string;
  /** Acceptance without an expiry date (offered while the server allows it). */
  noExpiry: boolean;
}

/** YYYY-MM-DD of today plus ``days``, in UTC like the server. */
function isoDay(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

function newModel(): BulkFormModel {
  return {
    status: 'fixed',
    reason: '',
    expiresOn: isoDay(DEFAULT_DISMISSAL_DAYS),
    noExpiry: false,
  };
}

/**
 * Bar of the findings page that records one triage decision for every selected finding (all
 * or nothing on the server). It asks what a finding card asks: a reason and an expiry date to
 * accept a risk, when one of the selected findings needs a formal acceptance; an optional reason
 * for a false positive; nothing for fixed or open. It only asks: the page saves the decision.
 */
@Component({
  selector: 'app-bulk-triage',
  imports: [FormField, TranslatePipe],
  templateUrl: './bulk-triage.component.html',
})
export class BulkTriageComponent {
  private readonly i18n = inject(I18nService);

  /** Selected findings. */
  readonly findings = input.required<readonly Finding[]>();
  /** A risk may be accepted without an expiry date (server setting). */
  readonly permanentAcceptance = input(false);
  /** Lowest severity whose acceptance needs a reason and an expiry date (null: every one). */
  readonly riskAcceptanceMinSeverity = input<Severity | null>(null);
  /** The decision is being saved. */
  readonly saving = input(false);

  /** The decision to save for every selected finding. */
  readonly decided = output<FindingDecision>();
  /** Clear the selection. */
  readonly cleared = output<void>();

  readonly statuses = FINDING_STATUSES;
  readonly statusMeta = STATUS_META;
  readonly minExpiry = isoDay(1);
  readonly maxFindings = MAX_BULK_FINDINGS;

  /** More findings are selected than one decision accepts. */
  readonly tooMany = computed(() => this.findings().length > MAX_BULK_FINDINGS);

  readonly model = signal<BulkFormModel>(newModel());
  readonly bulkForm = form(this.model, (path) => {
    validate(path.reason, ({ value }) =>
      this.reasonAsked() &&
      value().trim().length < MIN_REASON_CHARS &&
      (this.reasonRequired() || value().trim())
        ? { kind: 'minLength', message: this.i18n.translate(this.reasonHelp()) }
        : undefined,
    );
    maxLength(path.reason, MAX_REASON_CHARS);
    required(path.expiresOn, { when: () => this.expiryAsked() && !this.withoutExpiry() });
    validate(path.expiresOn, ({ value }) =>
      this.expiryAsked() && !this.withoutExpiry() && value() && value() < this.minExpiry
        ? { kind: 'minDate', message: this.i18n.translate('report.dismissExpiryHelp') }
        : undefined,
    );
  });

  /** Accepting needs a reason and an expiry: one selected finding is too severe for less. */
  private readonly formalAcceptance = computed(
    () =>
      this.model().status === 'accepted' &&
      this.findings().some((f) => !plainAcceptance(f.severity, this.riskAcceptanceMinSeverity())),
  );

  /** A reason is asked for a formal acceptance and (optional) for a false positive. */
  readonly reasonAsked = computed(
    () => this.formalAcceptance() || this.model().status === 'false_positive',
  );
  readonly reasonRequired = computed(() => this.formalAcceptance());
  readonly reasonHelp = computed(() =>
    this.reasonRequired() ? 'report.dismissReasonHelp' : 'report.dismissReasonOptionalHelp',
  );

  /** Only a formal acceptance has an expiry date. */
  readonly expiryAsked = computed(() => this.formalAcceptance());
  readonly withoutExpiry = computed(() => this.permanentAcceptance() && this.model().noExpiry);

  submit(event: Event): void {
    event.preventDefault();
    if (!this.findings().length || this.tooMany() || this.bulkForm().invalid()) {
      this.bulkForm().markAsTouched();
      return;
    }
    const { status, reason, expiresOn } = this.model();
    const decision: FindingDecision = { status };
    if (this.reasonAsked() && reason.trim()) {
      decision.reason = reason.trim();
    }
    if (this.expiryAsked()) {
      decision.expires_on = this.withoutExpiry() ? null : expiresOn;
    }
    this.decided.emit(decision);
  }

  /** Start again from an empty decision (after a save). */
  reset(): void {
    this.bulkForm().reset(newModel());
  }
}
