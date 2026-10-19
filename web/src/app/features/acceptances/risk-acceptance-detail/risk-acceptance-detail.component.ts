import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, input, linkedSignal, output, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required, validate } from '@angular/forms/signals';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg, serverDetail } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { Finding, RiskAcceptance } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';

/** Longest comment accepted by the server (models.MAX_COMMENT_CHARS). */
const MAX_COMMENT_CHARS = 2000;

/** New expiry date of the acceptance. */
interface ExpiryFormModel {
  expiresOn: string;
  /** Acceptance without an expiry date (only offered when the server allows it). */
  noExpiry: boolean;
}

/** YYYY-MM-DD of today plus ``days``, in UTC like the server. */
function isoDay(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

/** Message of a refused change: the detail of the server for a 422, else ``fallback``. */
function refusal(error: unknown, fallback: MessageKey): Message {
  return error instanceof HttpErrorResponse &&
    error.status === 422 &&
    typeof error.error?.detail === 'string'
    ? serverDetail(error.error.detail)
    : msg(fallback);
}

/**
 * One risk acceptance: its comments (the first one is the reason of the acceptance), with the forms of a triager to add a comment,
 * change the expiry date or remove the acceptance (the finding is open again). Comments are
 * only added: the server has no route to edit or delete one.
 */
@Component({
  selector: 'app-risk-acceptance-detail',
  imports: [DatePipe, FormField, RouterLink, TranslatePipe],
  templateUrl: './risk-acceptance-detail.component.html',
  styleUrl: './risk-acceptance-detail.component.css',
})
export class RiskAcceptanceDetailComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly acceptance = input.required<RiskAcceptance>();
  /** The user may change the acceptance and comment it (findings.triage). */
  readonly canTriage = input(false);
  /** A risk may be accepted without an expiry date (server setting). */
  readonly permanentAcceptance = input(false);

  /** The acceptance was saved with a new expiry date. */
  readonly changed = output<Finding>();
  /** The acceptance was removed: the finding is open again. */
  readonly removed = output<Finding>();
  /** A comment was added. */
  readonly commented = output<void>();

  /** Reloaded with the acceptance (a refresh of the page gives a new object). */
  readonly comments = rxResource({
    params: () => ({ id: this.acceptance().id, acceptance: this.acceptance() }),
    stream: ({ params }) => this.api.findingComments(params.id),
  });

  readonly saving = signal(false);
  readonly error = linkedSignal<RiskAcceptance, Message | null>({
    source: this.acceptance,
    computation: () => null,
  });
  readonly confirmingRemoval = linkedSignal<RiskAcceptance, boolean>({
    source: this.acceptance,
    computation: () => false,
  });

  readonly commentModel = signal({ body: '' });
  readonly commentForm = form(this.commentModel, (path) => {
    validate(path.body, ({ value }) =>
      value().trim() ? undefined : { kind: 'required', message: '' },
    );
    maxLength(path.body, MAX_COMMENT_CHARS);
  });

  readonly minExpiry = isoDay(1);
  readonly expiryModel = linkedSignal<RiskAcceptance, ExpiryFormModel>({
    source: this.acceptance,
    computation: (acceptance) => ({
      expiresOn: acceptance.status_expires_at?.slice(0, 10) ?? '',
      noExpiry: !acceptance.status_expires_at,
    }),
  });
  readonly expiryForm = form(this.expiryModel, (path) => {
    required(path.expiresOn, { when: () => !this.withoutExpiry() });
    validate(path.expiresOn, ({ value }) =>
      !this.withoutExpiry() && value() && value() < this.minExpiry
        ? { kind: 'minDate', message: this.i18n.translate('report.dismissExpiryHelp') }
        : undefined,
    );
  });

  /** The new expiry has no date: offered while the server allows a permanent acceptance. */
  readonly withoutExpiry = computed(
    () => this.permanentAcceptance() && this.expiryModel().noExpiry,
  );

  /** "file.py:10" */
  readonly location = computed(() => {
    const acceptance = this.acceptance();
    if (!acceptance.file_path) {
      return null;
    }
    return acceptance.line_start
      ? `${acceptance.file_path}:${acceptance.line_start}`
      : acceptance.file_path;
  });

  async addComment(event: Event): Promise<void> {
    event.preventDefault();
    const body = this.commentModel().body.trim();
    if (!body || this.commentForm().invalid()) {
      return;
    }
    await this.run('acceptances.commentFailed', async () => {
      await firstValueFrom(this.api.addFindingComment(this.acceptance().id, body));
      this.commentForm().reset({ body: '' });
      this.comments.reload();
      this.commented.emit();
    });
  }

  async saveExpiry(event: Event): Promise<void> {
    event.preventDefault();
    if (this.expiryForm().invalid()) {
      this.expiryForm().markAsTouched();
      return;
    }
    const acceptance = this.acceptance();
    await this.run('acceptances.expiryFailed', async () => {
      const saved = await firstValueFrom(
        this.api.updateFindingStatus(acceptance.id, {
          status: 'accepted',
          // Same reason: the server adds no comment for a new expiry date alone
          reason: acceptance.status_reason ?? '',
          expires_on: this.withoutExpiry() ? null : this.expiryModel().expiresOn,
        }),
      );
      this.changed.emit(saved);
    });
  }

  async remove(): Promise<void> {
    await this.run('acceptances.removeFailed', async () => {
      const saved = await firstValueFrom(
        this.api.updateFindingStatus(this.acceptance().id, { status: 'open' }),
      );
      this.removed.emit(saved);
    });
  }

  /** Run a change, showing ``failure`` (or the detail of the server) when it is refused. */
  private async run(failure: MessageKey, change: () => Promise<void>): Promise<void> {
    this.saving.set(true);
    this.error.set(null);
    try {
      await change();
    } catch (error: unknown) {
      this.error.set(refusal(error, failure));
    } finally {
      this.saving.set(false);
    }
  }
}
