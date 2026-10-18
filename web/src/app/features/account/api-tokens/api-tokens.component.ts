import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';

/**
 * API tokens of the logged-in user (My account): personal tokens for the REST API and its
 * Swagger, which hold the current rights of the user. The secret is shown once.
 */
@Component({
  selector: 'app-api-tokens',
  imports: [DatePipe, FormField, TranslatePipe],
  templateUrl: './api-tokens.component.html',
  styleUrl: './api-tokens.component.css',
})
export class ApiTokensComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly tokens = rxResource({ stream: () => this.api.myTokens() });
  readonly model = signal<ApiTokenFormModel>({ ...EMPTY_FORM });
  readonly tokenForm = form(this.model, (path) => {
    required(path.label, { message: () => this.i18n.translate('tokens.labelRequired') });
    maxLength(path.label, 64);
  });
  readonly validities = VALIDITY_DAYS;
  readonly createdToken = signal<string | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  async create(event: Event): Promise<void> {
    event.preventDefault();
    const { label, validity } = this.model();
    if (this.tokenForm().invalid() || !label.trim() || this.busy()) {
      this.tokenForm().markAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      const created = await firstValueFrom(
        this.api.createMyToken(label.trim(), validity ? Number(validity) : null),
      );
      this.createdToken.set(created.token);
      this.tokenForm().reset({ ...EMPTY_FORM });
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  async copyToken(): Promise<void> {
    const token = this.createdToken();
    if (!token) {
      return;
    }
    try {
      await navigator.clipboard.writeText(token);
      this.message.set(msg('tokens.copied'));
    } catch {
      this.error.set(msg('tokens.copyFailed'));
    }
  }

  async revoke(id: string, label: string): Promise<void> {
    if (this.busy() || !window.confirm(this.i18n.translate('tokens.confirmRevoke', { label }))) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.deleteMyToken(id));
      this.createdToken.set(null);
      this.message.set(msg('tokens.revoked', { label }));
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

/** Fields of the creation form. */
interface ApiTokenFormModel {
  label: string;
  /** Validity in days; '': the default of the server (SECREVIEW_TOKEN_MAX_DAYS). */
  validity: string;
}

const EMPTY_FORM: ApiTokenFormModel = { label: '', validity: '' };

/** Validities offered at creation, in days. */
const VALIDITY_DAYS: readonly string[] = ['30', '90', '180', '365'];

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && error.status === 422) {
    return typeof error.error?.detail === 'string'
      ? msg('tokens.refusedDetail', { detail: error.error.detail })
      : msg('tokens.failed');
  }
  return msg('tokens.failed');
}
