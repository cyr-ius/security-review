import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { FormField, form, maxLength, required, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { ROLE_META } from '../../../core/constants/labels';
import { MAX_PASSWORD_CHARS, followsPasswordPolicy } from '../../../core/constants/passwords';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { PasswordPolicyComponent } from '../../../shared/components/password-policy/password-policy.component';
import { describeGrants } from '../../../shared/utils/permission-utils';
import { ApiTokensComponent } from '../api-tokens/api-tokens.component';
import { OAuthGrantsComponent } from '../oauth-grants/oauth-grants.component';

/**
 * Account page: who is logged in and, for a web user, the change of its own password (the
 * other sessions of the user end, this tab gets a new session) and its API tokens.
 */
@Component({
  selector: 'app-account',
  imports: [
    ApiTokensComponent,
    FormField,
    OAuthGrantsComponent,
    PasswordPolicyComponent,
    TranslatePipe,
  ],
  templateUrl: './account.component.html',
})
export class AccountComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);

  readonly role = computed(() => ROLE_META[this.auth.identity()?.role ?? 'user']);
  /** Permissions of the caller, with their projects. */
  readonly permissions = computed(() =>
    describeGrants(this.auth.identity()?.permissions ?? {}, this.i18n),
  );

  readonly passwordModel = signal<PasswordFormModel>({ ...EMPTY_PASSWORDS });
  readonly passwordForm = form(this.passwordModel, (path) => {
    required(path.current);
    maxLength(path.current, MAX_PASSWORD_CHARS);
    required(path.next);
    // The rules are listed under the field (app-password-policy); the controller checks them again
    validate(path.next, ({ value }) =>
      followsPasswordPolicy(value())
        ? undefined
        : { kind: 'policy', message: this.i18n.translate('password.policy') },
    );
    // Shown as soon as the confirmation is typed, not only once the field is left
    validate(path.confirmation, ({ value, valueOf }) =>
      value() !== valueOf(path.next)
        ? { kind: 'mismatch', message: this.i18n.translate('account.mismatch') }
        : undefined,
    );
  });
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  readonly mismatch = computed(
    () =>
      this.passwordModel().confirmation.length > 0 && this.passwordForm.confirmation().invalid(),
  );

  readonly canSubmit = computed(() => !this.busy() && this.passwordForm().valid());

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    const { current, next } = this.passwordModel();
    try {
      const login = await firstValueFrom(this.api.changePassword(current, next));
      // The previous session is no longer valid: keep working with the new one
      this.auth.login(login.session);
      // The other pages open again once a required change is done
      this.auth.setIdentity(await firstValueFrom(this.api.me()));
      this.passwordForm().reset({ ...EMPTY_PASSWORDS });
      this.message.set(msg('account.changed'));
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

/** Fields of the password change form. */
interface PasswordFormModel {
  current: string;
  next: string;
  confirmation: string;
}

const EMPTY_PASSWORDS: PasswordFormModel = { current: '', next: '', confirmation: '' };

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse) {
    const detail = typeof error.error?.detail === 'string' ? error.error.detail : '';
    if (error.status === 422 && detail.includes('current password')) {
      return msg('account.wrongCurrent');
    }
    if (error.status === 422 && detail.includes('must differ')) {
      return msg('account.mustDiffer');
    }
    if (error.status === 422) {
      return detail ? msg('account.refusedDetail', { detail }) : msg('account.refused');
    }
    if (error.status === 429) {
      return msg('login.tooManyAttempts');
    }
  }
  return msg('account.failed');
}
