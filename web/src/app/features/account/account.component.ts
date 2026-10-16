import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ROLE_META } from '../../core/constants/labels';
import { MIN_PASSWORD_CHARS } from '../../core/constants/passwords';
import { Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

/**
 * Account page: who is logged in and, for a web user, the change of its own password (the
 * other sessions of the user end, this tab gets a new session).
 */
@Component({
  selector: 'app-account',
  imports: [TranslatePipe],
  templateUrl: './account.component.html',
})
export class AccountComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);

  readonly minPassword = MIN_PASSWORD_CHARS;
  readonly role = computed(() => ROLE_META[this.auth.identity()?.role ?? 'reader']);

  readonly current = signal('');
  readonly next = signal('');
  readonly confirmation = signal('');
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  readonly mismatch = computed(
    () => this.confirmation().length > 0 && this.confirmation() !== this.next(),
  );

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      this.current().length > 0 &&
      this.next().length >= MIN_PASSWORD_CHARS &&
      this.next() === this.confirmation(),
  );

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      const login = await firstValueFrom(this.api.changePassword(this.current(), this.next()));
      // The previous session is no longer valid: keep working with the new one
      this.auth.login(login.session);
      this.current.set('');
      this.next.set('');
      this.confirmation.set('');
      this.message.set(msg('account.changed'));
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

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
