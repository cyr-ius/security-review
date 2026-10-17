import { HttpErrorResponse } from '@angular/common/http';
import { inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { ApiService } from '../../core/services/api.service';

/**
 * Common part of the three administrator settings pages (report language, outgoing proxy,
 * OSV database): stored settings, outcome messages and the run helper.
 */
export abstract class SettingsPage {
  protected readonly api = inject(ApiService);
  protected readonly i18n = inject(I18nService);

  readonly settings = rxResource({ stream: () => this.api.appSettings() });

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  reload(): void {
    this.settings.reload();
  }

  /** Value of the input or select that sent an event. */
  inputValue(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  /** Run an action, show its outcome and refresh the page. */
  protected async run(action: () => Promise<unknown>, success: Message): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
      this.message.set(success);
      this.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && (error.status === 409 || error.status === 422)) {
    const detail = error.error?.detail;
    if (typeof detail === 'string') {
      return translateDetail(detail);
    }
    return msg('settings.refused');
  }
  return msg('settings.failed');
}

/** Translated message for the known errors of the API (the server answers in English). */
function translateDetail(detail: string): Message {
  if (detail.includes('SECREVIEW_OSV_AUTO_UPDATE')) {
    return msg('settings.osvDisabled');
  }
  if (detail.includes('already running')) {
    return msg('settings.alreadyRunning');
  }
  if (detail.includes('password again')) {
    return msg('settings.passwordAgain');
  }
  return msg('settings.refusedDetail', { detail });
}
