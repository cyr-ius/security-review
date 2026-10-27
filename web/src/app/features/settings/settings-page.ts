import { HttpErrorResponse } from '@angular/common/http';
import { afterRenderEffect, inject, signal } from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { ApiService } from '../../core/services/api.service';
import { ControllerUrlService } from '../../core/services/controller-url.service';

/**
 * Common part of the administrator settings pages (general, OSV database):
 * stored settings, outcome messages and the run helper.
 */
export abstract class SettingsPage {
  protected readonly api = inject(ApiService);
  protected readonly i18n = inject(I18nService);
  private readonly controllerUrl = inject(ControllerUrlService);

  readonly settings = rxResource({ stream: () => this.api.appSettings() });

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Section a link points to (``#controller-url`` from the banner of the shell). */
  private readonly fragment = toSignal(inject(ActivatedRoute).fragment);
  /** Section already scrolled to: a later reload does not move the page again. */
  private scrolledTo: string | null = null;

  constructor() {
    // The sections are rendered once the settings arrive, after the navigation
    afterRenderEffect(() => {
      const id = this.fragment();
      if (!id || id === this.scrolledTo || !this.settings.hasValue()) {
        return;
      }
      const section = document.getElementById(id);
      if (section) {
        section.scrollIntoView({ block: 'start' });
        this.scrolledTo = id;
      }
    });
  }

  reload(): void {
    this.settings.reload();
    // The banner of the shell follows the stored URL
    this.controllerUrl.reload();
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

/** Message of a failed settings request (the API detail of a refusal, translated if known). */
export function describeError(error: unknown): Message {
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
