import { DatePipe, DecimalPipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import {
  AdvisoryEcosystemResult,
  AdvisoryUpdate,
  AppSettings,
  ProxyUpdate,
} from '../../core/models/api.models';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/** How the report language is chosen in the form. */
type LanguageMode = 'inherit' | 'agent' | 'custom';

/** How the proxy URL is chosen: variable, set here, or direct connection. */
type ProxyMode = 'env' | 'custom' | 'none';

/** Delay between two refreshes of the OSV history while an update runs. */
const POLL_MS = 5000;

/** Same rule as the server: a language name or code, nothing that could carry instructions. */
const LANGUAGE_PATTERN = /^[\p{L} \-_()]{0,40}$/u;

export const UPDATE_STATUS_META: Record<
  AdvisoryUpdate['status'],
  { label: MessageKey; css: string }
> = {
  running: { label: 'settings.statusRunning', css: 'text-bg-info' },
  success: { label: 'settings.statusSuccess', css: 'text-bg-success' },
  partial: { label: 'settings.statusPartial', css: 'text-bg-warning' },
  failed: { label: 'settings.statusFailed', css: 'text-bg-danger' },
  interrupted: { label: 'settings.statusInterrupted', css: 'text-bg-secondary' },
};

export const TRIGGER_LABELS: Record<AdvisoryUpdate['trigger'], MessageKey> = {
  schedule: 'settings.triggerSchedule',
  cli: 'settings.triggerCli',
  web: 'sso.webInterface',
};

const PROXY_SOURCE_LABELS: Record<AppSettings['proxy']['effective']['source'], MessageKey> = {
  web: 'settings.sourceWeb',
  none: 'settings.sourceNone',
  SECREVIEW_PROXY: 'settings.sourceVariable',
  environment: 'settings.sourceEnvironment',
};

/**
 * Administrator page: language of the review reports, proxy of the outgoing connections of the
 * controller (OSV download and SSO provider; each value set here overrides its variable), state
 * of the advisory database, history of its updates and manual update.
 */
@Component({
  selector: 'app-settings',
  imports: [DatePipe, DecimalPipe, RefreshButtonComponent, TranslatePipe],
  templateUrl: './settings.component.html',
  styleUrl: './settings.component.css',
})
export class SettingsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly settings = rxResource({ stream: () => this.api.appSettings() });
  readonly advisories = rxResource({ stream: () => this.api.advisories() });

  readonly languageMode = signal<LanguageMode>('inherit');
  readonly language = signal('');
  readonly proxyMode = signal<ProxyMode>('env');
  readonly proxyUrl = signal('');
  /** The no_proxy list follows SECREVIEW_NO_PROXY (false) or is set here (true). */
  readonly noProxyCustom = signal(false);
  readonly noProxy = signal('');

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  readonly statusMeta = UPDATE_STATUS_META;
  readonly triggerLabels = TRIGGER_LABELS;
  readonly languageSuggestions = [
    'French',
    'English',
    'German',
    'Spanish',
    'Italian',
    'Portuguese',
  ];

  readonly languageValid = computed(
    () => this.languageMode() !== 'custom' || LANGUAGE_PATTERN.test(this.language().trim()),
  );

  readonly proxySource = computed(() => {
    const source = this.settings.value()?.proxy.effective.source;
    return source ? PROXY_SOURCE_LABELS[source] : null;
  });

  readonly ecosystems = computed(() =>
    Object.entries(this.advisories.value()?.database.by_ecosystem ?? {}).sort(([a], [b]) =>
      a.localeCompare(b),
    ),
  );

  private pollTimer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    // Fill the forms with the stored values each time they are loaded
    effect(() => {
      const value = this.settings.value();
      if (!value) {
        return;
      }
      const stored = value.report_language.value;
      this.languageMode.set(stored === null ? 'inherit' : stored === '' ? 'agent' : 'custom');
      this.language.set(stored ?? '');
      const url = value.proxy.url.value;
      this.proxyMode.set(url === null ? 'env' : url === '' ? 'none' : 'custom');
      this.proxyUrl.set(url ?? '');
      this.noProxyCustom.set(value.proxy.no_proxy.value !== null);
      this.noProxy.set(value.proxy.no_proxy.value ?? value.proxy.no_proxy.env ?? '');
    });
    // Follow an update in progress until it finishes
    effect(() => {
      clearTimeout(this.pollTimer);
      if (this.advisories.value()?.running) {
        this.pollTimer = setTimeout(() => this.advisories.reload(), POLL_MS);
      }
    });
    inject(DestroyRef).onDestroy(() => clearTimeout(this.pollTimer));
  }

  reload(): void {
    this.settings.reload();
    this.advisories.reload();
  }

  onLanguageMode(event: Event): void {
    this.languageMode.set((event.target as HTMLSelectElement).value as LanguageMode);
  }

  /** Value of the input or select that sent an event. */
  inputValue(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  /** State of the checkbox that sent an event. */
  checkedValue(event: Event): boolean {
    return (event.target as HTMLInputElement).checked;
  }

  onProxyMode(mode: ProxyMode): void {
    this.proxyMode.set(mode);
  }

  async saveLanguage(event: Event): Promise<void> {
    event.preventDefault();
    const mode = this.languageMode();
    const value = mode === 'inherit' ? null : mode === 'agent' ? '' : this.language().trim();
    if (mode === 'custom' && (!value || !this.languageValid())) {
      this.error.set(msg('settings.languageMissing'));
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(value)),
      msg('settings.languageSaved'),
    );
  }

  async saveProxy(event: Event): Promise<void> {
    event.preventDefault();
    const mode = this.proxyMode();
    const url = this.proxyUrl().trim();
    if (mode === 'custom' && !url) {
      this.error.set(msg('settings.proxyMissing'));
      return;
    }
    const values: ProxyUpdate = {
      url: mode === 'env' ? null : mode === 'none' ? '' : url,
      no_proxy: this.noProxyCustom() ? this.noProxy().trim() : null,
    };
    await this.run(() => firstValueFrom(this.api.setProxy(values)), msg('settings.proxySaved'));
  }

  async startUpdate(): Promise<void> {
    if (this.busy() || !window.confirm(this.i18n.translate('settings.confirmUpdate'))) {
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.startAdvisoryUpdate()),
      msg('settings.updateStarted'),
    );
  }

  /** Imported advisories, or the error, of each ecosystem of an update. */
  outcome(update: AdvisoryUpdate): { name: string; text: string; failed: boolean }[] {
    return Object.entries(update.results).map(([name, result]) => {
      if (typeof result === 'string') {
        return { name: this.i18n.translate('settings.error'), text: result, failed: true };
      }
      const stats = result as AdvisoryEcosystemResult;
      return stats.error
        ? { name, text: stats.error, failed: true }
        : {
            name,
            text: this.i18n.translate('settings.imported', { count: stats.imported ?? 0 }),
            failed: false,
          };
    });
  }

  /** Duration of a finished update, in a short human form. */
  duration(update: AdvisoryUpdate): string {
    if (!update.finished_at) {
      return '—';
    }
    const seconds = Math.round(
      (Date.parse(update.finished_at) - Date.parse(update.started_at)) / 1000,
    );
    return seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
  }

  /** Run an action, show its outcome and refresh the page. */
  private async run(action: () => Promise<unknown>, success: Message): Promise<void> {
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
