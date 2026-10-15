import { DatePipe, DecimalPipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import {
  AdvisoryEcosystemResult,
  AdvisoryUpdate,
  AppSettings,
  ProxyMode,
} from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/** How the report language is chosen in the form. */
type LanguageMode = 'inherit' | 'agent' | 'custom';

/** Delay between two refreshes of the OSV history while an update runs. */
const POLL_MS = 5000;

/** Same rule as the server: a language name or code, nothing that could carry instructions. */
const LANGUAGE_PATTERN = /^[\p{L} \-_()]{0,40}$/u;

export const UPDATE_STATUS_META: Record<AdvisoryUpdate['status'], { label: string; css: string }> =
  {
    running: { label: 'En cours', css: 'text-bg-info' },
    success: { label: 'Réussie', css: 'text-bg-success' },
    partial: { label: 'Partielle', css: 'text-bg-warning' },
    failed: { label: 'Échec', css: 'text-bg-danger' },
    interrupted: { label: 'Interrompue', css: 'text-bg-secondary' },
  };

export const TRIGGER_LABELS: Record<AdvisoryUpdate['trigger'], string> = {
  schedule: 'Planifiée',
  cli: 'CLI',
  web: 'Interface web',
};

const PROXY_SOURCE_LABELS: Record<AppSettings['osv_proxy']['effective']['source'], string> = {
  web: 'interface web',
  none: 'connexion directe (interface web)',
  SECREVIEW_OSV_PROXY: 'variable SECREVIEW_OSV_PROXY',
  environment: 'variables HTTPS_PROXY / NO_PROXY',
};

/**
 * Administrator page: language of the review reports, proxy of the OSV download (or the one of
 * the environment), state of the advisory database, history of its updates and manual update.
 */
@Component({
  selector: 'app-settings',
  imports: [DatePipe, DecimalPipe, RefreshButtonComponent],
  templateUrl: './settings.component.html',
  styleUrl: './settings.component.css',
})
export class SettingsComponent {
  private readonly api = inject(ApiService);

  readonly settings = rxResource({ stream: () => this.api.appSettings() });
  readonly advisories = rxResource({ stream: () => this.api.advisories() });

  readonly languageMode = signal<LanguageMode>('inherit');
  readonly language = signal('');
  readonly proxyMode = signal<ProxyMode>('env');
  readonly proxyUrl = signal('');

  readonly message = signal<string | null>(null);
  readonly error = signal<string | null>(null);
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
    const source = this.settings.value()?.osv_proxy.effective.source;
    return source ? PROXY_SOURCE_LABELS[source] : '';
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
      this.proxyMode.set(value.osv_proxy.mode);
      this.proxyUrl.set(value.osv_proxy.url ?? '');
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

  onProxyMode(mode: ProxyMode): void {
    this.proxyMode.set(mode);
  }

  async saveLanguage(event: Event): Promise<void> {
    event.preventDefault();
    const mode = this.languageMode();
    const value = mode === 'inherit' ? null : mode === 'agent' ? '' : this.language().trim();
    if (mode === 'custom' && (!value || !this.languageValid())) {
      this.error.set('Indiquez un nom ou un code de langue (par exemple French, fr ou pt-BR).');
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(value)),
      'Langue des rapports enregistrée : elle s’applique aux prochains prompts de revue.',
    );
  }

  async saveProxy(event: Event): Promise<void> {
    event.preventDefault();
    const mode = this.proxyMode();
    const url = mode === 'custom' ? this.proxyUrl().trim() : null;
    if (mode === 'custom' && !url) {
      this.error.set('Indiquez l’URL du proxy (http://[utilisateur:mot de passe@]hôte:port).');
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.setOsvProxy(mode, url)),
      'Proxy enregistré : il s’applique au prochain téléchargement OSV.',
    );
  }

  async startUpdate(): Promise<void> {
    if (
      this.busy() ||
      !window.confirm(
        'Télécharger maintenant les avis OSV ? L’opération peut prendre plusieurs minutes.',
      )
    ) {
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.startAdvisoryUpdate()),
      'Mise à jour lancée. L’historique se rafraîchit jusqu’à la fin du téléchargement.',
    );
  }

  /** Imported advisories, or the error, of each ecosystem of an update. */
  outcome(update: AdvisoryUpdate): { name: string; text: string; failed: boolean }[] {
    return Object.entries(update.results).map(([name, result]) => {
      if (typeof result === 'string') {
        return { name: 'Erreur', text: result, failed: true };
      }
      const stats = result as AdvisoryEcosystemResult;
      return stats.error
        ? { name, text: stats.error, failed: true }
        : { name, text: `${stats.imported ?? 0} avis importés`, failed: false };
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
  private async run(action: () => Promise<unknown>, success: string): Promise<void> {
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

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse && (error.status === 409 || error.status === 422)) {
    const detail = error.error?.detail;
    if (typeof detail === 'string') {
      return translateDetail(detail);
    }
    return 'Valeur refusée par le serveur.';
  }
  return 'L’opération a échoué.';
}

/** French message for the known errors of the API (the server answers in English). */
function translateDetail(detail: string): string {
  if (detail.includes('SECREVIEW_OSV_AUTO_UPDATE')) {
    return 'Le téléchargement OSV est désactivé sur ce contrôleur (SECREVIEW_OSV_AUTO_UPDATE=false).';
  }
  if (detail.includes('already running')) {
    return 'Une mise à jour OSV est déjà en cours.';
  }
  if (detail.includes('password again')) {
    return 'Saisissez de nouveau le mot de passe du proxy (l’hôte ou l’utilisateur a changé).';
  }
  return `Valeur refusée : ${detail}`;
}
