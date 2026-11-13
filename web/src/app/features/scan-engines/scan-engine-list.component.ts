import { DatePipe } from '@angular/common';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ScanEngine, ScanEngineList } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { HelpLinkComponent } from '../../shared/components/help-link/help-link.component';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import { describeError } from '../settings/settings-page';
import { ScanEngineFlowComponent } from './scan-engine-flow/scan-engine-flow.component';

/** Frequent refresh keeps short-running scans visible in the activity diagram. */
const REFRESH_MS = 2_000;

/**
 * Activity page (settings.manage): the activity diagram of the agents, pipelines, MCP and
 * Controller servers and scan engines, then the engines enrolled with the shared secret, with
 * their version, address and last activity, each one revocable (its access token stops working).
 * It links to the audit log, out of the menu for its users. The page reloads itself while it is
 * visible.
 */
@Component({
  selector: 'app-scan-engine-list',
  imports: [
    DatePipe,
    HelpLinkComponent,
    RefreshButtonComponent,
    RouterLink,
    ScanEngineFlowComponent,
    TranslatePipe,
  ],
  templateUrl: './scan-engine-list.component.html',
})
export class ScanEngineListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  /** The Audit log button: the page is out of the menu for those who can open this one. */
  readonly canReadAudit = inject(AuthService).can('audit.read');

  readonly engineList = signal<ScanEngineList | null>(null);
  readonly initialLoading = signal(true);
  readonly manualRefreshing = signal(false);
  readonly loadError = signal(false);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);
  private autoRefreshing = false;
  private requestVersion = 0;

  private readonly ticker = setInterval(() => {
    if (!document.hidden) {
      void this.loadEngines('automatic');
    }
  }, REFRESH_MS);

  constructor() {
    inject(DestroyRef).onDestroy(() => clearInterval(this.ticker));
    void this.loadEngines('initial');
  }

  async refresh(): Promise<void> {
    if (this.manualRefreshing()) {
      return;
    }
    this.manualRefreshing.set(true);
    this.error.set(null);
    await this.loadEngines('manual');
  }

  /**
   * Load the engines. An automatic reload is skipped while another one runs; a forced one (after
   * an action) never is, and its newer requestVersion discards the answer of a reload in flight,
   * which may predate the action.
   */
  private async loadEngines(source: 'initial' | 'manual' | 'automatic' | 'forced'): Promise<void> {
    if (source === 'automatic' && this.autoRefreshing) {
      return;
    }
    if (source === 'automatic') {
      this.autoRefreshing = true;
    }
    const requestVersion = ++this.requestVersion;
    try {
      const engines = await firstValueFrom(this.api.scanEngines());
      if (requestVersion === this.requestVersion) {
        this.engineList.set(engines);
        this.loadError.set(false);
      }
    } catch (error: unknown) {
      if (requestVersion === this.requestVersion) {
        if (!this.engineList()) {
          this.loadError.set(true);
        }
        if (source === 'manual') {
          this.error.set(describeError(error));
        }
      }
    } finally {
      if (source === 'initial') {
        this.initialLoading.set(false);
      } else if (source === 'manual') {
        this.manualRefreshing.set(false);
      } else if (source === 'automatic') {
        this.autoRefreshing = false;
      }
    }
  }

  async revoke(engine: ScanEngine): Promise<void> {
    const name = engine.name;
    if (
      this.busy() ||
      !window.confirm(this.i18n.translate('scanEngines.confirmRevoke', { name }))
    ) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.revokeScanEngine(engine.id));
      this.message.set(msg('scanEngines.revoked', { name }));
      void this.loadEngines('forced');
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}
