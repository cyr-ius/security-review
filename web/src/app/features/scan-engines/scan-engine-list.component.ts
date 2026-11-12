import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ScanEngine } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { HelpLinkComponent } from '../../shared/components/help-link/help-link.component';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import { describeError } from '../settings/settings-page';

/**
 * Scan engines page (settings.manage): the engines enrolled with the shared secret, with their
 * version, address and last activity, each one revocable (its access token stops working).
 */
@Component({
  selector: 'app-scan-engine-list',
  imports: [DatePipe, HelpLinkComponent, RefreshButtonComponent, TranslatePipe],
  templateUrl: './scan-engine-list.component.html',
})
export class ScanEngineListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly engines = rxResource({ stream: () => this.api.scanEngines() });
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

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
      this.engines.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}
