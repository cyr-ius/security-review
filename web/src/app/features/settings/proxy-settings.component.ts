import { Component, computed, effect, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { AppSettings, ProxyUpdate } from '../../core/models/api.models';
import { msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from './settings-page';

/** How the proxy URL is chosen: variable, set here, or direct connection. */
type ProxyMode = 'env' | 'custom' | 'none';

const PROXY_SOURCE_LABELS: Record<AppSettings['proxy']['effective']['source'], MessageKey> = {
  web: 'settings.sourceWeb',
  none: 'settings.sourceNone',
  SECREVIEW_PROXY: 'settings.sourceVariable',
  environment: 'settings.sourceEnvironment',
};

/**
 * Administrator page: proxy of the outgoing connections of the controller (OSV download and SSO
 * provider); each value set here overrides its variable.
 */
@Component({
  selector: 'app-proxy-settings',
  imports: [RefreshButtonComponent, TranslatePipe],
  templateUrl: './proxy-settings.component.html',
  styleUrl: './settings.css',
})
export class ProxySettingsComponent extends SettingsPage {
  readonly proxyMode = signal<ProxyMode>('env');
  readonly proxyUrl = signal('');
  /** The no_proxy list follows SECREVIEW_NO_PROXY (false) or is set here (true). */
  readonly noProxyCustom = signal(false);
  readonly noProxy = signal('');

  readonly proxySource = computed(() => {
    const source = this.settings.value()?.proxy.effective.source;
    return source ? PROXY_SOURCE_LABELS[source] : null;
  });

  constructor() {
    super();
    // Fill the form with the stored values each time they are loaded
    effect(() => {
      const value = this.settings.value();
      if (!value) {
        return;
      }
      const url = value.proxy.url.value;
      this.proxyMode.set(url === null ? 'env' : url === '' ? 'none' : 'custom');
      this.proxyUrl.set(url ?? '');
      this.noProxyCustom.set(value.proxy.no_proxy.value !== null);
      this.noProxy.set(value.proxy.no_proxy.value ?? value.proxy.no_proxy.env ?? '');
    });
  }

  /** State of the checkbox that sent an event. */
  checkedValue(event: Event): boolean {
    return (event.target as HTMLInputElement).checked;
  }

  onProxyMode(mode: ProxyMode): void {
    this.proxyMode.set(mode);
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
}
