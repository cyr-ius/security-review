import { Component, computed, linkedSignal } from '@angular/core';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { AppSettings, ProxyUpdate } from '../../../core/models/api.models';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from '../settings-page';

/** How the proxy URL is chosen: variable, set here, or direct connection. */
type ProxyMode = 'env' | 'custom' | 'none';

const PROXY_SOURCE_LABELS: Record<AppSettings['proxy']['effective']['source'], MessageKey> = {
  web: 'settings.sourceWeb',
  none: 'settings.sourceNone',
  SECREVIEW_PROXY: 'settings.sourceVariable',
  environment: 'settings.sourceEnvironment',
};

/** Longest proxy URL or no_proxy list accepted by the server (proxy.MAX_*_CHARS). */
const MAX_PROXY_CHARS = 500;

/** Fields of the proxy form. */
interface ProxyFormModel {
  mode: ProxyMode;
  url: string;
  /** The no_proxy list follows SECREVIEW_NO_PROXY (false) or is set here (true). */
  noProxyCustom: boolean;
  noProxy: string;
}

/**
 * Administrator page: proxy of the outgoing connections of the controller (OSV download and OIDC
 * provider); each value set here overrides its variable.
 */
@Component({
  selector: 'app-proxy-settings',
  imports: [FormField, RefreshButtonComponent, TranslatePipe],
  templateUrl: './proxy-settings.component.html',
  styleUrl: '../settings.css',
})
export class ProxySettingsComponent extends SettingsPage {
  /** Filled with the stored values each time they are loaded, then edited by the form. */
  readonly proxyModel = linkedSignal<ProxyFormModel>(() => {
    const proxy = this.settings.value()?.proxy;
    if (!proxy) {
      return { mode: 'env', url: '', noProxyCustom: false, noProxy: '' };
    }
    const url = proxy.url.value;
    return {
      mode: url === null ? 'env' : url === '' ? 'none' : 'custom',
      url: url ?? '',
      noProxyCustom: proxy.no_proxy.value !== null,
      noProxy: proxy.no_proxy.value ?? proxy.no_proxy.env ?? '',
    };
  });
  readonly proxyForm = form(this.proxyModel, (path) => {
    maxLength(path.url, MAX_PROXY_CHARS);
    maxLength(path.noProxy, MAX_PROXY_CHARS);
  });

  readonly proxySource = computed(() => {
    const source = this.settings.value()?.proxy.effective.source;
    return source ? PROXY_SOURCE_LABELS[source] : null;
  });

  async saveProxy(event: Event): Promise<void> {
    event.preventDefault();
    const model = this.proxyModel();
    const mode = model.mode;
    const url = model.url.trim();
    if (this.proxyForm().invalid() || (mode === 'custom' && !url)) {
      this.error.set(msg('settings.proxyMissing'));
      return;
    }
    const values: ProxyUpdate = {
      url: mode === 'env' ? null : mode === 'none' ? '' : url,
      no_proxy: model.noProxyCustom ? model.noProxy.trim() : null,
    };
    await this.run(() => firstValueFrom(this.api.setProxy(values)), msg('settings.proxySaved'));
  }
}
