import { NgTemplateOutlet } from '@angular/common';
import { Component, computed, linkedSignal } from '@angular/core';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { AppSettings, ProxyUpdate } from '../../../core/models/api.models';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from '../settings-page';

/** Proxy URL chosen here, when HTTPS_PROXY and HTTP_PROXY are not set. */
type ProxyMode = 'none' | 'custom';

const PROXY_SOURCE_LABELS: Record<AppSettings['proxy']['effective']['source'], MessageKey> = {
  web: 'settings.sourceWeb',
  environment: 'settings.sourceEnvironment',
  none: 'settings.sourceNone',
};

/** Longest proxy URL or no_proxy list accepted by the server (proxy.MAX_*_CHARS). */
const MAX_PROXY_CHARS = 500;

/** Fields of the proxy form. */
interface ProxyFormModel {
  mode: ProxyMode;
  url: string;
  /** Hosts reached without proxy, when NO_PROXY is not set. */
  noProxy: string;
}

/** A proxy setting that can be deleted when its variable hides it. */
type ProxyField = 'url' | 'no_proxy';

/**
 * Administrator page: proxy of the outgoing connections of the controller (OSV download and OIDC
 * provider). HTTPS_PROXY / HTTP_PROXY and NO_PROXY, when set, take precedence: their field is
 * then only shown.
 */
@Component({
  selector: 'app-proxy-settings',
  imports: [FormField, NgTemplateOutlet, RefreshButtonComponent, TranslatePipe],
  templateUrl: './proxy-settings.component.html',
  styleUrl: '../settings.css',
})
export class ProxySettingsComponent extends SettingsPage {
  /** Filled with the stored values each time they are loaded, then edited by the form. */
  readonly proxyModel = linkedSignal<ProxyFormModel>(() => {
    const proxy = this.settings.value()?.proxy;
    const url = proxy?.url.value;
    return {
      mode: url ? 'custom' : 'none',
      url: url ?? '',
      noProxy: proxy?.no_proxy.value ?? '',
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
    const proxy = this.settings.value()?.proxy;
    if (!proxy) {
      return;
    }
    const model = this.proxyModel();
    const url = model.url.trim();
    const values: ProxyUpdate = {};
    if (!proxy.url.env_set) {
      if (this.proxyForm().invalid() || (model.mode === 'custom' && !url)) {
        this.error.set(msg('settings.proxyMissing'));
        return;
      }
      values.url = model.mode === 'none' ? null : url;
    }
    if (!proxy.no_proxy.env_set) {
      values.no_proxy = model.noProxy.trim() || null;
    }
    await this.run(() => firstValueFrom(this.api.setProxy(values)), msg('settings.proxySaved'));
  }

  /** Delete a stored value that its variable hides. */
  async deleteStored(field: ProxyField): Promise<void> {
    await this.run(
      () => firstValueFrom(this.api.setProxy({ [field]: null })),
      msg('settings.storedDeleted'),
    );
  }
}
