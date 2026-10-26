import { DOCUMENT, NgTemplateOutlet } from '@angular/common';
import { Component, computed, inject, linkedSignal } from '@angular/core';
import { FormField, form, maxLength, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { AppSettings, ProxyUpdate } from '../../../core/models/api.models';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from '../settings-page';

/** How the report language is chosen in the form (without SECREVIEW_REPORT_LANGUAGE). */
type LanguageMode = 'agent' | 'custom';

/** Same rule as the server: a language name or code, nothing that could carry instructions. */
const LANGUAGE_PATTERN = /^[\p{L} \-_()]{0,40}$/u;

/** Fields of the report language form. */
interface LanguageFormModel {
  mode: LanguageMode;
  language: string;
}

/** Longest URL accepted by the server (config.CONTROLLER_URL_MAX_CHARS). */
const MAX_CONTROLLER_URL_CHARS = 500;

/** Path of the web interface under the controller URL (config.WEB_UI_PATH). */
const WEB_UI_PATH = '/ui';

/**
 * Same rule as the server: the root http(s) URL of the controller, without user name, password,
 * query, fragment nor the path of the interface; empty clears it.
 */
function isControllerUrl(value: string): boolean {
  if (!value) {
    return true;
  }
  if (value.length > MAX_CONTROLLER_URL_CHARS) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      ['http:', 'https:'].includes(url.protocol) &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      !value.replace(/\/+$/, '').endsWith(WEB_UI_PATH)
    );
  } catch {
    return false;
  }
}

/** Fields of the controller URL form. */
interface ControllerUrlFormModel {
  url: string;
}

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
 * Administrator page: general settings. The language of the review reports, the public URL of
 * the controller (the MCP server gives its web interface to the agents without a valid token,
 * the connectors link to it) and the proxy of the outgoing connections of the controller (OSV
 * download and OIDC provider). SECREVIEW_REPORT_LANGUAGE, SECREVIEW_CONTROLLER_URL,
 * HTTPS_PROXY / HTTP_PROXY and NO_PROXY, when set, take precedence: their field then only shows
 * them.
 */
@Component({
  selector: 'app-general-settings',
  imports: [FormField, NgTemplateOutlet, RefreshButtonComponent, TranslatePipe],
  templateUrl: './general-settings.component.html',
  styleUrl: '../settings.css',
})
export class GeneralSettingsComponent extends SettingsPage {
  /** Filled with the stored value each time it is loaded, then edited by the form. */
  readonly languageModel = linkedSignal<LanguageFormModel>(() => {
    const stored = this.settings.value()?.report_language.value;
    return { mode: stored ? 'custom' : 'agent', language: stored ?? '' };
  });
  readonly languageForm = form(this.languageModel, (path) => {
    validate(path.language, ({ value, valueOf }) =>
      valueOf(path.mode) === 'custom' && !LANGUAGE_PATTERN.test(value().trim())
        ? { kind: 'pattern', message: this.i18n.translate('settings.languagePattern') }
        : undefined,
    );
  });
  readonly languageMode = computed(() => this.languageModel().mode);

  readonly languageSuggestions = [
    'French',
    'English',
    'German',
    'Spanish',
    'Italian',
    'Portuguese',
  ];

  readonly languageValid = computed(() => this.languageForm().valid());

  async saveLanguage(event: Event): Promise<void> {
    event.preventDefault();
    const { mode, language } = this.languageModel();
    const value = mode === 'agent' ? null : language.trim();
    if (mode === 'custom' && (!value || !this.languageValid())) {
      this.error.set(msg('settings.languageMissing'));
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(value)),
      msg('settings.languageSaved'),
    );
  }

  /** Delete the stored value that SECREVIEW_REPORT_LANGUAGE hides. */
  async deleteStoredLanguage(): Promise<void> {
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(null)),
      msg('settings.storedDeleted'),
    );
  }

  /** Root URL of this controller in the browser (base of the Angular application without /ui). */
  readonly currentUrl = inject(DOCUMENT)
    .baseURI.replace(/\/+$/, '')
    .replace(new RegExp(`${WEB_UI_PATH}$`), '');

  /** Filled with the stored URL each time it is loaded, then edited by the form. */
  readonly controllerUrlModel = linkedSignal<ControllerUrlFormModel>(() => ({
    url: this.settings.value()?.controller_url.value ?? '',
  }));
  readonly controllerUrlForm = form(this.controllerUrlModel, (path) => {
    validate(path.url, ({ value }) =>
      isControllerUrl(value().trim())
        ? undefined
        : { kind: 'url', message: this.i18n.translate('settings.controllerUrlPattern') },
    );
  });
  readonly controllerUrlValid = computed(() => this.controllerUrlForm().valid());

  /** Put the address of this interface in the field. */
  useCurrent(): void {
    this.controllerUrlModel.set({ url: this.currentUrl });
  }

  async saveControllerUrl(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.controllerUrlValid()) {
      this.error.set(msg('settings.controllerUrlPattern'));
      return;
    }
    const value = this.controllerUrlModel().url.trim() || null;
    await this.run(
      () => firstValueFrom(this.api.setControllerUrl(value)),
      value ? msg('settings.controllerUrlSaved') : msg('settings.storedDeleted'),
    );
  }

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
