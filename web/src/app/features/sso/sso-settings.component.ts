import { NgTemplateOutlet } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, effect, inject, output, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import {
  OidcSettingName,
  OidcSettings,
  OidcSettingsUpdate,
  OidcTestResult,
} from '../../core/models/api.models';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';

/** Value shown by the API in place of a set client secret. */
const SECRET_MASK = '***';

/** How a setting is edited. */
type FieldKind = 'text' | 'bool' | 'secret';

/** One field of the form. */
interface FieldMeta {
  name: OidcSettingName;
  label: MessageKey;
  kind: FieldKind;
  placeholder?: string;
  help?: MessageKey;
}

/** Fields of the form, grouped as displayed. */
const PROVIDER_FIELDS: FieldMeta[] = [
  {
    name: 'issuer',
    label: 'sso.issuer',
    kind: 'text',
    placeholder: 'https://sso.example.com/realms/acme',
  },
  { name: 'client_id', label: 'sso.clientId', kind: 'text', placeholder: 'secreview' },
  {
    name: 'client_secret',
    label: 'sso.clientSecret',
    kind: 'secret',
    help: 'sso.clientSecretHelp',
  },
  {
    name: 'redirect_uri',
    label: 'sso.redirectUri',
    kind: 'text',
    placeholder: 'https://secreview.example.com/api/v1/auth/oidc/callback',
  },
  { name: 'scopes', label: 'sso.scopes', kind: 'text', placeholder: 'openid profile email' },
  { name: 'display_name', label: 'sso.displayName', kind: 'text', placeholder: 'SSO' },
];

const ACCESS_FIELDS: FieldMeta[] = [
  {
    name: 'roles_claim',
    label: 'sso.rolesClaim',
    kind: 'text',
    placeholder: 'groups',
    help: 'sso.rolesClaimHelp',
  },
  {
    name: 'username_claim',
    label: 'sso.usernameClaim',
    kind: 'text',
    placeholder: 'preferred_username',
  },
  {
    name: 'admin_groups',
    label: 'sso.adminGroups',
    kind: 'text',
    help: 'sso.adminGroupsHelp',
  },
  {
    name: 'default_group',
    label: 'sso.defaultGroup',
    kind: 'text',
    help: 'sso.defaultGroupHelp',
  },
  {
    name: 'auto_create_users',
    label: 'sso.autoCreate',
    kind: 'bool',
  },
];

/** Name of the SECREVIEW_OIDC_* variable of a setting. */
export function variableOf(name: OidcSettingName): string {
  return `SECREVIEW_OIDC_${name.toUpperCase()}`;
}

/**
 * Settings of the single sign-on login (OpenID Connect): each value stored here overrides its
 * SECREVIEW_OIDC_* variable, and "Variable" applies the variable again. Changes apply at the next
 * login, without restarting the controller.
 */
@Component({
  selector: 'app-sso-settings',
  imports: [NgTemplateOutlet, RouterLink, TranslatePipe],
  templateUrl: './sso-settings.component.html',
})
export class SsoSettingsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  /** Emitted after a change, so that the page reloads what depends on the settings. */
  readonly changed = output<void>();

  readonly providerFields = PROVIDER_FIELDS;
  readonly accessFields = ACCESS_FIELDS;
  readonly variableOf = variableOf;

  readonly settings = rxResource({ stream: () => this.api.oidcSettings() });

  /** Values being edited (the client secret is empty unless a new one is typed). */
  readonly draft = signal<Record<string, string | boolean>>({});
  readonly testResult = signal<OidcTestResult | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Values of the form that differ from the effective ones. */
  readonly changes = computed<OidcSettingsUpdate>(() => {
    const current = this.settings.value();
    if (!current) {
      return {};
    }
    const changes: OidcSettingsUpdate = {};
    for (const [name, value] of Object.entries(this.draft())) {
      const key = name as OidcSettingName;
      if (key === 'client_secret') {
        if (value !== '') {
          changes[key] = value;
        }
      } else if (value !== (current.fields[key].effective ?? '')) {
        changes[key] = value;
      }
    }
    return changes;
  });

  readonly dirty = computed(() => Object.keys(this.changes()).length > 0);

  constructor() {
    // Load the effective values into the form at each (re)load
    effect(() => {
      const current = this.settings.value();
      if (current) {
        this.draft.set(draftOf(current));
      }
    });
  }

  value(name: OidcSettingName): string | boolean {
    return this.draft()[name] ?? '';
  }

  text(name: OidcSettingName): string {
    return String(this.value(name));
  }

  set(name: OidcSettingName, value: string | boolean): void {
    this.draft.update((draft) => ({ ...draft, [name]: value }));
    this.testResult.set(null);
  }

  onCheck(name: OidcSettingName, event: Event): void {
    this.set(name, (event.target as HTMLInputElement).checked);
  }

  onText(name: OidcSettingName, event: Event): void {
    this.set(name, (event.target as HTMLInputElement | HTMLSelectElement).value);
  }

  /** True when the value of this setting is stored in the web interface. */
  stored(current: OidcSettings, name: OidcSettingName): boolean {
    return current.fields[name].value !== null;
  }

  /** Value of the variable, as shown next to the field. */
  envValue(current: OidcSettings, name: OidcSettingName): string {
    const env = current.fields[name].env;
    if (typeof env === 'boolean') {
      return env ? 'true' : 'false';
    }
    return env ? env : this.i18n.translate('sso.empty');
  }

  /** Placeholder of the client secret field. */
  secretPlaceholder(current: OidcSettings): string {
    const effective = current.fields.client_secret.effective;
    return this.i18n.translate(effective === SECRET_MASK ? 'sso.secretSet' : 'sso.secretNone');
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.dirty() || this.busy()) {
      return;
    }
    const names = Object.keys(this.changes()).length;
    await this.run(async () => {
      await firstValueFrom(this.api.setOidcSettings(this.changes()));
      return msg('sso.saved', { count: names });
    });
  }

  /** Apply the SECREVIEW_OIDC_* variable of one setting again. */
  async restore(name: OidcSettingName): Promise<void> {
    if (this.busy()) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.setOidcSettings({ [name]: null }));
      return msg('sso.restored', { variable: variableOf(name) });
    });
  }

  /** Make the client public: the stored secret becomes empty. */
  async clearSecret(): Promise<void> {
    if (this.busy() || !window.confirm(this.i18n.translate('sso.confirmClearSecret'))) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.setOidcSettings({ client_secret: '' }));
      return msg('sso.secretCleared');
    });
  }

  async test(): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.testResult.set(null);
    try {
      this.testResult.set(await firstValueFrom(this.api.testOidcSettings(this.changes())));
    } catch (error: unknown) {
      this.error.set(describeError(error, TEST_REFUSED));
    } finally {
      this.busy.set(false);
    }
  }

  reset(): void {
    const current = this.settings.value();
    if (current) {
      this.draft.set(draftOf(current));
    }
    this.testResult.set(null);
  }

  /** Run a change, show its outcome and reload the settings. */
  private async run(action: () => Promise<Message>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.testResult.set(null);
    try {
      this.message.set(await action());
      this.settings.reload();
      this.changed.emit();
    } catch (error: unknown) {
      this.error.set(describeError(error, SETTINGS_REFUSED));
    } finally {
      this.busy.set(false);
    }
  }
}

/** Form values of the effective settings (the client secret is never shown). */
function draftOf(current: OidcSettings): Record<string, string | boolean> {
  const draft: Record<string, string | boolean> = {};
  for (const [name, field] of Object.entries(current.fields)) {
    draft[name] = name === 'client_secret' ? '' : (field.effective ?? '');
  }
  return draft;
}

/** Messages of a refused change: with the detail sent by the server, or without one. */
interface Refusal {
  detail: MessageKey;
  generic: MessageKey;
}

const TEST_REFUSED: Refusal = { detail: 'sso.testRefused', generic: 'sso.testRefusedCheck' };
const SETTINGS_REFUSED: Refusal = {
  detail: 'sso.settingsRefused',
  generic: 'sso.settingsRefusedCheck',
};

function describeError(error: unknown, refusal: Refusal): Message {
  if (error instanceof HttpErrorResponse && error.status === 422) {
    const detail = error.error?.detail;
    return typeof detail === 'string' ? msg(refusal.detail, { detail }) : msg(refusal.generic);
  }
  return msg('sso.failed');
}
