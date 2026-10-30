import { DatePipe } from '@angular/common';
import { Component, computed, inject, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import {
  OAuthClientAdmin,
  OAuthOverview,
  OAuthSettingsUpdate,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { describeError } from '../../settings/settings-page';

type OAuthGrantAdmin = OAuthOverview['grants'][number];

/** Longest MCP endpoint URL accepted by the server (CONTROLLER_URL_MAX_CHARS). */
const MAX_URL_CHARS = 500;

/**
 * OAuth login of the MCP clients (Tokens page, tokens.manage): the settings in use, every
 * grant (revocable, one by one or all at once) and every registered client (deletable), also
 * while the login is off (the grants are then suspended). The holders of settings.manage turn
 * the login on or off and set the URL of the MCP endpoint, unless their variable
 * (SECREVIEW_MCP_OAUTH_ENABLED, SECREVIEW_MCP_URL) is set.
 */
@Component({
  selector: 'app-oauth-clients',
  imports: [HelpLinkComponent, DatePipe, FormField, TranslatePipe],
  templateUrl: './oauth-clients.component.html',
})
export class OAuthClientsComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);

  readonly overview = rxResource({ stream: () => this.api.oauthOverview() });
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  readonly canManage = computed(() => this.auth.can('settings.manage'));

  /** Filled with the URL in use each time the settings are loaded, then edited by the form. */
  readonly model = linkedSignal(() => {
    const url = this.overview.value()?.settings.mcp_url;
    return { mcpUrl: url?.effective ?? url?.value ?? '' };
  });
  readonly urlForm = form(this.model, (path) => {
    maxLength(path.mcpUrl, MAX_URL_CHARS);
  });

  name(item: { client_name: string | null; client_id: string }): string {
    return item.client_name || item.client_id;
  }

  /** Turn the login on (with the URL of the form) or off (every grant is suspended). */
  async toggle(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const enabled = input.checked;
    if (!enabled && !window.confirm(this.i18n.translate('oauth.confirmOff'))) {
      input.checked = true;
      return;
    }
    const values: OAuthSettingsUpdate = { enabled };
    if (enabled && !this.overview.value()?.settings.mcp_url.env_set) {
      const url = this.model().mcpUrl.trim();
      if (!url || this.urlForm().invalid()) {
        input.checked = false;
        this.error.set(msg('oauth.urlMissing'));
        return;
      }
      values.mcp_url = url;
    }
    const done = await this.save(values, msg(enabled ? 'oauth.turnedOn' : 'oauth.turnedOff'));
    if (!done) {
      input.checked = !enabled;
    }
  }

  async saveUrl(event: Event): Promise<void> {
    event.preventDefault();
    const url = this.model().mcpUrl.trim();
    if (this.urlForm().invalid() || (!url && this.overview.value()?.enabled)) {
      this.error.set(msg('oauth.urlMissing'));
      return;
    }
    await this.save({ mcp_url: url || null }, msg('oauth.urlSaved'));
  }

  revokeGrant(grant: OAuthGrantAdmin): Promise<void> {
    const client = this.name(grant);
    return this.run(
      this.i18n.translate('oauth.confirmRevokeGrant', { client, user: grant.username }),
      () => firstValueFrom(this.api.revokeOAuthGrant(grant.id)),
      msg('oauth.revoked', { client }),
    );
  }

  revokeAll(): Promise<void> {
    return this.run(this.i18n.translate('oauth.confirmRevokeAll'), async () => {
      const { revoked } = await firstValueFrom(this.api.revokeAllOAuthGrants());
      this.message.set(msg('oauth.allRevoked', { count: revoked }));
    });
  }

  deleteClient(client: OAuthClientAdmin): Promise<void> {
    const name = this.name(client);
    return this.run(
      this.i18n.translate('oauth.confirmDeleteClient', { client: name }),
      () => firstValueFrom(this.api.deleteOAuthClient(client.client_id)),
      msg('oauth.clientDeleted', { client: name }),
    );
  }

  /** Send the settings, show the outcome and reload; return whether they were stored. */
  private async save(values: OAuthSettingsUpdate, success: Message): Promise<boolean> {
    if (this.busy()) {
      return false;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.setOAuthSettings(values));
      this.message.set(success);
      this.overview.reload();
      return true;
    } catch (error: unknown) {
      this.error.set(describeError(error));
      return false;
    } finally {
      this.busy.set(false);
    }
  }

  private async run(question: string, action: () => Promise<void>, done?: Message): Promise<void> {
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
      if (done) {
        this.message.set(done);
      }
      this.overview.reload();
    } catch {
      this.error.set(msg('oauth.revokeFailed'));
    } finally {
      this.busy.set(false);
    }
  }
}
