import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { OAuthClientAdmin, OAuthOverview } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';

type OAuthGrantAdmin = OAuthOverview['grants'][number];

/**
 * OAuth login of the MCP clients (Tokens screen, tokens.manage): the settings in use, every
 * grant (revocable) and every registered client (deletable). Hidden while the login is off.
 */
@Component({
  selector: 'app-oauth-clients',
  imports: [HelpLinkComponent, DatePipe, TranslatePipe],
  templateUrl: './oauth-clients.component.html',
})
export class OAuthClientsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly overview = rxResource({ stream: () => this.api.oauthOverview() });
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  name(item: { client_name: string | null; client_id: string }): string {
    return item.client_name || item.client_id;
  }

  revokeGrant(grant: OAuthGrantAdmin): Promise<void> {
    const client = this.name(grant);
    return this.run(
      this.i18n.translate('oauth.confirmRevokeGrant', { client, user: grant.username }),
      () => firstValueFrom(this.api.revokeOAuthGrant(grant.id)),
      msg('oauth.revoked', { client }),
    );
  }

  deleteClient(client: OAuthClientAdmin): Promise<void> {
    const name = this.name(client);
    return this.run(
      this.i18n.translate('oauth.confirmDeleteClient', { client: name }),
      () => firstValueFrom(this.api.deleteOAuthClient(client.client_id)),
      msg('oauth.clientDeleted', { client: name }),
    );
  }

  private async run(question: string, action: () => Promise<void>, done: Message): Promise<void> {
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
      this.message.set(done);
      this.overview.reload();
    } catch {
      this.error.set(msg('oauth.revokeFailed'));
    } finally {
      this.busy.set(false);
    }
  }
}
