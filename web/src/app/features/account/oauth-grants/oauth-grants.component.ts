import { DatePipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { OAuthGrant } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';

/**
 * MCP clients the logged-in user approved with the OAuth login (My account), each revocable.
 * Hidden while there is none (the OAuth login may be off).
 */
@Component({
  selector: 'app-oauth-grants',
  imports: [HelpLinkComponent, DatePipe, TranslatePipe],
  templateUrl: './oauth-grants.component.html',
})
export class OAuthGrantsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly grants = rxResource({ stream: () => this.api.myOAuthGrants() });
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  name(grant: OAuthGrant): string {
    return grant.client_name || grant.client_id;
  }

  async revoke(grant: OAuthGrant): Promise<void> {
    const client = this.name(grant);
    if (this.busy() || !window.confirm(this.i18n.translate('oauth.confirmRevoke', { client }))) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.deleteMyOAuthGrant(grant.id));
      this.message.set(msg('oauth.revoked', { client }));
      this.grants.reload();
    } catch {
      this.error.set(msg('oauth.revokeFailed'));
    } finally {
      this.busy.set(false);
    }
  }
}
