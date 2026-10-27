import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

/**
 * Consent screen of the OAuth login of the MCP clients: the controller sends the browser here
 * (behind the login) with the handle of a pending request; the user approves or denies the
 * client, then the browser goes back to the client with a code or an error.
 */
@Component({
  selector: 'app-oauth-consent',
  imports: [TranslatePipe],
  templateUrl: './oauth-consent.component.html',
})
export class OAuthConsentComponent {
  private readonly api = inject(ApiService);
  readonly auth = inject(AuthService);
  private readonly handle = inject(ActivatedRoute).snapshot.queryParamMap.get('request') ?? '';

  readonly pending = rxResource({
    params: () => this.handle || undefined,
    stream: ({ params }) => this.api.oauthRequest(params),
  });
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  async decide(approve: boolean): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    try {
      const { redirect_url } = await firstValueFrom(this.api.oauthDecide(this.handle, approve));
      // Back to the client (its redirect URI, checked at its registration)
      window.location.assign(redirect_url);
    } catch (error: unknown) {
      this.error.set(describeError(error));
      this.busy.set(false);
    }
  }

  /** Message of a request that cannot be shown. */
  loadError(): Message {
    return describeError(this.pending.error());
  }
}

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && error.status === 403) {
    return msg('oauth.forbidden');
  }
  if (error instanceof HttpErrorResponse && error.status === 404) {
    return msg('oauth.expired');
  }
  return msg('oauth.failed');
}
