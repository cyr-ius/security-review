import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormField, form, maxLength, required, submit } from '@angular/forms/signals';
import { ActivatedRoute, Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { API_URL, ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { ThemeService } from '../../core/services/theme.service';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LanguageSelectComponent } from '../../shared/components/language-select/language-select.component';

/** Messages of the oidcError codes sent back by /api/v1/auth/oidc/callback. */
const OIDC_ERRORS: Record<string, MessageKey> = {
  denied: 'login.oidcDenied',
  forbidden: 'login.oidcForbidden',
  unknown_user: 'login.oidcUnknownUser',
  conflict: 'login.oidcConflict',
  username: 'login.oidcUsername',
  revoked: 'login.oidcRevoked',
  state: 'login.oidcState',
  token: 'login.oidcToken',
  provider: 'login.oidcProvider',
};

/**
 * Login page of the web users: a username and a password (local user), or the identity
 * provider (SSO user) when the controller offers OIDC. Bearer tokens are for the MCP server and
 * the REST API only: they never open the web interface.
 */
@Component({
  selector: 'app-login',
  imports: [FormField, TranslatePipe, LanguageSelectComponent],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})
export class LoginComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  readonly theme = inject(ThemeService);
  private readonly i18n = inject(I18nService);

  /** Highlights shown on the brand panel. */
  readonly features = [
    {
      icon: 'bi-robot',
      title: 'login.featureReviewTitle',
      text: 'login.featureReviewText',
    },
    {
      icon: 'bi-bug',
      title: 'login.featureScanTitle',
      text: 'login.featureScanText',
    },
    {
      icon: 'bi-graph-down-arrow',
      title: 'login.featureTrendTitle',
      text: 'login.featureTrendText',
    },
  ] as const satisfies readonly { icon: string; title: MessageKey; text: MessageKey }[];

  readonly error = signal<Message | null>(this.initialMessage());
  readonly reveal = signal(false);

  /** Label of the single sign-on button; null when OIDC is not enabled. */
  readonly ssoName = signal<string | null>(null);
  /** True while the session returned by the identity provider is being checked. */
  readonly ssoPending = signal(false);

  /** Start of the OIDC login, coming back to the requested page. */
  readonly ssoUrl = computed(
    () => `${API_URL}/auth/oidc/login?return_url=${encodeURIComponent(this.returnUrl())}`,
  );

  ngOnInit(): void {
    const session = this.takeSessionFromFragment();
    if (session) {
      this.ssoPending.set(true);
      void this.enter(session).finally(() => this.ssoPending.set(false));
    }
    this.api.authConfig().subscribe({
      next: (config) => this.ssoName.set(config.oidc ? config.oidc_display_name : null),
      // Older controller or network error: only the password login is offered
      error: () => this.ssoName.set(null),
    });
  }

  readonly accountModel = signal({ username: '', password: '' });

  readonly accountForm = form(this.accountModel, (path) => {
    required(path.username, { message: () => this.i18n.translate('login.usernameRequired') });
    maxLength(path.username, 64, { message: () => this.i18n.translate('login.usernameTooLong') });
    required(path.password, { message: () => this.i18n.translate('login.passwordRequired') });
    maxLength(path.password, 256, {
      message: () => this.i18n.translate('login.passwordTooLong'),
    });
  });

  onAccountSubmit(event: Event): void {
    event.preventDefault();
    submit(this.accountForm, async (fields) => {
      this.error.set(null);
      try {
        const login = await firstValueFrom(
          this.api.login(fields.username().value().trim(), fields.password().value()),
        );
        await this.enter(login.session);
      } catch (err: unknown) {
        this.error.set(describeAccountError(err));
      }
    });
  }

  /** Check a session and open the requested page. */
  private async enter(session: string): Promise<void> {
    this.error.set(null);
    this.auth.login(session);
    try {
      const identity = await firstValueFrom(this.api.me());
      this.auth.identity.set(identity);
      await this.router.navigateByUrl(this.returnUrl());
    } catch (err: unknown) {
      this.auth.logout();
      this.error.set(describeError(err));
    }
  }

  /** Requested page, local paths only (no open redirect). */
  private returnUrl(): string {
    const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';
    return returnUrl.startsWith('/') && !returnUrl.startsWith('//') ? returnUrl : '/';
  }

  /**
   * Read the session token put in the URL fragment by the OIDC callback, then remove it from
   * the address bar and the history so that it is neither bookmarked nor shared.
   */
  private takeSessionFromFragment(): string | null {
    const fragment = this.route.snapshot.fragment;
    if (!fragment) {
      return null;
    }
    const session = new URLSearchParams(fragment).get('session');
    if (session) {
      history.replaceState(history.state, '', location.pathname + location.search);
    }
    return session;
  }

  private initialMessage(): Message | null {
    const query = this.route.snapshot.queryParamMap;
    const oidcError = query.get('oidcError');
    if (oidcError) {
      return msg(OIDC_ERRORS[oidcError] ?? 'login.oidcFailed');
    }
    if (query.has('authRequired')) {
      return msg('login.authRequired');
    }
    if (query.has('forbidden')) {
      return msg('login.forbidden');
    }
    if (query.has('expired')) {
      return msg('login.expired');
    }
    return null;
  }
}

function describeAccountError(err: unknown): Message {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 401) {
      return msg('login.badCredentials');
    }
    if (err.status === 429) {
      return msg('login.tooManyAttempts');
    }
    if (err.status === 422) {
      return msg('login.tooLong');
    }
    if (err.status === 0) {
      return msg('login.unreachable');
    }
  }
  return msg('login.failed');
}

function describeError(err: unknown): Message {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 401) {
      return msg('login.sessionInvalid');
    }
    if (err.status === 403) {
      return msg('login.forbidden');
    }
    if (err.status === 0) {
      return msg('login.unreachable');
    }
  }
  return msg('login.failed');
}
