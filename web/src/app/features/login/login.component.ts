import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormField, form, required, submit } from '@angular/forms/signals';
import { ActivatedRoute, Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { API_URL, ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { ThemeService } from '../../core/services/theme.service';

/** Messages of the oidcError codes sent back by /api/v1/auth/oidc/callback. */
const OIDC_ERRORS: Record<string, string> = {
  denied: "Connexion refusée ou annulée auprès du fournisseur d'identité.",
  forbidden:
    "Votre compte n'appartient à aucun groupe autorisé sur l'interface (reader, triager ou admin).",
  state: 'La connexion a expiré ou a été ouverte dans un autre navigateur : recommencez.',
  token: "La réponse du fournisseur d'identité a été refusée (jeton invalide).",
  provider: "Fournisseur d'identité injoignable ou mal configuré.",
};

/**
 * Login page: the user enters a bootstrap password or a bearer token, or signs in with the
 * identity provider (OIDC) when the controller offers it.
 */
@Component({
  selector: 'app-login',
  imports: [FormField],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})
export class LoginComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  readonly theme = inject(ThemeService);

  /** Highlights shown on the brand panel. */
  readonly features = [
    {
      icon: 'bi-robot',
      title: 'Revues assistées par IA',
      text: 'Prompts et checklists exposés à votre assistant via MCP.',
    },
    {
      icon: 'bi-bug',
      title: 'Scan de code et de dépendances',
      text: 'Règles par motifs et avis de vulnérabilité OSV importés hors ligne.',
    },
    {
      icon: 'bi-graph-down-arrow',
      title: 'Suivi et tendances',
      text: 'Triage des findings, gate CI/CD, export SARIF.',
    },
  ] as const;

  readonly error = signal<string | null>(this.initialMessage());
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
      // Older controller or network error: only the password or token login is offered
      error: () => this.ssoName.set(null),
    });
  }

  readonly loginModel = signal({ token: '' });

  readonly loginForm = form(this.loginModel, (path) => {
    required(path.token, { message: 'Le mot de passe ou jeton est obligatoire' });
  });

  onSubmit(event: Event): void {
    event.preventDefault();
    submit(this.loginForm, async (fields) => {
      await this.enter(fields.token().value().trim());
    });
  }

  /** Check a secret (password, token or OIDC session) and open the requested page. */
  private async enter(secret: string): Promise<void> {
    this.error.set(null);
    this.auth.login(secret);
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

  private initialMessage(): string | null {
    const query = this.route.snapshot.queryParamMap;
    const oidcError = query.get('oidcError');
    if (oidcError) {
      return OIDC_ERRORS[oidcError] ?? 'La connexion par SSO a échoué.';
    }
    if (query.has('authRequired')) {
      return "L'authentification de l'interface n'est pas configurée sur ce serveur.";
    }
    if (query.has('forbidden')) {
      return "Ce secret n'a pas accès à l'interface web (rôle reader, triager ou admin requis).";
    }
    if (query.has('expired')) {
      return 'Session expirée ou token révoqué : reconnectez-vous.';
    }
    return null;
  }
}

function describeError(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    if (err.status === 401) {
      return 'Mot de passe ou jeton invalide.';
    }
    if (err.status === 403) {
      return "Ce secret n'a pas accès à l'interface web (rôle reader, triager ou admin requis).";
    }
    if (err.status === 0) {
      return 'Serveur injoignable.';
    }
  }
  return 'La connexion a échoué.';
}
