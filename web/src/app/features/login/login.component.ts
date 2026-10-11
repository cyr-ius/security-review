import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { FormField, form, required, submit } from '@angular/forms/signals';
import { ActivatedRoute, Router } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

/** Login page: the user enters a bootstrap password or a bearer token. */
@Component({
  selector: 'app-login',
  imports: [FormField],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css',
})
export class LoginComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly error = signal<string | null>(this.initialMessage());
  readonly reveal = signal(false);

  readonly loginModel = signal({ token: '' });

  readonly loginForm = form(this.loginModel, (path) => {
    required(path.token, { message: 'Le mot de passe ou jeton est obligatoire' });
  });

  onSubmit(event: Event): void {
    event.preventDefault();
    submit(this.loginForm, async (fields) => {
      this.error.set(null);
      this.auth.login(fields.token().value().trim());
      try {
        const identity = await firstValueFrom(this.api.me());
        this.auth.identity.set(identity);
        const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';
        // Only follow local paths
        await this.router.navigateByUrl(returnUrl.startsWith('/') ? returnUrl : '/');
      } catch (err: unknown) {
        this.auth.logout();
        this.error.set(describeError(err));
      }
    });
  }

  private initialMessage(): string | null {
    const query = this.route.snapshot.queryParamMap;
    if (query.has('forbidden')) {
      return "Ce secret n'a pas accès à l'interface web (rôle web-admin, reader, triager ou admin requis).";
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
      return "Ce secret n'a pas accès à l'interface web (rôle web-admin, reader, triager ou admin requis).";
    }
    if (err.status === 0) {
      return 'Serveur injoignable.';
    }
  }
  return 'La connexion a échoué.';
}
