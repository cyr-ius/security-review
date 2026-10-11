import { HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { ApiService } from '../services/api.service';
import { AuthService } from '../services/auth.service';

/**
 * Let the user in once /api/v1/me answers.
 *
 * Without configured tokens the server answers without a token, so no login is needed.
 */
export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  const api = inject(ApiService);
  const router = inject(Router);

  if (auth.identity()) {
    return true;
  }
  return api.me().pipe(
    map((identity) => {
      auth.identity.set(identity);
      return true;
    }),
    catchError((error: unknown) => {
      if (error instanceof HttpErrorResponse && error.status === 403) {
        // Valid token whose role cannot use the web interface (e.g. an MCP token)
        auth.logout();
        return of(router.createUrlTree(['/login'], { queryParams: { forbidden: 1 } }));
      }
      // A stored token that is no longer accepted has expired or been revoked
      const expired = auth.token() !== null ? 1 : null;
      auth.logout();
      return of(
        router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url, expired } }),
      );
    }),
  );
};
