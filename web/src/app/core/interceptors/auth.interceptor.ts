import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { API_URL } from '../services/api.service';
import { AuthService } from '../services/auth.service';

/** Identity check: its errors are handled by the auth guard and the login page. */
const ME_URL = `${API_URL}/me`;

/** Add the bearer token to API calls and go back to the login page on 401. */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  // Only our own API receives the token
  const token = auth.token();
  const authorized =
    token && request.url.startsWith(API_URL)
      ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
      : request;

  return next(authorized).pipe(
    catchError((error: unknown) => {
      // Token revoked while browsing: log out and come back here after logging in again
      if (
        error instanceof HttpErrorResponse &&
        error.status === 401 &&
        token &&
        request.url !== ME_URL
      ) {
        auth.logout();
        router.navigate(['/login'], { queryParams: { expired: 1, returnUrl: router.url } });
      }
      return throwError(() => error);
    }),
  );
};
