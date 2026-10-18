import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { UNAVAILABLE_PATH } from '../guards/backend.guard';
import { API_URL } from '../services/api.service';
import { AuthService } from '../services/auth.service';
import { HEALTH_URL, HealthService, isUnreachable } from '../services/health.service';

/** Identity check: its errors are handled by the auth guard and the login page. */
const ME_URL = `${API_URL}/me`;

/**
 * Errors shared by every screen: a controller that does not answer opens the "Backend
 * unavailable" page, and a session that is no longer accepted shows the "Session expired"
 * dialog. The screens still receive the error for their own message.
 */
export const errorInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(AuthService);
  const health = inject(HealthService);
  const router = inject(Router);
  const hadSession = auth.token() !== null;

  return next(request).pipe(
    catchError((error: unknown) => {
      if (request.url !== HEALTH_URL && isUnreachable(error)) {
        health.markUnavailable();
        if (!router.url.startsWith(UNAVAILABLE_PATH)) {
          void router.navigate([UNAVAILABLE_PATH], { queryParams: { returnUrl: router.url } });
        }
      } else if (
        error instanceof HttpErrorResponse &&
        error.status === 401 &&
        hadSession &&
        request.url !== ME_URL
      ) {
        // Session expired or revoked while browsing
        auth.expire();
      }
      return throwError(() => error);
    }),
  );
};
