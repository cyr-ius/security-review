import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { API_URL } from '../services/api.service';
import { AuthService } from '../services/auth.service';

/** Add the session token to the calls of our own API (errors: see errorInterceptor). */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(AuthService);

  // Only our own API receives the token
  const token = auth.token();
  const authorized =
    token && request.url.startsWith(API_URL)
      ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
      : request;

  return next(authorized);
};
