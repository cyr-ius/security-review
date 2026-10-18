import { inject } from '@angular/core';
import { CanActivateChildFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

/** Page that changes the password of the logged-in user. */
export const ACCOUNT_PATH = '/account';

/**
 * Keep a user whose password was set by someone else on My account until it changes it (the
 * API refuses everything else meanwhile).
 */
export const passwordChangeGuard: CanActivateChildFn = (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const mustChange = auth.identity()?.must_change_password ?? false;
  return mustChange && !state.url.startsWith(ACCOUNT_PATH)
    ? router.createUrlTree([ACCOUNT_PATH])
    : true;
};
