import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { HealthService } from '../services/health.service';

/** Page shown while the controller does not answer. */
export const UNAVAILABLE_PATH = '/unavailable';

/** Open the application only once the controller answers (checked once per load). */
export const backendGuard: CanActivateFn = async (_route, state) => {
  const health = inject(HealthService);
  const router = inject(Router);
  if (await health.check()) {
    return true;
  }
  return router.createUrlTree([UNAVAILABLE_PATH], { queryParams: { returnUrl: state.url } });
};
