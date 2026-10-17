import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { Permission } from '../models/api.models';
import { AuthService } from '../services/auth.service';

/** Open a page only to the users that hold ``permission`` (on at least one project). */
export function permissionGuard(permission: Permission): CanActivateFn {
  return () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    return auth.can(permission) ? true : router.createUrlTree(['/projects']);
  };
}
