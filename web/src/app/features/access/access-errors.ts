import { HttpErrorResponse } from '@angular/common/http';
import { Message, msg } from '../../core/i18n/i18n.service';

/** Message of a failed change of a role, of the roles of a user or of the OIDC mappings. */
export function describeAccessError(error: unknown): Message {
  if (error instanceof HttpErrorResponse) {
    const detail = typeof error.error?.detail === 'string' ? error.error.detail : null;
    if (detail?.includes('users.manage')) {
      return msg('access.lastManager');
    }
    if (error.status === 404) {
      return msg('access.notFound');
    }
    if (error.status === 409 || error.status === 422) {
      return detail ? msg('common.refusedDetail', { detail }) : msg('common.refused');
    }
  }
  return msg('access.failed');
}
