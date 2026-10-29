import { PERMISSION_META, SCOPED_PERMISSIONS } from '../../core/constants/labels';
import { I18nService } from '../../core/i18n/i18n.service';
import { AccessRole, Grants, Permission } from '../../core/models/api.models';

/**
 * Text of each permission of `grants`, in display order: a per-project permission names its
 * projects, e.g. ["Read the reports (shop-api, billing)", "Manage the tokens"]. Empty: no access.
 */
export function describeGrants(grants: Grants, i18n: I18nService): string[] {
  return (Object.keys(PERMISSION_META) as Permission[])
    .filter((permission) => permission in grants)
    .map((permission) => {
      const label = i18n.translate(PERMISSION_META[permission].label);
      if (!SCOPED_PERMISSIONS.has(permission)) {
        return label;
      }
      const projects = grants[permission];
      return projects
        ? i18n.translate('permission.onProjects', {
            permission: label,
            projects: projects.join(', '),
          })
        : i18n.translate('permission.onAllProjects', { permission: label });
    });
}

/**
 * Labels of the permissions of `role` that do not apply when it is given on a project (the
 * permissions on the whole Controller server), joined; empty when they all apply.
 */
export function ignoredOnProject(role: AccessRole | undefined, i18n: I18nService): string {
  return (role?.permissions ?? [])
    .filter((permission) => !SCOPED_PERMISSIONS.has(permission))
    .map((permission) => i18n.translate(PERMISSION_META[permission].label))
    .join(', ');
}
