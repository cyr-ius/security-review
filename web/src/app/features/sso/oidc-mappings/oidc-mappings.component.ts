import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { SCOPED_PERMISSIONS } from '../../../core/constants/labels';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { OidcRoleMapping, OidcRoleMappingWrite } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { describeAccessError } from '../../access/access-errors';

/** The mapping being added: a value of the claim, a role and its projects. */
interface MappingFormModel {
  claim: string;
  /** Id of the role, as the value of the select. */
  roleId: string;
  allProjects: boolean;
  /** Comma-separated project names (when not every project). */
  projects: string;
}

const EMPTY_MAPPING: MappingFormModel = { claim: '', roleId: '', allProjects: true, projects: '' };

/** Projects a mapping may name (as the API). */
const MAX_PROJECTS = 50;

/**
 * The OIDC mappings: each value of the roles claim gives a role, on every project or on a list
 * of projects (a project not created yet is ignored until it is). They apply at once to the OIDC
 * users, through the values of their claim at their last login.
 */
@Component({
  selector: 'app-oidc-mappings',
  imports: [FormField, HelpLinkComponent, TranslatePipe],
  templateUrl: './oidc-mappings.component.html',
})
export class OidcMappingsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly catalog = rxResource({ stream: () => this.api.oidcMappings() });
  readonly roles = rxResource({ stream: () => this.api.roles() });

  readonly mappingModel = signal<MappingFormModel>({ ...EMPTY_MAPPING });
  readonly mappingForm = form(this.mappingModel, (path) => {
    required(path.claim);
    maxLength(path.claim, 200);
    required(path.roleId);
    validate(path.projects, ({ value, valueOf }) => {
      if (valueOf(path.allProjects)) {
        return undefined;
      }
      const count = splitProjects(value()).length;
      return count === 0 || count > MAX_PROJECTS
        ? { kind: 'projects', message: this.i18n.translate('mappings.projectsHelp') }
        : undefined;
    });
  });

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Roles offered for a mapping on projects: those that give something there. */
  readonly projectRoles = computed(() =>
    (this.roles.value() ?? []).filter((role) =>
      role.permissions.some((permission) => SCOPED_PERMISSIONS.has(permission)),
    ),
  );

  /** Roles offered by the form, given its scope. */
  readonly roleChoices = computed(() =>
    this.mappingModel().allProjects ? (this.roles.value() ?? []) : this.projectRoles(),
  );

  readonly canSubmit = computed(() => !this.busy() && this.mappingForm().valid());

  async add(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const { claim, roleId, allProjects, projects } = this.mappingModel();
    const added: OidcRoleMappingWrite = {
      claim: claim.trim(),
      role_id: Number(roleId),
      projects: allProjects ? null : splitProjects(projects),
    };
    const ok = await this.save([...this.current(), added], msg('mappings.saved'));
    if (ok) {
      this.mappingForm().reset({ ...EMPTY_MAPPING });
    }
  }

  async remove(mapping: OidcRoleMapping): Promise<void> {
    const question = this.i18n.translate('mappings.confirmDelete', {
      claim: mapping.claim,
      role: mapping.role,
    });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.save(
      this.current().filter(
        (item) => item.claim !== mapping.claim || item.role_id !== mapping.role_id,
      ),
      msg('mappings.deleted', { claim: mapping.claim }),
    );
  }

  /** The stored mappings, as sent back to the API. */
  private current(): OidcRoleMappingWrite[] {
    return (this.catalog.value()?.mappings ?? []).map((item) => ({
      claim: item.claim,
      role_id: item.role_id,
      projects: item.projects,
    }));
  }

  /** Replace every mapping; true when it worked. */
  private async save(mappings: OidcRoleMappingWrite[], done: Message): Promise<boolean> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.setOidcMappings(mappings));
      this.message.set(done);
      return true;
    } catch (error: unknown) {
      this.error.set(describeAccessError(error));
      return false;
    } finally {
      this.busy.set(false);
      this.catalog.reload();
    }
  }
}

/** Project names of a comma-separated list, without blanks nor duplicates. */
function splitProjects(text: string): string[] {
  return [
    ...new Set(
      text
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
}
