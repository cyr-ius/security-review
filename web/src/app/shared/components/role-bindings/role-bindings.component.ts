import { Component, computed, inject, input, model } from '@angular/core';
import { AccessRole } from '../../../core/models/api.models';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** A role being given, on every project or on the selected ones. */
export interface RoleBindingDraft {
  roleId: number;
  allProjects: boolean;
  projects: string[];
}

/** Role bindings as sent to the API: an empty list of projects means every project. */
export function toRoleBindings(
  drafts: RoleBindingDraft[],
  roles: AccessRole[],
): { role_id: number; projects: string[] }[] {
  const scoped = new Map(roles.map((role) => [role.id, role.scoped] as const));
  return drafts.map((draft) => ({
    role_id: draft.roleId,
    projects: draft.allProjects || !scoped.get(draft.roleId) ? [] : draft.projects,
  }));
}

/** Drafts of stored role bindings (projects null: every project). */
export function toRoleDrafts(
  bindings: { role_id: number; projects: string[] | null }[],
): RoleBindingDraft[] {
  return bindings.map((binding) => ({
    roleId: binding.role_id,
    allProjects: binding.projects === null,
    projects: binding.projects ?? [],
  }));
}

/** True when every binding limited to projects lists at least one. */
export function roleDraftsComplete(drafts: RoleBindingDraft[]): boolean {
  return drafts.every((draft) => draft.allProjects || draft.projects.length > 0);
}

/**
 * Editor of the roles given to a group: each role applies to every project
 * or, when it is made of per-project permissions only, to the selected projects.
 */
@Component({
  selector: 'app-role-bindings',
  imports: [TranslatePipe],
  templateUrl: './role-bindings.component.html',
})
export class RoleBindingsComponent {
  private readonly i18n = inject(I18nService);

  /** Every role that can be given. */
  readonly roles = input<AccessRole[]>([]);
  /** Known projects, offered as checkboxes with those already selected. */
  readonly projects = input<string[]>([]);
  /** False while the known projects are loading. */
  readonly projectsLoaded = input(true);
  /** Prefix of the element ids, unique on the page. */
  readonly idPrefix = input('binding');
  readonly bindings = model<RoleBindingDraft[]>([]);

  /** Roles by id. */
  readonly roleById = computed(() => new Map(this.roles().map((role) => [role.id, role] as const)));

  /** Roles not given yet. */
  readonly availableRoles = computed(() => {
    const used = new Set(this.bindings().map((binding) => binding.roleId));
    return this.roles().filter((role) => !used.has(role.id));
  });

  /** Projects offered as checkboxes: known projects plus those already selected. */
  readonly projectChoices = computed(() => {
    const selected = this.bindings().flatMap((binding) => binding.projects);
    return [...new Set([...this.projects(), ...selected])].sort();
  });

  /** True when the role may be limited to projects (only scoped permissions). */
  scoped(roleId: number): boolean {
    return this.roleById().get(roleId)?.scoped ?? false;
  }

  roleName(role: AccessRole): string {
    return role.system ? `${role.name} — ${this.i18n.translate('roles.system')}` : role.name;
  }

  addBinding(event: Event): void {
    const select = event.target as HTMLSelectElement;
    const roleId = Number(select.value);
    select.value = '';
    if (roleId) {
      this.bindings.update((items) => [...items, { roleId, allProjects: true, projects: [] }]);
    }
  }

  removeBinding(index: number): void {
    this.bindings.update((items) => items.filter((_, position) => position !== index));
  }

  setAllProjects(index: number, allProjects: boolean): void {
    this.updateBinding(index, (binding) => ({ ...binding, allProjects }));
  }

  toggleProject(index: number, project: string, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.updateBinding(index, (binding) => ({
      ...binding,
      projects: checked
        ? [...binding.projects, project]
        : binding.projects.filter((item) => item !== project),
    }));
  }

  private updateBinding(
    index: number,
    change: (binding: RoleBindingDraft) => RoleBindingDraft,
  ): void {
    this.bindings.update((items) =>
      items.map((binding, position) => (position === index ? change(binding) : binding)),
    );
  }
}
