import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { AccessRole, UserGroup } from '../../core/models/api.models';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import { describeAccessError } from './access-errors';

/** A role of the group being edited, on every project or on the selected ones. */
interface BindingDraft {
  roleId: number;
  allProjects: boolean;
  projects: string[];
}

/**
 * Administrator page for the groups of web users: their roles (each on every project or on some
 * projects) and their members. A group open to SSO also gets, at each login, the SSO users whose
 * groups claim holds its name.
 */
@Component({
  selector: 'app-group-list',
  imports: [RouterLink, RefreshButtonComponent, TranslatePipe],
  templateUrl: './group-list.component.html',
  styleUrl: './access.css',
})
export class GroupListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly catalog = rxResource({ stream: () => this.api.groups() });
  readonly roles = rxResource({ stream: () => this.api.roles() });
  readonly users = rxResource({ stream: () => this.api.users() });
  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly name = signal('');
  readonly description = signal('');
  readonly sso = signal(true);
  readonly bindings = signal<BindingDraft[]>([]);
  /** Ids of the members added by an administrator. */
  readonly members = signal<number[]>([]);
  /** Group being edited (null: creation form). */
  readonly editing = signal<UserGroup | null>(null);

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Roles by id. */
  readonly roleById = computed(
    () => new Map((this.roles.value() ?? []).map((role) => [role.id, role] as const)),
  );

  /** Roles not given yet to the edited group. */
  readonly availableRoles = computed(() => {
    const used = new Set(this.bindings().map((binding) => binding.roleId));
    return (this.roles.value() ?? []).filter((role) => !used.has(role.id));
  });

  /** Projects offered as checkboxes: known projects plus those already selected. */
  readonly projectChoices = computed(() => {
    const known = (this.projects.value() ?? []).map((item) => item.project);
    const selected = this.bindings().flatMap((binding) => binding.projects);
    return [...new Set([...known, ...selected])].sort();
  });

  /** Members of the edited group found in its groups claim at their last login. */
  readonly ssoMembers = computed(() =>
    (this.editing()?.members ?? []).filter((member) => member.source === 'oidc'),
  );

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      this.name().trim().length > 0 &&
      this.bindings().every((binding) => binding.allProjects || binding.projects.length > 0),
  );

  onName(event: Event): void {
    this.name.set((event.target as HTMLInputElement).value);
  }

  onDescription(event: Event): void {
    this.description.set((event.target as HTMLInputElement).value);
  }

  onSso(event: Event): void {
    this.sso.set((event.target as HTMLInputElement).checked);
  }

  /** True when the role may be limited to projects (only scoped permissions). */
  scoped(roleId: number): boolean {
    return this.roleById().get(roleId)?.scoped ?? false;
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

  toggleMember(userId: number, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.members.update((ids) =>
      checked ? [...ids, userId] : ids.filter((item) => item !== userId),
    );
  }

  /** Text of the roles of a group, e.g. "triager (shop-api, billing)". */
  describeRoles(group: UserGroup): string {
    if (!group.roles.length) {
      return '—';
    }
    const all = this.i18n.translate('reports.allProjects');
    return group.roles
      .map((role) => `${role.name} (${role.projects ? role.projects.join(', ') : all})`)
      .join(' · ');
  }

  roleName(role: AccessRole): string {
    return role.system ? `${role.name} — ${this.i18n.translate('roles.system')}` : role.name;
  }

  /** Load a group into the form. */
  edit(group: UserGroup): void {
    this.editing.set(group);
    this.name.set(group.name);
    this.description.set(group.description);
    this.sso.set(group.sso);
    this.bindings.set(
      group.roles.map((role) => ({
        roleId: role.role_id,
        allProjects: role.projects === null,
        projects: role.projects ?? [],
      })),
    );
    this.members.set(
      group.members.filter((member) => member.source === 'local').map((member) => member.user_id),
    );
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.name.set('');
    this.description.set('');
    this.sso.set(true);
    this.bindings.set([]);
    this.members.set([]);
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const body = {
      name: this.name().trim(),
      description: this.description().trim(),
      sso: this.sso(),
    };
    const roles = this.bindings().map((binding) => ({
      role_id: binding.roleId,
      projects: binding.allProjects || !this.scoped(binding.roleId) ? [] : binding.projects,
    }));
    const members = this.members();
    const editing = this.editing();
    await this.run(async () => {
      const group = editing
        ? await firstValueFrom(this.api.updateGroup(editing.id, body))
        : await firstValueFrom(this.api.createGroup(body));
      await firstValueFrom(this.api.setGroupRoles(group.id, roles));
      await firstValueFrom(this.api.setGroupMembers(group.id, members));
      return msg(editing ? 'groups.updated' : 'groups.created', { group: group.name });
    });
  }

  async remove(group: UserGroup): Promise<void> {
    const question = this.i18n.translate('groups.confirmDelete', {
      group: group.name,
      count: group.members.length,
    });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.deleteGroup(group.id));
      return msg('groups.deleted', { group: group.name });
    });
  }

  private updateBinding(index: number, change: (binding: BindingDraft) => BindingDraft): void {
    this.bindings.update((items) =>
      items.map((binding, position) => (position === index ? change(binding) : binding)),
    );
  }

  /** Run a change, show its outcome and reload the list. */
  private async run(action: () => Promise<Message>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      this.message.set(await action());
      this.resetForm();
    } catch (error: unknown) {
      this.error.set(describeAccessError(error));
    } finally {
      this.busy.set(false);
      this.catalog.reload();
      this.roles.reload();
    }
  }
}
