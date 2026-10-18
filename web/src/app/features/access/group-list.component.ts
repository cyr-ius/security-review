import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { UserGroup } from '../../core/models/api.models';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import {
  RoleBindingDraft,
  RoleBindingsComponent,
  roleDraftsComplete,
  toRoleBindings,
  toRoleDrafts,
} from '../../shared/components/role-bindings/role-bindings.component';
import { describeAccessError } from './access-errors';

/**
 * Administrator page for the groups of web users: their roles (each on every project or on some
 * projects) and their members. A group open to SSO also gets, at each login, the SSO users whose
 * groups claim holds its name.
 */
@Component({
  selector: 'app-group-list',
  imports: [RouterLink, RefreshButtonComponent, RoleBindingsComponent, TranslatePipe],
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
  readonly bindings = signal<RoleBindingDraft[]>([]);
  /** Ids of the members added by an administrator. */
  readonly members = signal<number[]>([]);
  /** Group being edited (null: creation form). */
  readonly editing = signal<UserGroup | null>(null);

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Names of the known projects. */
  readonly knownProjects = computed(() =>
    (this.projects.value() ?? []).map((item) => item.project),
  );

  /** Members of the edited group found in its groups claim at their last login. */
  readonly ssoMembers = computed(() =>
    (this.editing()?.members ?? []).filter((member) => member.source === 'oidc'),
  );

  readonly canSubmit = computed(
    () => !this.busy() && this.name().trim().length > 0 && roleDraftsComplete(this.bindings()),
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

  /** Load a group into the form. */
  edit(group: UserGroup): void {
    this.editing.set(group);
    this.name.set(group.name);
    this.description.set(group.description);
    this.sso.set(group.sso);
    this.bindings.set(toRoleDrafts(group.roles));
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
    const roles = toRoleBindings(this.bindings(), this.roles.value() ?? []);
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
