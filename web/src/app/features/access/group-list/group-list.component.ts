import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { UserGroup } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import {
  RoleBindingDraft,
  RoleBindingsComponent,
  roleDraftsComplete,
  toRoleBindings,
  toRoleDrafts,
} from '../../../shared/components/role-bindings/role-bindings.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { compareTableText, filterAndSortRows } from '../../../shared/utils/table-utils';
import { describeAccessError } from '../access-errors';

/** Name, description and OIDC switch of the group being created or edited. */
interface GroupFormModel {
  name: string;
  description: string;
  sso: boolean;
}

const EMPTY_GROUP: GroupFormModel = { name: '', description: '', sso: false };

type GroupSortKey = 'name' | 'roles' | 'members' | 'created';

/**
 * Administrator page for the groups of web users: their roles (each on every project or on some
 * projects) and their members. A group open to OIDC also gets, at each login, the OIDC users whose
 * groups claim holds its name.
 */
@Component({
  selector: 'app-group-list',
  imports: [
    FormField,
    RouterLink,
    RefreshButtonComponent,
    RoleBindingsComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './group-list.component.html',
  styleUrl: '../access.css',
})
export class GroupListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly catalog = rxResource({ stream: () => this.api.groups() });
  readonly roles = rxResource({ stream: () => this.api.roles() });
  readonly users = rxResource({ stream: () => this.api.users() });
  readonly projects = rxResource({ stream: () => this.api.projects() });
  readonly tableSearch = signal('');
  readonly tableSort = signal<GroupSortKey>('name');
  readonly tableDirection = signal<'asc' | 'desc'>('asc');
  readonly groupTypeFilter = signal<'all' | 'oidc' | 'local'>('all');
  readonly tableSortOptions = computed(() => [
    { value: 'name', label: this.i18n.translate('access.name') },
    { value: 'roles', label: this.i18n.translate('layout.roles') },
    { value: 'members', label: this.i18n.translate('groups.members') },
    { value: 'created', label: this.i18n.translate('common.createdAt') },
  ]);
  readonly tableFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'type',
      label: this.i18n.translate('groups.type'),
      value: this.groupTypeFilter(),
      options: [
        { value: 'all', label: this.i18n.translate('common.all') },
        { value: 'oidc', label: this.i18n.translate('groups.sso') },
        { value: 'local', label: this.i18n.translate('groups.localOnly') },
      ],
    },
  ]);
  readonly visibleGroups = computed(() => {
    const type = this.groupTypeFilter();
    const groups = (this.catalog.value()?.groups ?? []).filter(
      (group) => type === 'all' || group.sso === (type === 'oidc'),
    );
    const sort = this.tableSort();
    return filterAndSortRows(
      groups,
      this.tableSearch(),
      this.tableDirection(),
      (group) =>
        [
          group.name,
          group.description,
          group.roles.map((role) => `${role.name} ${role.projects?.join(' ') ?? ''}`).join(' '),
          group.members.map((member) => member.username).join(' '),
        ].join(' '),
      (left, right) => {
        if (sort === 'roles') {
          return compareTableText(this.describeRoles(left), this.describeRoles(right));
        }
        if (sort === 'members') {
          const leftMembers = left.members
            .map((member) => member.username)
            .sort()
            .join(', ');
          const rightMembers = right.members
            .map((member) => member.username)
            .sort()
            .join(', ');
          return compareTableText(leftMembers, rightMembers);
        }
        if (sort === 'created') {
          return left.created_at.localeCompare(right.created_at);
        }
        return compareTableText(left.name, right.name);
      },
    );
  });

  readonly groupModel = signal<GroupFormModel>({ ...EMPTY_GROUP });
  readonly groupForm = form(this.groupModel, (path) => {
    required(path.name);
    maxLength(path.name, 200);
    maxLength(path.description, 500);
  });
  /** Roles of the group: a list edited row by row, kept apart from the model. */
  readonly bindings = signal<RoleBindingDraft[]>([]);
  /** Ids of the members added by an administrator. */
  readonly members = signal<number[]>([]);
  /** Group being edited (null: creation form). */
  readonly editing = signal<UserGroup | null>(null);

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  onGroupTableSort(value: string): void {
    if (value === 'name' || value === 'roles' || value === 'members' || value === 'created') {
      this.tableSort.set(value);
    }
  }

  onGroupTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'type') {
      this.groupTypeFilter.set(
        change.value === 'oidc' || change.value === 'local' ? change.value : 'all',
      );
    }
  }

  /** Names of the known projects. */
  readonly knownProjects = computed(() =>
    (this.projects.value() ?? []).map((item) => item.project),
  );

  /** Members of the edited group found in its groups claim at their last login. */
  readonly ssoMembers = computed(() =>
    (this.editing()?.members ?? []).filter((member) => member.source === 'oidc'),
  );

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      this.groupForm().valid() &&
      this.groupModel().name.trim().length > 0 &&
      roleDraftsComplete(this.bindings()),
  );

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
    this.groupForm().reset({ name: group.name, description: group.description, sso: group.sso });
    this.bindings.set(toRoleDrafts(group.roles));
    this.members.set(
      group.members.filter((member) => member.source === 'local').map((member) => member.user_id),
    );
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.groupForm().reset({ ...EMPTY_GROUP });
    this.bindings.set([]);
    this.members.set([]);
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const { name, description, sso } = this.groupModel();
    const body = { name: name.trim(), description: description.trim(), sso };
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
