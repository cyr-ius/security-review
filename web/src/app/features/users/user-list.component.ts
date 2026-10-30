import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, disabled, form, maxLength, required, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { PERMISSION_META } from '../../core/constants/labels';
import { MAX_PASSWORD_CHARS, followsPasswordPolicy } from '../../core/constants/passwords';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../shared/components/help-link/help-link.component';
import { AccessRole, AuthSource, Permission, WebUser } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import {
  MultiSelectDropdownComponent,
  MultiSelectOption,
} from '../../shared/components/multi-select-dropdown/multi-select-dropdown.component';
import { PasswordPolicyComponent } from '../../shared/components/password-policy/password-policy.component';
import {
  ProjectDraft,
  ProjectPickerComponent,
} from '../../shared/components/project-picker/project-picker.component';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../shared/components/table-controls/table-controls.component';
import { SortHeaderComponent } from '../../shared/components/sort-header/sort-header.component';
import { TableSort } from '../../shared/utils/table-sort';
import { describeGrants } from '../../shared/utils/permission-utils';
import { compareTableText, filterAndSortRows } from '../../shared/utils/table-utils';

/** Account type, name and password of the user being created (or edited: name only). */
interface UserFormModel {
  source: AuthSource;
  username: string;
  /** Empty: the controller generates one. */
  password: string;
}

const EMPTY_USER: UserFormModel = { source: 'local', username: '', password: '' };

type UserSortKey = 'username' | 'created' | 'lastLogin' | 'access';
type RevokedSortKey = 'username' | 'revoked_at' | 'revoked_by';

/**
 * Administrator page for the web users, the only accounts of the web interface: local users
 * (username and password) and OIDC users (OpenID Connect, created here or at their first login),
 * their roles (permissions on the whole server) and their projects with their per-project
 * permissions (with those of their OIDC mappings, the only source of their permissions),
 * password resets and deletion.
 */
@Component({
  selector: 'app-user-list',
  imports: [
    HelpLinkComponent,
    DatePipe,
    FormField,
    MultiSelectDropdownComponent,
    PasswordPolicyComponent,
    ProjectPickerComponent,
    RefreshButtonComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './user-list.component.html',
  styleUrl: './user-list.component.css',
})
export class UserListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);

  readonly users = rxResource({ stream: () => this.api.users() });
  /** Deleted OIDC users, never created again by a login. */
  readonly revoked = rxResource({ stream: () => this.api.revokedUsers() });
  readonly roles = rxResource({ stream: () => this.api.roles() });
  /** Login methods of the controller: tells whether OIDC users can log in. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });
  readonly tableSearch = signal('');
  readonly tableSort = new TableSort<UserSortKey>(
    'users',
    ['username', 'access', 'lastLogin', 'created'],
    'username',
    'asc',
  );
  readonly sourceFilter = signal<AuthSource | ''>('');
  readonly tableFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'source',
      label: this.i18n.translate('users.type'),
      value: this.sourceFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        { value: 'local', label: this.i18n.translate('users.localPassword') },
        { value: 'oidc', label: 'OIDC' },
      ],
    },
  ]);
  readonly visibleUsers = computed(() => {
    const source = this.sourceFilter();
    const users = (this.users.value() ?? []).filter(
      (user) => !source || user.auth_source === source,
    );
    const sort = this.tableSort.key();
    return filterAndSortRows(
      users,
      this.tableSearch(),
      this.tableSort.direction(),
      (user) =>
        [
          user.username,
          this.describeRoles(user).join(' '),
          this.describeProjects(user).join(' '),
          this.describe(user),
        ].join(' '),
      (left, right) => {
        if (sort === 'created') {
          return left.created_at.localeCompare(right.created_at);
        }
        if (sort === 'lastLogin') {
          return (left.last_login_at ?? '').localeCompare(right.last_login_at ?? '');
        }
        if (sort === 'access') {
          return compareTableText(this.describe(left), this.describe(right));
        }
        return compareTableText(left.username, right.username);
      },
    );
  });
  readonly revokedSearch = signal('');
  readonly revokedSort = new TableSort<RevokedSortKey>(
    'revoked-users',
    ['username', 'revoked_by', 'revoked_at'],
    'revoked_at',
    'desc',
  );
  readonly revokedByFilter = signal('');
  readonly revokedFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'revoked_by',
      label: this.i18n.translate('users.revokedBy'),
      value: this.revokedByFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...[
          ...new Set((this.revoked.value() ?? []).map((user) => user.revoked_by).filter(Boolean)),
        ].map((username) => ({ value: username as string, label: username as string })),
      ],
    },
  ]);
  readonly visibleRevoked = computed(() => {
    const revokedBy = this.revokedByFilter();
    const users = (this.revoked.value() ?? []).filter(
      (user) => !revokedBy || user.revoked_by === revokedBy,
    );
    const sort = this.revokedSort.key();
    return filterAndSortRows(
      users,
      this.revokedSearch(),
      this.revokedSort.direction(),
      (user) => [user.username, user.revoked_by ?? ''].join(' '),
      (left, right) => {
        if (sort === 'revoked_at') {
          return left.revoked_at.localeCompare(right.revoked_at);
        }
        if (sort === 'revoked_by') {
          return compareTableText(left.revoked_by ?? '', right.revoked_by ?? '');
        }
        return compareTableText(left.username, right.username);
      },
    );
  });

  /** User whose roles are being edited (null: creation form). */
  readonly editing = signal<WebUser | null>(null);
  readonly userModel = signal<UserFormModel>({ ...EMPTY_USER });
  readonly userForm = form(this.userModel, (path) => {
    required(path.username);
    maxLength(path.username, 64);
    // The name of an existing user never changes: only its roles are edited
    disabled(path.username, () => this.editing() !== null);
    maxLength(path.password, MAX_PASSWORD_CHARS);
    // Empty: the controller generates one; typed: it follows the password policy
    validate(path.password, ({ value, valueOf }) =>
      valueOf(path.source) === 'local' && value().length > 0 && !followsPasswordPolicy(value())
        ? { kind: 'policy', message: this.i18n.translate('password.policy') }
        : undefined,
    );
  });
  /** Ids of the roles of the user (those of the OIDC mappings are kept apart). */
  readonly selectedRoles = signal<number[]>([]);
  /** Roles offered in the list of roles of the user. */
  readonly roleOptions = computed<MultiSelectOption[]>(() =>
    (this.roles.value() ?? []).map((role) => ({
      value: String(role.id),
      label: this.roleLabel(role),
    })),
  );
  /** Selected roles, as values of the list. */
  readonly selectedRoleValues = computed(() => this.selectedRoles().map(String));
  /** Per-project permissions of the user on every project, null when "All projects" is not given. */
  readonly allProjectsPermissions = signal<Permission[] | null>(null);
  /** Projects of the user. */
  readonly projects = signal<ProjectDraft[]>([]);

  /** Generated password, shown once with the user it belongs to. */
  readonly createdPassword = signal<{ username: string; password: string } | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  onUserTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'source') {
      this.sourceFilter.set(
        change.value === 'local' || change.value === 'oidc' ? change.value : '',
      );
    }
  }

  onRevokedFilter(change: TableControlFilterChange): void {
    if (change.key === 'revoked_by') {
      this.revokedByFilter.set(change.value);
    }
  }

  /** Source of the user of the form (the edited one, or the one being created). */
  readonly formSource = computed(() => this.editing()?.auth_source ?? this.userModel().source);

  /** Name of the identity provider on the login page; null when OIDC is not enabled. */
  readonly ssoName = computed(() => {
    const config = this.authConfig.value();
    return config?.oidc ? config.oidc_display_name : null;
  });

  /** What the OIDC mappings of the edited user give (its claim at its last login). */
  readonly oidcAccess = computed(() => this.editing()?.oidc ?? []);

  readonly passwordInvalid = computed(
    () => this.formSource() === 'local' && this.userForm.password().invalid(),
  );

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      this.allProjectsPermissions()?.length !== 0 &&
      this.projects().every((item) => item.permissions.length > 0) &&
      (this.editing() !== null ||
        (this.userForm().valid() && this.userModel().username.trim().length > 0)),
  );

  /** True for the row of the logged-in user. */
  isSelf(user: WebUser): boolean {
    const identity = this.auth.identity();
    if (!identity || identity.auth_source !== user.auth_source) {
      return false;
    }
    const label = user.auth_source === 'oidc' ? `oidc:${user.username}` : user.username;
    return identity.client === label;
  }

  /** Permissions of a user, with their projects (empty: no access). */
  access(user: WebUser): string[] {
    return describeGrants(user.permissions, this.i18n);
  }

  /** Text of the access of a user, for the search and the sort. */
  describe(user: WebUser): string {
    return this.access(user).join(', ');
  }

  /** Roles of a user, with those of its OIDC mappings ("auditor ← devs"). */
  describeRoles(user: WebUser): string[] {
    return [
      ...user.roles.map((role) => role.name),
      ...user.oidc.flatMap((item) => item.roles.map((role) => `${role} ← ${item.claim}`)),
    ];
  }

  /** Projects of a user with their permissions, e.g. "shop-api: Read the reports". */
  describeProjects(user: WebUser): string[] {
    const all = this.i18n.translate('reports.allProjects');
    const text = (name: string, permissions: Permission[]) =>
      `${name}: ${permissions
        .map((permission) => this.i18n.translate(PERMISSION_META[permission].label))
        .join(', ')}`;
    return [
      ...(user.all_projects_permissions.length ? [text(all, user.all_projects_permissions)] : []),
      ...user.projects.map((item) => text(item.project, item.permissions)),
      ...user.oidc.flatMap((item) => [
        ...(item.all_projects_permissions.length
          ? [`${text(all, item.all_projects_permissions)} ← ${item.claim}`]
          : []),
        ...item.projects.map(
          (project) => `${text(project.project, project.permissions)} ← ${item.claim}`,
        ),
      ]),
    ];
  }

  roleLabel(role: AccessRole): string {
    return role.system ? `${role.name} — ${this.i18n.translate('roles.system')}` : role.name;
  }

  onRolesChange(values: string[]): void {
    this.selectedRoles.set(values.map(Number));
  }

  /** Load a user into the form to change its roles. */
  edit(user: WebUser): void {
    this.editing.set(user);
    this.userForm().reset({ source: user.auth_source, username: user.username, password: '' });
    this.selectedRoles.set(user.roles.map((role) => role.role_id));
    this.allProjectsPermissions.set(
      user.all_projects_permissions.length ? user.all_projects_permissions : null,
    );
    this.projects.set(
      user.projects.map((item) => ({ project: item.project, permissions: item.permissions })),
    );
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.userForm().reset({ ...EMPTY_USER });
    this.selectedRoles.set([]);
    this.allProjectsPermissions.set(null);
    this.projects.set([]);
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const roles = this.selectedRoles();
    const allProjects = this.allProjectsPermissions() ?? [];
    const projects = this.projects().map((item) => ({
      project: item.project,
      permissions: item.permissions,
    }));
    const editing = this.editing();
    const { source, username, password: typed } = this.userModel();
    await this.run(async () => {
      if (editing) {
        const updated = await firstValueFrom(
          this.api.updateUser(editing.id, roles, allProjects, projects),
        );
        this.message.set(msg('users.updated', { user: updated.username }));
      } else {
        const password = source === 'local' ? typed || null : null;
        const created = await firstValueFrom(
          this.api.createUser(username.trim(), source, roles, allProjects, projects, password),
        );
        if (created.password) {
          this.createdPassword.set({ username: created.username, password: created.password });
        }
        this.message.set(
          msg(source === 'oidc' ? 'users.ssoCreated' : 'users.created', {
            user: created.username,
          }),
        );
      }
      this.resetForm();
    });
  }

  async resetPassword(user: WebUser): Promise<void> {
    const question = this.i18n.translate('users.confirmReset', { user: user.username });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      const reset = await firstValueFrom(this.api.resetUserPassword(user.id, null));
      if (reset.password) {
        this.createdPassword.set({ username: reset.username, password: reset.password });
      }
      this.message.set(msg('users.resetDone', { user: reset.username }));
    });
  }

  async remove(user: WebUser): Promise<void> {
    const question = this.i18n.translate(
      user.auth_source === 'oidc' ? 'users.confirmDeleteSso' : 'users.confirmDelete',
      { user: user.username },
    );
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.deleteUser(user.id));
      if (this.editing()?.id === user.id) {
        this.resetForm();
      }
      this.message.set(msg('users.deleted', { user: user.username }));
    });
  }

  /** Let a deleted OIDC user be created again at its next login. */
  async liftRevocation(username: string): Promise<void> {
    const question = this.i18n.translate('users.confirmLift', { user: username });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.liftRevocation(username));
      this.message.set(msg('users.lifted', { user: username }));
    });
  }

  async copyPassword(): Promise<void> {
    const created = this.createdPassword();
    if (!created) {
      return;
    }
    try {
      await navigator.clipboard.writeText(created.password);
      this.message.set(msg('users.copied'));
    } catch {
      this.error.set(msg('users.copyFailed'));
    }
  }

  /** Run an action, show its error and refresh the list. */
  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
      this.users.reload();
      this.revoked.reload();
    }
  }
}

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse) {
    const detail = typeof error.error?.detail === 'string' ? error.error.detail : null;
    if (error.status === 409 && detail?.includes('users.manage')) {
      return msg('users.lastAdminDelete');
    }
    if (error.status === 409) {
      return msg('users.conflict');
    }
    if (error.status === 422 && detail?.includes('users.manage')) {
      return msg('users.lastAdminRole');
    }
    if (error.status === 422) {
      return detail ? msg('common.refusedDetail', { detail }) : msg('common.refused');
    }
    if (error.status === 404) {
      return msg('users.notFound');
    }
  }
  return msg('users.failed');
}
