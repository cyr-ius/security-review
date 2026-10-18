import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, disabled, form, maxLength, required, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { MAX_PASSWORD_CHARS, followsPasswordPolicy } from '../../core/constants/passwords';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AuthSource, WebUser, WebUserRole } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { PasswordPolicyComponent } from '../../shared/components/password-policy/password-policy.component';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import {
    TableControlFilter,
    TableControlFilterChange,
    TableControlsComponent,
} from '../../shared/components/table-controls/table-controls.component';
import { compareTableText, filterAndSortRows } from '../../shared/utils/table-utils';

/** Message keys of the roles of a web user. */
const ROLE_LABELS: Record<WebUserRole, MessageKey> = {
  reader: 'users.roleReader',
  triager: 'users.roleTriager',
  admin: 'users.roleAdmin',
};

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
 * the groups given to them (the only source of their permissions: an account has no role of its
 * own), password resets and deletion.
 */
@Component({
  selector: 'app-user-list',
  imports: [
    DatePipe,
    FormField,
    PasswordPolicyComponent,
    RefreshButtonComponent,
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

  readonly roleLabels = ROLE_LABELS;
  readonly users = rxResource({ stream: () => this.api.users() });
  /** Deleted OIDC users, never created again by a login. */
  readonly revoked = rxResource({ stream: () => this.api.revokedUsers() });
  readonly groups = rxResource({ stream: () => this.api.groups() });
  /** Login methods of the controller: tells whether OIDC users can log in. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });
  readonly tableSearch = signal('');
  readonly tableSort = signal<UserSortKey>('username');
  readonly tableDirection = signal<'asc' | 'desc'>('asc');
  readonly sourceFilter = signal<AuthSource | ''>('');
  readonly tableSortOptions = computed(() => [
    { value: 'username', label: this.i18n.translate('login.username') },
    { value: 'created', label: this.i18n.translate('common.createdAt') },
    { value: 'lastLogin', label: this.i18n.translate('users.lastLogin') },
    { value: 'access', label: this.i18n.translate('users.access') },
  ]);
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
    const sort = this.tableSort();
    return filterAndSortRows(
      users,
      this.tableSearch(),
      this.tableDirection(),
      (user) =>
        [user.username, user.groups.map((group) => group.name).join(' '), this.describe(user)].join(
          ' ',
        ),
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
  readonly revokedSort = signal<RevokedSortKey>('revoked_at');
  readonly revokedDirection = signal<'asc' | 'desc'>('desc');
  readonly revokedByFilter = signal('');
  readonly revokedSortOptions = computed(() => [
    { value: 'username', label: this.i18n.translate('login.username') },
    { value: 'revoked_at', label: this.i18n.translate('users.revokedAt') },
    { value: 'revoked_by', label: this.i18n.translate('users.revokedBy') },
  ]);
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
    const sort = this.revokedSort();
    return filterAndSortRows(
      users,
      this.revokedSearch(),
      this.revokedDirection(),
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

  /** User whose groups are being edited (null: creation form). */
  readonly editing = signal<WebUser | null>(null);
  readonly userModel = signal<UserFormModel>({ ...EMPTY_USER });
  readonly userForm = form(this.userModel, (path) => {
    required(path.username);
    maxLength(path.username, 64);
    // The name of an existing user never changes: only its groups are edited
    disabled(path.username, () => this.editing() !== null);
    maxLength(path.password, MAX_PASSWORD_CHARS);
    // Empty: the controller generates one; typed: it follows the password policy
    validate(path.password, ({ value, valueOf }) =>
      valueOf(path.source) === 'local' && value().length > 0 && !followsPasswordPolicy(value())
        ? { kind: 'policy', message: this.i18n.translate('password.policy') }
        : undefined,
    );
  });
  /** Ids of the groups given by an administrator (the OIDC groups are kept apart). */
  readonly selectedGroups = signal<number[]>([]);

  /** Generated password, shown once with the user it belongs to. */
  readonly createdPassword = signal<{ username: string; password: string } | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  onUserTableSort(value: string): void {
    if (
      value === 'username' ||
      value === 'created' ||
      value === 'lastLogin' ||
      value === 'access'
    ) {
      this.tableSort.set(value);
    }
  }

  onUserTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'source') {
      this.sourceFilter.set(
        change.value === 'local' || change.value === 'oidc' ? change.value : '',
      );
    }
  }

  onRevokedSort(value: string): void {
    if (value === 'username' || value === 'revoked_at' || value === 'revoked_by') {
      this.revokedSort.set(value);
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

  /** OIDC groups of the edited user (named by its groups claim at its last login). */
  readonly ssoGroups = computed(() =>
    (this.editing()?.groups ?? []).filter((group) => group.source === 'oidc'),
  );

  readonly passwordInvalid = computed(
    () => this.formSource() === 'local' && this.userForm.password().invalid(),
  );

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
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

  /** Text of the access of a user, e.g. "Triage (shop-api, billing)". */
  describe(user: WebUser): string {
    if (!user.effective_role) {
      return '—';
    }
    const label = this.i18n.translate(ROLE_LABELS[user.effective_role]);
    const projects = user.permissions['reports.read'];
    return projects
      ? `${label} (${projects.join(', ')})`
      : this.i18n.translate('users.roleAllProjects', { role: label });
  }

  toggleGroup(groupId: number, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.selectedGroups.update((selected) =>
      checked ? [...selected, groupId] : selected.filter((item) => item !== groupId),
    );
  }

  /** Load a user into the form to change its groups. */
  edit(user: WebUser): void {
    this.editing.set(user);
    this.userForm().reset({ source: user.auth_source, username: user.username, password: '' });
    this.selectedGroups.set(
      user.groups.filter((group) => group.source === 'local').map((group) => group.group_id),
    );
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.userForm().reset({ ...EMPTY_USER });
    this.selectedGroups.set([]);
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const groups = this.selectedGroups();
    const editing = this.editing();
    const { source, username, password: typed } = this.userModel();
    await this.run(async () => {
      if (editing) {
        const updated = await firstValueFrom(this.api.updateUser(editing.id, groups));
        this.message.set(msg('users.updated', { user: updated.username }));
      } else {
        const password = source === 'local' ? typed || null : null;
        const created = await firstValueFrom(
          this.api.createUser(username.trim(), source, groups, password),
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
