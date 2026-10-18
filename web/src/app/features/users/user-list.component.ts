import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { MIN_PASSWORD_CHARS } from '../../core/constants/passwords';
import { AuthSource, WebUser, WebUserRole } from '../../core/models/api.models';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import {
  RoleBindingDraft,
  RoleBindingsComponent,
  roleDraftsComplete,
  toRoleBindings,
  toRoleDrafts,
} from '../../shared/components/role-bindings/role-bindings.component';

/** Message keys of the roles of a web user. */
const ROLE_LABELS: Record<WebUserRole, MessageKey> = {
  reader: 'users.roleReader',
  triager: 'users.roleTriager',
  admin: 'users.roleAdmin',
};

/**
 * Administrator page for the web users, the only accounts of the web interface: local users
 * (username and password) and SSO users (OpenID Connect, created here or at their first login),
 * the groups given to them and the roles given to them directly on every project or on some
 * projects (both give the permissions), password resets and deletion.
 */
@Component({
  selector: 'app-user-list',
  imports: [DatePipe, RefreshButtonComponent, RoleBindingsComponent, TranslatePipe],
  templateUrl: './user-list.component.html',
  styleUrl: './user-list.component.css',
})
export class UserListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);

  readonly roleLabels = ROLE_LABELS;
  readonly minPassword = MIN_PASSWORD_CHARS;
  readonly users = rxResource({ stream: () => this.api.users() });
  /** Deleted SSO users, never created again by a login. */
  readonly revoked = rxResource({ stream: () => this.api.revokedUsers() });
  readonly groups = rxResource({ stream: () => this.api.groups() });
  readonly roles = rxResource({ stream: () => this.api.roles() });
  readonly projects = rxResource({ stream: () => this.api.projects() });
  /** Login methods of the controller: tells whether SSO users can log in. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });

  readonly username = signal('');
  readonly source = signal<AuthSource>('local');
  /** Ids of the groups given by an administrator (the SSO groups are kept apart). */
  readonly selectedGroups = signal<number[]>([]);
  /** Roles given directly to the user, each on every project or on the selected ones. */
  readonly bindings = signal<RoleBindingDraft[]>([]);
  /** Password typed by the administrator; empty: the controller generates one. */
  readonly password = signal('');
  /** User whose groups are being edited (null: creation form). */
  readonly editing = signal<WebUser | null>(null);

  /** Generated password, shown once with the user it belongs to. */
  readonly createdPassword = signal<{ username: string; password: string } | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Source of the user of the form (the edited one, or the one being created). */
  readonly formSource = computed(() => this.editing()?.auth_source ?? this.source());

  /** Names of the known projects. */
  readonly knownProjects = computed(() =>
    (this.projects.value() ?? []).map((item) => item.project),
  );

  /** Name of the identity provider on the login page; null when OIDC is not enabled. */
  readonly ssoName = computed(() => {
    const config = this.authConfig.value();
    return config?.oidc ? config.oidc_display_name : null;
  });

  /** SSO groups of the edited user (named by its groups claim at its last login). */
  readonly ssoGroups = computed(() =>
    (this.editing()?.groups ?? []).filter((group) => group.source === 'oidc'),
  );

  readonly passwordTooShort = computed(
    () =>
      this.formSource() === 'local' &&
      this.password().length > 0 &&
      this.password().length < MIN_PASSWORD_CHARS,
  );

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      !this.passwordTooShort() &&
      roleDraftsComplete(this.bindings()) &&
      (this.editing() !== null || this.username().trim().length > 0),
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

  /** Text of the direct roles of a user, e.g. "triager (shop-api, billing)". */
  describeRoles(user: WebUser): string {
    const all = this.i18n.translate('reports.allProjects');
    return user.roles
      .map((role) => `${role.name} (${role.projects ? role.projects.join(', ') : all})`)
      .join(' · ');
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

  onUsernameInput(event: Event): void {
    this.username.set((event.target as HTMLInputElement).value);
  }

  onPasswordInput(event: Event): void {
    this.password.set((event.target as HTMLInputElement).value);
  }

  onSourceChange(source: AuthSource): void {
    this.source.set(source);
    this.password.set('');
  }

  toggleGroup(groupId: number, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.selectedGroups.update((selected) =>
      checked ? [...selected, groupId] : selected.filter((item) => item !== groupId),
    );
  }

  /** Load a user into the form to change its groups and its direct roles. */
  edit(user: WebUser): void {
    this.editing.set(user);
    this.username.set(user.username);
    this.source.set(user.auth_source);
    this.selectedGroups.set(
      user.groups.filter((group) => group.source === 'local').map((group) => group.group_id),
    );
    this.bindings.set(toRoleDrafts(user.roles));
    this.password.set('');
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.username.set('');
    this.source.set('local');
    this.selectedGroups.set([]);
    this.bindings.set([]);
    this.password.set('');
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const groups = this.selectedGroups();
    const roles = toRoleBindings(this.bindings(), this.roles.value() ?? []);
    const editing = this.editing();
    const source = this.source();
    await this.run(async () => {
      if (editing) {
        const updated = await firstValueFrom(this.api.updateUser(editing.id, groups, roles));
        this.message.set(msg('users.updated', { user: updated.username }));
      } else {
        const password = source === 'local' ? this.password() || null : null;
        const created = await firstValueFrom(
          this.api.createUser(this.username().trim(), source, groups, password, roles),
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

  /** Let a deleted SSO user be created again at its next login. */
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
