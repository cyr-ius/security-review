import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { MIN_PASSWORD_CHARS } from '../../core/constants/passwords';
import { AuthSource, WebUser, WebUserRole } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/** Labels of the roles of a web user. */
const ROLE_LABELS: Record<WebUserRole, string> = {
  reader: 'Lecture',
  triager: 'Triage',
  admin: 'Administration',
};

/** Role chosen in the form: a web role, or none (SSO user: only the role of its groups). */
type FormRole = WebUserRole | 'none';

/**
 * Administrator page for the web users, the only accounts of the web interface: local users
 * (username and password) and SSO users (OpenID Connect, created here or at their first login),
 * their role and projects, password resets and deletion.
 */
@Component({
  selector: 'app-user-list',
  imports: [DatePipe, RefreshButtonComponent],
  templateUrl: './user-list.component.html',
  styleUrl: './user-list.component.css',
})
export class UserListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);

  readonly roleLabels = ROLE_LABELS;
  readonly minPassword = MIN_PASSWORD_CHARS;
  readonly users = rxResource({ stream: () => this.api.users() });
  /** Deleted SSO users, never created again by a login. */
  readonly revoked = rxResource({ stream: () => this.api.revokedUsers() });
  readonly projects = rxResource({ stream: () => this.api.projects() });
  /** Login methods of the controller: tells whether SSO users can log in. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });

  readonly username = signal('');
  readonly source = signal<AuthSource>('local');
  readonly role = signal<FormRole>('reader');
  /** Every project, or only the selected ones. */
  readonly allProjects = signal(true);
  readonly selectedProjects = signal<string[]>([]);
  /** Password typed by the administrator; empty: the controller generates one. */
  readonly password = signal('');
  /** User whose role and projects are being edited (null: creation form). */
  readonly editing = signal<WebUser | null>(null);

  /** Generated password, shown once with the user it belongs to. */
  readonly createdPassword = signal<{ username: string; password: string } | null>(null);
  readonly message = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  /** Admin users always reach every project; a user without a role lists none. */
  readonly projectsLocked = computed(() => this.role() === 'admin' || this.role() === 'none');

  /** Source of the user of the form (the edited one, or the one being created). */
  readonly formSource = computed(() => this.editing()?.auth_source ?? this.source());

  /** Name of the identity provider on the login page; null when OIDC is not enabled. */
  readonly ssoName = computed(() => {
    const config = this.authConfig.value();
    return config?.oidc ? config.oidc_display_name : null;
  });

  /** Projects offered as checkboxes: known projects plus those of the edited user. */
  readonly projectChoices = computed(() => {
    const known = (this.projects.value() ?? []).map((item) => item.project);
    return [...new Set([...known, ...this.selectedProjects()])].sort();
  });

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
      (this.editing() !== null || this.username().trim().length > 0) &&
      (this.allProjects() || this.projectsLocked() || this.selectedProjects().length > 0),
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

  /** Text of a role and its projects, e.g. "Triage (shop-api, billing)". */
  describe(role: WebUserRole | null, projects: string[] | null): string {
    if (!role) {
      return '—';
    }
    return projects && role !== 'admin'
      ? `${ROLE_LABELS[role]} (${projects.join(', ')})`
      : `${ROLE_LABELS[role]} (tous les projets)`;
  }

  onSourceChange(source: AuthSource): void {
    this.source.set(source);
    this.password.set('');
    if (source === 'local' && this.role() === 'none') {
      this.role.set('reader');
    }
  }

  onRoleChange(event: Event): void {
    const role = (event.target as HTMLSelectElement).value as FormRole;
    this.role.set(role);
    if (role === 'admin' || role === 'none') {
      this.allProjects.set(true);
    }
  }

  toggleProject(project: string, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.selectedProjects.update((selected) =>
      checked ? [...selected, project] : selected.filter((item) => item !== project),
    );
  }

  /** Load a user into the form to change its role and projects. */
  edit(user: WebUser): void {
    this.editing.set(user);
    this.username.set(user.username);
    this.source.set(user.auth_source);
    this.role.set(user.role ?? 'none');
    this.allProjects.set(user.projects === null);
    this.selectedProjects.set(user.projects ?? []);
    this.password.set('');
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.username.set('');
    this.source.set('local');
    this.role.set('reader');
    this.allProjects.set(true);
    this.selectedProjects.set([]);
    this.password.set('');
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const chosen = this.role();
    const role = chosen === 'none' ? null : chosen;
    const projects = this.allProjects() || this.projectsLocked() ? [] : this.selectedProjects();
    const editing = this.editing();
    const source = this.source();
    await this.run(async () => {
      if (editing) {
        const updated = await firstValueFrom(this.api.updateUser(editing.id, role, projects));
        this.message.set(`Utilisateur « ${updated.username} » mis à jour.`);
      } else {
        const password = source === 'local' ? this.password() || null : null;
        const created = await firstValueFrom(
          this.api.createUser(this.username().trim(), source, role, projects, password),
        );
        if (created.password) {
          this.createdPassword.set({ username: created.username, password: created.password });
        }
        this.message.set(
          source === 'oidc'
            ? `Utilisateur SSO « ${created.username} » créé : il se connecte avec le fournisseur d'identité.`
            : `Utilisateur « ${created.username} » créé.`,
        );
      }
      this.resetForm();
    });
  }

  async resetPassword(user: WebUser): Promise<void> {
    const question =
      `Générer un nouveau mot de passe pour « ${user.username} » ? ` +
      'Ses sessions ouvertes seront fermées.';
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      const reset = await firstValueFrom(this.api.resetUserPassword(user.id, null));
      if (reset.password) {
        this.createdPassword.set({ username: reset.username, password: reset.password });
      }
      this.message.set(`Mot de passe de « ${reset.username} » réinitialisé.`);
    });
  }

  async remove(user: WebUser): Promise<void> {
    const question =
      user.auth_source === 'oidc'
        ? `Supprimer l'utilisateur SSO « ${user.username} » ? Ses sessions sont fermées et il ` +
          "ne sera plus recréé à sa connexion, jusqu'à ce que vous le recréiez ou l'autorisiez " +
          'à nouveau.'
        : `Supprimer l'utilisateur « ${user.username} » ?`;
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.deleteUser(user.id));
      if (this.editing()?.id === user.id) {
        this.resetForm();
      }
      this.message.set(`Utilisateur « ${user.username} » supprimé.`);
    });
  }

  /** Let a deleted SSO user be created again at its next login. */
  async liftRevocation(username: string): Promise<void> {
    const question =
      `Autoriser à nouveau « ${username} » ? Avec la création automatique, son compte SSO ` +
      'sera recréé à sa prochaine connexion si ses groupes lui donnent un rôle.';
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.liftRevocation(username));
      this.message.set(`« ${username} » peut de nouveau être créé à sa connexion.`);
    });
  }

  async copyPassword(): Promise<void> {
    const created = this.createdPassword();
    if (!created) {
      return;
    }
    try {
      await navigator.clipboard.writeText(created.password);
      this.message.set('Mot de passe copié. Transmettez-le par un canal sûr.');
    } catch {
      this.error.set('Copie impossible ; sélectionnez le mot de passe et copiez-le manuellement.');
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

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    const detail = typeof error.error?.detail === 'string' ? error.error.detail : null;
    if (error.status === 409 && detail?.includes('last administrator')) {
      return 'Le dernier administrateur ne peut pas être supprimé.';
    }
    if (error.status === 409) {
      return 'Un utilisateur porte déjà cet identifiant.';
    }
    if (error.status === 422 && detail?.includes('last administrator')) {
      return 'Le dernier administrateur doit garder le rôle administration.';
    }
    if (error.status === 422) {
      return detail ? `Données refusées : ${detail}` : 'Données refusées par le serveur.';
    }
    if (error.status === 404) {
      return "Cet utilisateur n'existe plus.";
    }
  }
  return 'La gestion des utilisateurs a échoué.';
}
