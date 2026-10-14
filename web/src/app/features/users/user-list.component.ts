import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { MIN_PASSWORD_CHARS } from '../../core/constants/passwords';
import { WebUser, WebUserRole } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

/** Labels of the roles of a web user. */
const ROLE_LABELS: Record<WebUserRole, string> = {
  reader: 'Lecture',
  triager: 'Triage',
  admin: 'Administration',
};

/**
 * Administrator page for the web users: accounts that log in with a username and a password,
 * their role and projects, password resets and deletion.
 */
@Component({
  selector: 'app-user-list',
  imports: [DatePipe],
  templateUrl: './user-list.component.html',
  styleUrl: './user-list.component.css',
})
export class UserListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);

  readonly roleLabels = ROLE_LABELS;
  readonly minPassword = MIN_PASSWORD_CHARS;
  readonly users = rxResource({ stream: () => this.api.users() });
  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly username = signal('');
  readonly role = signal<WebUserRole>('reader');
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

  /** Admin users always reach every project. */
  readonly projectsLocked = computed(() => this.role() === 'admin');

  /** Projects offered as checkboxes: known projects plus those of the edited user. */
  readonly projectChoices = computed(() => {
    const known = (this.projects.value() ?? []).map((item) => item.project);
    return [...new Set([...known, ...this.selectedProjects()])].sort();
  });

  readonly passwordTooShort = computed(
    () => this.password().length > 0 && this.password().length < MIN_PASSWORD_CHARS,
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
    return identity?.local_account === true && identity.client === user.username;
  }

  onRoleChange(event: Event): void {
    const role = (event.target as HTMLSelectElement).value as WebUserRole;
    this.role.set(role);
    if (role === 'admin') {
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
    this.role.set(user.role);
    this.allProjects.set(user.projects === null);
    this.selectedProjects.set(user.projects ?? []);
    this.password.set('');
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.username.set('');
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
    const role = this.role();
    const projects = this.allProjects() || this.projectsLocked() ? [] : this.selectedProjects();
    const editing = this.editing();
    await this.run(async () => {
      if (editing) {
        const updated = await firstValueFrom(this.api.updateUser(editing.id, role, projects));
        this.message.set(`Utilisateur « ${updated.username} » mis à jour.`);
      } else {
        const created = await firstValueFrom(
          this.api.createUser(this.username().trim(), role, projects, this.password() || null),
        );
        if (created.password) {
          this.createdPassword.set({ username: created.username, password: created.password });
        }
        this.message.set(`Utilisateur « ${created.username} » créé.`);
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
    if (this.busy() || !window.confirm(`Supprimer l'utilisateur « ${user.username} » ?`)) {
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
