import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { EnrollmentRequest, ProjectTokenRole } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';

/**
 * Administrator page for project tokens: enrollment requests waiting for approval, creation of
 * read-only tokens and revocation.
 */
@Component({
  selector: 'app-project-token-list',
  imports: [DatePipe],
  templateUrl: './project-token-list.component.html',
  styleUrl: './project-token-list.component.css',
})
export class ProjectTokenListComponent {
  private readonly api = inject(ApiService);

  readonly projects = rxResource({ stream: () => this.api.projects() });
  readonly tokens = rxResource({ stream: () => this.api.projectTokens() });
  readonly enrollments = rxResource({ stream: () => this.api.enrollments() });
  readonly label = signal('');
  readonly role = signal<ProjectTokenRole>('reader');
  readonly selectedProjects = signal<string[]>([]);
  readonly createdToken = signal<string | null>(null);
  readonly message = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  onRoleChange(event: Event): void {
    this.role.set((event.target as HTMLSelectElement).value as ProjectTokenRole);
  }

  toggleProject(project: string, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.selectedProjects.update((selected) =>
      checked ? [...selected, project] : selected.filter((item) => item !== project),
    );
  }

  async create(event: Event): Promise<void> {
    event.preventDefault();
    const label = this.label().trim();
    const role = this.role();
    const projects = this.selectedProjects();
    if (!label || !projects.length || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.createdToken.set(null);
    try {
      const created = await firstValueFrom(this.api.createProjectToken(label, projects, role));
      this.createdToken.set(created.token);
      this.label.set('');
      this.role.set('reader');
      this.selectedProjects.set([]);
      this.message.set(
        `Jeton « ${created.label} » (${created.role}) créé pour ${projects.join(', ')}.`,
      );
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  /** Reload every list of the page. */
  reload(): void {
    this.projects.reload();
    this.tokens.reload();
    this.enrollments.reload();
  }

  async approve(request: EnrollmentRequest): Promise<void> {
    const { id, label, project, kind } = request;
    if (this.busy() || !window.confirm(`Approuver la demande « ${label} » pour ${project} ?`)) {
      return;
    }
    await this.decide(
      () => firstValueFrom(this.api.approveEnrollment(id)),
      kind === 'additional'
        ? `Accès au projet ${project} ajouté au jeton « ${label} ».`
        : `Demande « ${label} » approuvée : le jeton est actif.`,
    );
  }

  async reject(id: string, label: string): Promise<void> {
    if (this.busy() || !window.confirm(`Refuser la demande « ${label} » ?`)) {
      return;
    }
    await this.decide(
      () => firstValueFrom(this.api.rejectEnrollment(id)),
      `Demande « ${label} » refusée.`,
    );
  }

  /** Apply a decision on an enrollment request and refresh the lists. */
  private async decide(action: () => Promise<unknown>, success: string): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
      this.message.set(success);
      this.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  async copyToken(): Promise<void> {
    const token = this.createdToken();
    if (!token) {
      return;
    }
    try {
      await navigator.clipboard.writeText(token);
      this.message.set('Jeton copié. Conservez-le en lieu sûr.');
    } catch {
      this.error.set('Copie impossible; sélectionnez le jeton et copiez-le manuellement.');
    }
  }

  async revoke(id: string, label: string): Promise<void> {
    if (this.busy() || !window.confirm(`Révoquer le jeton « ${label} » ?`)) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.deleteProjectToken(id));
      this.createdToken.set(null);
      this.message.set(`Jeton « ${label} » révoqué.`);
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse && error.status === 404) {
    return "Cette demande n'existe plus (déjà traitée ou expirée).";
  }
  if (error instanceof HttpErrorResponse && error.status === 409) {
    return 'Un jeton porte déjà ce label.';
  }
  if (error instanceof HttpErrorResponse && error.status === 503) {
    return "Le stockage des jetons projet n'est pas configuré.";
  }
  return 'La gestion des jetons a échoué.';
}
