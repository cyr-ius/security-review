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
  /** Whether SSO is enabled: approvals then offer web read access to the developer. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });
  /** Web access chosen for each pending request, by request id (default: see portalAccess). */
  private readonly portalChoices = signal<Record<string, PortalAccess>>({});
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

  /**
   * Web access offered with the approval: checked by default and filled with the requester,
   * which the administrator checks or corrects (the requester name is not verified).
   */
  portalAccess(request: EnrollmentRequest): PortalAccess {
    return (
      this.portalChoices()[request.id] ?? {
        enabled: Boolean(request.requested_by),
        user: request.requested_by ?? '',
      }
    );
  }

  setPortalAccess(request: EnrollmentRequest, change: Partial<PortalAccess>): void {
    const current = this.portalAccess(request);
    this.portalChoices.update((choices) => ({
      ...choices,
      [request.id]: { ...current, ...change },
    }));
  }

  /** OIDC user who gets read access with the approval, or null. */
  private portalUser(request: EnrollmentRequest): string | null {
    const access = this.portalAccess(request);
    return this.authConfig.value()?.oidc && access.enabled && access.user.trim()
      ? access.user.trim()
      : null;
  }

  async approve(request: EnrollmentRequest): Promise<void> {
    const { id, label, project, kind } = request;
    const portalUser = this.portalUser(request);
    const question = portalUser
      ? `Approuver la demande « ${label} » pour ${project} et donner la lecture du projet ` +
        `dans le portail à l'utilisateur SSO « ${portalUser} » ?`
      : `Approuver la demande « ${label} » pour ${project} ?`;
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    const approved =
      kind === 'additional'
        ? `Accès au projet ${project} ajouté au jeton « ${label} ».`
        : `Demande « ${label} » approuvée : le jeton est actif.`;
    await this.decide(
      () => firstValueFrom(this.api.approveEnrollment(id, portalUser)),
      portalUser
        ? `${approved} « ${portalUser} » peut lire ${project} dans le portail (prochaine connexion).`
        : approved,
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
      // The request may have been decided anyway (already processed, or approved without
      // its web access)
      this.enrollments.reload();
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

/** Web read access given to the developer when approving its enrollment. */
interface PortalAccess {
  enabled: boolean;
  /** Identifier of the user at the identity provider (username claim). */
  user: string;
}

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse && error.status === 422) {
    return typeof error.error?.detail === 'string'
      ? `Accès portail refusé : ${error.error.detail}`
      : 'Accès portail refusé : vérifiez l’identifiant SSO.';
  }
  if (
    error instanceof HttpErrorResponse &&
    error.status === 409 &&
    error.url?.includes('/approve')
  ) {
    return 'Demande approuvée, mais l’accès au portail n’a pas pu être accordé : réessayez depuis la page Rôles SSO.';
  }
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
