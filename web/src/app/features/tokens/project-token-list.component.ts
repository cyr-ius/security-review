import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { ApiService } from '../../core/services/api.service';

/** Administrator page for creating and revoking read-only project tokens. */
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
  readonly label = signal('');
  readonly project = signal('');
  readonly createdToken = signal<string | null>(null);
  readonly message = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  onProjectChange(event: Event): void {
    this.project.set((event.target as HTMLSelectElement).value);
  }

  async create(event: Event): Promise<void> {
    event.preventDefault();
    const label = this.label().trim();
    const project = this.project();
    if (!label || !project || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.createdToken.set(null);
    try {
      const created = await firstValueFrom(this.api.createProjectToken(label, project));
      this.createdToken.set(created.token);
      this.label.set('');
      this.message.set(`Jeton « ${created.label} » créé pour ${created.project}.`);
      this.tokens.reload();
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
  if (error instanceof HttpErrorResponse && error.status === 409) {
    return 'Un jeton porte déjà ce label.';
  }
  if (error instanceof HttpErrorResponse && error.status === 503) {
    return "Le stockage des jetons projet n'est pas configuré.";
  }
  return 'La gestion des jetons a échoué.';
}
