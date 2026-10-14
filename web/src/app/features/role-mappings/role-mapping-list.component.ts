import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { MappedRole, RoleMapping } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';

/** Labels of the roles a mapping may grant. */
const ROLE_LABELS: Record<MappedRole, string> = {
  reader: 'Lecture',
  triager: 'Triage',
  admin: 'Administration',
};

/**
 * Administrator page for the OIDC role mapping: which web role, and which projects, the groups
 * or roles of the identity provider grant.
 */
@Component({
  selector: 'app-role-mapping-list',
  imports: [DatePipe],
  templateUrl: './role-mapping-list.component.html',
  styleUrl: './role-mapping-list.component.css',
})
export class RoleMappingListComponent {
  private readonly api = inject(ApiService);

  readonly roleLabels = ROLE_LABELS;
  readonly catalog = rxResource({ stream: () => this.api.roleMappings() });
  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly claimValue = signal('');
  readonly role = signal<MappedRole>('reader');
  /** Every project, or only the selected ones. */
  readonly allProjects = signal(true);
  readonly selectedProjects = signal<string[]>([]);
  /** Mapping whose projects are being edited (null: creation form). */
  readonly editing = signal<RoleMapping | null>(null);

  readonly message = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);

  /** Admin mappings always reach every project. */
  readonly projectsLocked = computed(() => this.role() === 'admin');

  /** Projects offered as checkboxes: known projects plus those already in the edited mapping. */
  readonly projectChoices = computed(() => {
    const known = (this.projects.value() ?? []).map((item) => item.project);
    return [...new Set([...known, ...this.selectedProjects()])].sort();
  });

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      (this.editing() !== null || this.claimValue().trim().length > 0) &&
      (this.allProjects() || this.projectsLocked() || this.selectedProjects().length > 0),
  );

  onRoleChange(event: Event): void {
    const role = (event.target as HTMLSelectElement).value as MappedRole;
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

  /** Load a stored mapping into the form to change its projects. */
  edit(mapping: RoleMapping): void {
    this.editing.set(mapping);
    this.claimValue.set(mapping.claim_value);
    this.role.set(mapping.role);
    this.allProjects.set(mapping.projects === null);
    this.selectedProjects.set(mapping.projects ?? []);
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.claimValue.set('');
    this.role.set('reader');
    this.allProjects.set(true);
    this.selectedProjects.set([]);
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const projects = this.allProjects() || this.projectsLocked() ? [] : this.selectedProjects();
    const editing = this.editing();
    await this.run(async () => {
      if (editing?.id !== undefined) {
        await firstValueFrom(this.api.updateRoleMapping(editing.id, projects));
        return `Projets du groupe « ${editing.claim_value} » mis à jour.`;
      }
      const created = await firstValueFrom(
        this.api.createRoleMapping(this.claimValue().trim(), this.role(), projects),
      );
      return `Groupe « ${created.claim_value} » associé au rôle ${ROLE_LABELS[created.role]}.`;
    });
  }

  async remove(mapping: RoleMapping): Promise<void> {
    const { id, claim_value, role } = mapping;
    if (
      id === undefined ||
      this.busy() ||
      !window.confirm(`Supprimer l'association « ${claim_value} » → ${ROLE_LABELS[role]} ?`)
    ) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.deleteRoleMapping(id));
      return `Association « ${claim_value} » supprimée.`;
    });
  }

  /** Run a change, show its outcome and reload the list. */
  private async run(action: () => Promise<string>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      this.message.set(await action());
      this.resetForm();
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    if (error.status === 404) {
      return "Cette association n'existe plus.";
    }
    if (error.status === 422 && typeof error.error?.detail === 'string') {
      return `Association refusée : ${error.error.detail}`;
    }
    if (error.status === 422) {
      return 'Association refusée : vérifiez le groupe, le rôle et les projets.';
    }
  }
  return 'La gestion des rôles SSO a échoué.';
}
