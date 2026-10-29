import { Component, computed, inject, input, model, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { SCOPED_PERMISSIONS } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { AccessRole } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { ignoredOnProject } from '../../utils/permission-utils';

/** A role given on a project. */
export interface ProjectRoleDraft {
  project: string;
  roleId: number;
}

/** Projects returned by one search. */
const SEARCH_LIMIT = 50;

/**
 * Editor of the roles given on projects: a search of the known projects (on the controller),
 * several of them selected at once and added with one role (reader by default), then a role per
 * row. Only the roles that hold a per-project permission are offered: the others give nothing on
 * a project.
 */
@Component({
  selector: 'app-project-roles',
  imports: [TranslatePipe],
  templateUrl: './project-roles.component.html',
  host: { class: 'd-block' },
})
export class ProjectRolesComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  /** Every role. */
  readonly roles = input<AccessRole[]>([]);
  /** Prefix of the element ids, unique on the page. */
  readonly idPrefix = input('project-roles');
  readonly bindings = model<ProjectRoleDraft[]>([]);

  readonly search = signal('');
  /** Projects of the search results ticked to be added. */
  readonly picked = signal<string[]>([]);
  /** Role given to the projects added (0: reader). */
  readonly pickedRole = signal(0);

  readonly results = rxResource({
    params: () => this.search().trim().toLowerCase(),
    stream: ({ params }) => this.api.searchProjects(params, SEARCH_LIMIT),
  });

  /** Roles that give something on a project. */
  readonly projectRoles = computed(() =>
    this.roles().filter((role) =>
      role.permissions.some((permission) => SCOPED_PERMISSIONS.has(permission)),
    ),
  );

  readonly roleById = computed(() => new Map(this.roles().map((role) => [role.id, role] as const)));

  /** Role chosen for the projects to add: the picked one, else reader. */
  readonly addRole = computed(
    () =>
      this.pickedRole() ||
      this.projectRoles().find((role) => role.name === 'reader')?.id ||
      this.projectRoles()[0]?.id ||
      0,
  );

  /** Search results not given the chosen role yet. */
  readonly choices = computed(() => {
    const role = this.addRole();
    const given = new Set(
      this.bindings()
        .filter((binding) => binding.roleId === role)
        .map((binding) => binding.project),
    );
    return (this.results.value() ?? []).map((item) => item.name).filter((name) => !given.has(name));
  });

  /** Rows sorted by project, then role name. */
  readonly rows = computed(() =>
    [...this.bindings()].sort(
      (left, right) =>
        left.project.localeCompare(right.project) ||
        this.roleName(left.roleId).localeCompare(this.roleName(right.roleId)),
    ),
  );

  /** Permissions of a role that give nothing on a project (empty: none). */
  ignored(roleId: number): string {
    return ignoredOnProject(this.roleById().get(roleId), this.i18n);
  }

  roleName(roleId: number): string {
    return this.roleById().get(roleId)?.name ?? String(roleId);
  }

  onSearch(event: Event): void {
    this.search.set((event.target as HTMLInputElement).value);
    this.picked.set([]);
  }

  onRole(event: Event): void {
    this.pickedRole.set(Number((event.target as HTMLSelectElement).value));
  }

  togglePick(project: string, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.picked.update((items) =>
      checked ? [...items, project] : items.filter((item) => item !== project),
    );
  }

  /** Tick every search result, or none when they all are. */
  toggleAll(): void {
    const choices = this.choices();
    this.picked.set(choices.every((project) => this.picked().includes(project)) ? [] : choices);
  }

  /** Add the ticked projects with the chosen role. */
  add(): void {
    const roleId = this.addRole();
    const picked = this.picked().filter((project) => this.choices().includes(project));
    if (!roleId || !picked.length) {
      return;
    }
    this.bindings.update((items) => [...items, ...picked.map((project) => ({ project, roleId }))]);
    this.picked.set([]);
  }

  /** Change the role of one row (a duplicate row is dropped). */
  changeRole(row: ProjectRoleDraft, event: Event): void {
    const roleId = Number((event.target as HTMLSelectElement).value);
    this.bindings.update((items) => {
      const others = items.filter((item) => item !== row);
      return others.some((item) => item.project === row.project && item.roleId === roleId)
        ? others
        : [...others, { project: row.project, roleId }];
    });
  }

  remove(row: ProjectRoleDraft): void {
    this.bindings.update((items) => items.filter((item) => item !== row));
  }
}
