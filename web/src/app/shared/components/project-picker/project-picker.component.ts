import { Component, computed, inject, input, model, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { Permission } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { ProjectPermissionsComponent } from '../project-permissions/project-permissions.component';

/** A project with the per-project permissions given there. */
export interface ProjectDraft {
  project: string;
  permissions: Permission[];
}

/** Projects returned by one search. */
const SEARCH_LIMIT = 50;
/** Permissions of a project just added: its reading. */
const DEFAULT_PERMISSIONS: Permission[] = ['reports.read'];

/**
 * Editor of a list of projects: a search of the known projects (on the controller), several of
 * them selected at once and added (with their reading), then the per-project permissions of each
 * row chosen in a multiple choice, or the row removed.
 */
@Component({
  selector: 'app-project-picker',
  imports: [ProjectPermissionsComponent, TranslatePipe],
  templateUrl: './project-picker.component.html',
  host: { class: 'd-block' },
})
export class ProjectPickerComponent {
  private readonly api = inject(ApiService);

  /** Prefix of the element ids, unique on the page. */
  readonly idPrefix = input('projects');
  readonly projects = model<ProjectDraft[]>([]);

  readonly search = signal('');
  /** Projects of the search results ticked to be added. */
  readonly picked = signal<string[]>([]);

  readonly results = rxResource({
    params: () => this.search().trim().toLowerCase(),
    stream: ({ params }) => this.api.searchProjects(params, SEARCH_LIMIT),
  });

  /** Search results not given yet. */
  readonly choices = computed(() => {
    const given = new Set(this.projects().map((item) => item.project));
    return (this.results.value() ?? []).map((item) => item.name).filter((name) => !given.has(name));
  });

  readonly rows = computed(() =>
    [...this.projects()].sort((left, right) => left.project.localeCompare(right.project)),
  );

  onSearch(event: Event): void {
    this.search.set((event.target as HTMLInputElement).value);
    this.picked.set([]);
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

  /** Add the ticked projects, with their reading. */
  add(): void {
    const picked = this.picked().filter((project) => this.choices().includes(project));
    if (!picked.length) {
      return;
    }
    this.projects.update((items) => [
      ...items,
      ...picked.map((project) => ({ project, permissions: [...DEFAULT_PERMISSIONS] })),
    ]);
    this.picked.set([]);
  }

  setPermissions(row: ProjectDraft, permissions: Permission[]): void {
    this.projects.update((items) =>
      items.map((item) => (item.project === row.project ? { ...item, permissions } : item)),
    );
  }

  remove(row: ProjectDraft): void {
    this.projects.update((items) => items.filter((item) => item.project !== row.project));
  }
}
