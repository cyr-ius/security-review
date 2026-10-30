import { Component, computed, inject, input, model, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { Permission } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import {
  MultiSelectDropdownComponent,
  MultiSelectOption,
} from '../multi-select-dropdown/multi-select-dropdown.component';
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
/** Value of "All projects" in the ticked results (no project name holds a "*"). */
const ALL_PROJECTS = '*';

/**
 * Editor of a list of projects: a multiple choice with a search of the known projects (on the
 * controller), several of them selected at once and added (with their reading), then the
 * per-project permissions of each row chosen in a multiple choice, or the row removed. With
 * ``withAllProjects``, "All projects" is offered first and given the same way.
 */
@Component({
  selector: 'app-project-picker',
  imports: [MultiSelectDropdownComponent, ProjectPermissionsComponent, TranslatePipe],
  templateUrl: './project-picker.component.html',
  host: { class: 'd-block' },
})
export class ProjectPickerComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  /** Prefix of the element ids, unique on the page. */
  readonly idPrefix = input('projects');
  readonly projects = model<ProjectDraft[]>([]);
  /** Offer "All projects" among the results. */
  readonly withAllProjects = input(false);
  /** Per-project permissions on every project, or null when "All projects" is not given. */
  readonly allProjects = model<Permission[] | null>(null);

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

  /** "All projects" can be ticked: offered and not given yet. */
  readonly offerAllProjects = computed(() => this.withAllProjects() && this.allProjects() === null);

  /** Options of the multiple choice: "All projects", then the search results not given yet. */
  readonly options = computed<MultiSelectOption[]>(() => [
    ...(this.offerAllProjects()
      ? [
          {
            value: ALL_PROJECTS,
            label: this.i18n.translate('reports.allProjects'),
            strong: true,
            divider: true,
            standalone: true,
          },
        ]
      : []),
    ...this.choices().map((project) => ({
      value: project,
      label: project,
      monospace: true,
      disabled: this.picked().includes(ALL_PROJECTS),
    })),
  ]);

  /** Text under the options: loading, no project found, or the search to refine. */
  readonly note = computed(() => {
    if (this.results.isLoading() && !this.results.hasValue()) {
      return this.i18n.translate('common.loading');
    }
    if (!this.results.isLoading() && !this.choices().length) {
      return this.i18n.translate('access.noProjectFound');
    }
    if ((this.results.value() ?? []).length >= SEARCH_LIMIT) {
      return this.i18n.translate('access.refineSearch');
    }
    return null;
  });

  readonly rows = computed(() =>
    [...this.projects()].sort((left, right) => left.project.localeCompare(right.project)),
  );

  /** Ticking "All projects" unticks the projects, which it already reaches. */
  onPick(values: string[]): void {
    this.picked.set(values.includes(ALL_PROJECTS) ? [ALL_PROJECTS] : values);
  }

  onSearch(search: string): void {
    this.search.set(search);
    this.picked.update((items) => items.filter((item) => item === ALL_PROJECTS));
  }

  /** Add the ticked projects, with their reading. */
  add(): void {
    if (this.offerAllProjects() && this.picked().includes(ALL_PROJECTS)) {
      this.allProjects.set([...DEFAULT_PERMISSIONS]);
    }
    const picked = this.picked().filter((project) => this.choices().includes(project));
    this.picked.set([]);
    if (!picked.length) {
      return;
    }
    this.projects.update((items) => [
      ...items,
      ...picked.map((project) => ({ project, permissions: [...DEFAULT_PERMISSIONS] })),
    ]);
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
