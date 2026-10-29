import { Component, computed, inject, input, model, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';

/** A project of a user; readOnly: only read, whatever the roles of the user. */
export interface ProjectDraft {
  project: string;
  readOnly: boolean;
}

/** Projects returned by one search. */
const SEARCH_LIMIT = 50;

/**
 * Editor of the projects of a user: a search of the known projects (on the controller), several
 * of them selected at once and added, then each row read-only or not, or removed. The roles of
 * the user apply to its projects; a read-only project is only read.
 */
@Component({
  selector: 'app-project-picker',
  imports: [TranslatePipe],
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

  /** Add the ticked projects. */
  add(): void {
    const picked = this.picked().filter((project) => this.choices().includes(project));
    if (!picked.length) {
      return;
    }
    this.projects.update((items) => [
      ...items,
      ...picked.map((project) => ({ project, readOnly: false })),
    ]);
    this.picked.set([]);
  }

  setReadOnly(row: ProjectDraft, event: Event): void {
    const readOnly = (event.target as HTMLInputElement).checked;
    this.projects.update((items) =>
      items.map((item) => (item.project === row.project ? { ...item, readOnly } : item)),
    );
  }

  remove(row: ProjectDraft): void {
    this.projects.update((items) => items.filter((item) => item.project !== row.project));
  }
}
