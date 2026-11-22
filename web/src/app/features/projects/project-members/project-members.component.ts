import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { PERMISSION_META } from '../../../core/constants/labels';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { Permission } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { ProjectPermissionsComponent } from '../../../shared/components/project-permissions/project-permissions.component';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { describeAccessError } from '../../access/access-errors';

/** A user who has the project, with its per-project permissions there, being edited. */
interface MemberDraft {
  userId: number;
  permissions: Permission[];
}

/** Users suggested by a search. */
const SEARCH_LIMIT = 50;

/**
 * The users who have one project (``users.manage``): several users found by a search are added
 * at once (with its reading), then the per-project permissions of each row are chosen, or the
 * row removed. The users who have every project (themselves or by an OIDC mapping) are listed
 * apart, read only.
 */
@Component({
  selector: 'app-project-members',
  imports: [HelpLinkComponent, ProjectPermissionsComponent, TranslatePipe],
  templateUrl: './project-members.component.html',
  styleUrl: './project-members.component.css',
})
export class ProjectMembersComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly project = input.required<string>();
  /** Shown in a modal of the Projects page: the title names the project, no bottom margin. */
  readonly embedded = input(false);

  /** On the project page the card starts folded; the modal of the Projects page is always open. */
  readonly expanded = signal(false);
  readonly open = computed(() => this.embedded() || this.expanded());

  /** Folds or unfolds the card of the project page (the modal of the Projects page stays open). */
  toggle(): void {
    this.expanded.update((expanded) => !expanded);
  }

  readonly members = rxResource({
    params: () => this.project(),
    stream: ({ params }) => this.api.projectMembers(params),
  });
  readonly users = rxResource({ stream: () => this.api.users() });

  /** Rows being edited, reset from the stored members. */
  readonly drafts = linkedSignal<MemberDraft[]>(() => this.stored());

  /** Users given the project, with their permissions there. */
  private readonly stored = computed<MemberDraft[]>(() =>
    (this.members.value()?.data ?? [])
      .filter((item) => item.permissions.length)
      .map((item) => ({ userId: item.user_id, permissions: item.permissions })),
  );

  /** Users who have every project, with their permissions there (read only). */
  readonly allProjects = computed(() =>
    (this.members.value()?.data ?? []).filter((item) => item.all_projects_permissions.length),
  );
  readonly search = signal('');
  /** The list of suggestions under the search field. */
  readonly suggestionsOpen = signal(false);
  readonly activeIndex = signal(0);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  readonly usernames = computed(
    () => new Map((this.users.value() ?? []).map((user) => [user.id, user.username] as const)),
  );

  /** Users whose name contains the search, not members yet. */
  readonly choices = computed(() => {
    const text = this.search().trim().toLowerCase();
    const given = new Set(this.drafts().map((item) => item.userId));
    return (this.users.value() ?? [])
      .filter((user) => !given.has(user.id) && user.username.toLowerCase().includes(text))
      .slice(0, SEARCH_LIMIT);
  });

  /** Members whose name contains the search: shown greyed in the suggestions, not addable. */
  readonly matchingMembers = computed(() => {
    const text = this.search().trim().toLowerCase();
    return this.drafts()
      .map((item) => ({ id: item.userId, username: this.username(item.userId) }))
      .filter((user) => user.username.toLowerCase().includes(text))
      .sort((left, right) => left.username.localeCompare(right.username))
      .slice(0, SEARCH_LIMIT);
  });

  /** Suggestion chosen by Enter, kept within the list. */
  readonly active = computed(() =>
    Math.min(this.activeIndex(), Math.max(this.choices().length - 1, 0)),
  );

  readonly rows = computed(() =>
    [...this.drafts()].sort((left, right) =>
      this.username(left.userId).localeCompare(this.username(right.userId)),
    ),
  );

  /** True when the rows differ from the stored members. */
  readonly changed = computed(() => {
    const key = (items: MemberDraft[]) =>
      items
        .map((item) => `${item.userId}:${item.permissions.join('+')}`)
        .sort()
        .join(',');
    return key(this.stored()) !== key(this.drafts());
  });

  /** Labels of per-project permissions. */
  labels(permissions: Permission[]): string {
    return permissions
      .map((permission) => this.i18n.translate(PERMISSION_META[permission].label))
      .join(', ');
  }

  username(userId: number): string {
    return this.usernames().get(userId) ?? String(userId);
  }

  onSearch(event: Event): void {
    this.search.set((event.target as HTMLInputElement).value);
    this.activeIndex.set(0);
    this.suggestionsOpen.set(true);
  }

  /** Empty the search and give the focus back to its field. */
  clearSearch(field: HTMLInputElement): void {
    this.search.set('');
    this.activeIndex.set(0);
    field.focus();
  }

  /** Close the suggestions when the focus leaves the field and its list. */
  onSearchFocusOut(event: FocusEvent): void {
    const next = event.relatedTarget as Node | null;
    if (!next || !(event.currentTarget as HTMLElement).contains(next)) {
      this.suggestionsOpen.set(false);
    }
  }

  onSearchKeydown(event: KeyboardEvent): void {
    const count = this.choices().length;
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        this.suggestionsOpen.set(true);
        this.activeIndex.set(count ? (this.active() + 1) % count : 0);
        break;
      case 'ArrowUp':
        event.preventDefault();
        this.activeIndex.set(count ? (this.active() - 1 + count) % count : 0);
        break;
      case 'Enter': {
        event.preventDefault();
        const chosen = this.choices()[this.active()];
        if (this.suggestionsOpen() && chosen) {
          this.add(chosen.id);
        }
        break;
      }
      case 'Escape':
        if (this.suggestionsOpen()) {
          // A modal of the Projects page closes on Escape too: the list closes first
          event.stopPropagation();
          this.suggestionsOpen.set(false);
        }
        break;
    }
  }

  /** Add a suggested user as a member (with the reading); the search is emptied for the next. */
  add(userId: number): void {
    if (this.locked() || !this.choices().some((user) => user.id === userId)) {
      return;
    }
    this.drafts.update((items) => [
      ...items,
      { userId, permissions: ['reports.read' as Permission] },
    ]);
    this.search.set('');
    this.activeIndex.set(0);
    void this.save();
  }

  setPermissions(row: MemberDraft, permissions: Permission[]): void {
    this.drafts.update((items) =>
      items.map((item) => (item.userId === row.userId ? { ...item, permissions } : item)),
    );
    void this.save();
  }

  /** Every row gives at least one permission. */
  readonly complete = computed(() => this.drafts().every((item) => item.permissions.length));

  remove(row: MemberDraft): void {
    this.drafts.update((items) => items.filter((item) => item.userId !== row.userId));
    void this.save();
  }

  /** Saving, or reloading the saved members: the rows wait for it, a suggestion is not taken. */
  readonly locked = computed(() => this.busy() || this.members.isLoading());

  /** Each change is saved at once; a member without any permission waits for one (or removal). */
  private async save(): Promise<void> {
    if (this.busy() || !this.changed()) {
      return;
    }
    if (!this.complete()) {
      this.message.set(null);
      this.error.set(msg('projectMembers.permissionRequired'));
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(
        this.api.setProjectMembers(
          this.project(),
          this.drafts().map((item) => ({ user_id: item.userId, permissions: item.permissions })),
          this.members.value()?.version ?? null,
        ),
      );
      this.message.set(msg('projectMembers.saved'));
    } catch (error: unknown) {
      this.error.set(describeAccessError(error));
    } finally {
      this.busy.set(false);
      this.members.reload();
    }
  }
}
