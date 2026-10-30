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

/** Users listed by a search. */
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
})
export class ProjectMembersComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly project = input.required<string>();
  /** Shown in a modal of the Projects page: the title names the project, no bottom margin. */
  readonly embedded = input(false);

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
  readonly picked = signal<number[]>([]);
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
    this.picked.set([]);
  }

  togglePick(userId: number, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.picked.update((items) =>
      checked ? [...items, userId] : items.filter((item) => item !== userId),
    );
  }

  add(): void {
    const allowed = new Set(this.choices().map((user) => user.id));
    const picked = this.picked().filter((userId) => allowed.has(userId));
    if (!picked.length) {
      return;
    }
    this.drafts.update((items) => [
      ...items,
      ...picked.map((userId) => ({ userId, permissions: ['reports.read' as Permission] })),
    ]);
    this.picked.set([]);
  }

  setPermissions(row: MemberDraft, permissions: Permission[]): void {
    this.drafts.update((items) =>
      items.map((item) => (item.userId === row.userId ? { ...item, permissions } : item)),
    );
  }

  /** Every row gives at least one permission. */
  readonly complete = computed(() => this.drafts().every((item) => item.permissions.length));

  remove(row: MemberDraft): void {
    this.drafts.update((items) => items.filter((item) => item.userId !== row.userId));
  }

  async save(): Promise<void> {
    if (this.busy()) {
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
