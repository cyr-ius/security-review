import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { SCOPED_PERMISSIONS } from '../../../core/constants/labels';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { describeAccessError } from '../../access/access-errors';

/** A role given to a user on the project, being edited. */
interface MemberDraft {
  userId: number;
  roleId: number;
}

/** Users listed by a search. */
const SEARCH_LIMIT = 50;

/**
 * The roles of the users on one project (``users.manage``): several users found by a search are
 * added at once with one role (reader by default), then each row may change role or be removed.
 * The roles on every project and those of the OIDC mappings are not listed here.
 */
@Component({
  selector: 'app-project-members',
  imports: [HelpLinkComponent, TranslatePipe],
  templateUrl: './project-members.component.html',
})
export class ProjectMembersComponent {
  private readonly api = inject(ApiService);

  readonly project = input.required<string>();

  readonly members = rxResource({
    params: () => this.project(),
    stream: ({ params }) => this.api.projectMembers(params),
  });
  readonly users = rxResource({ stream: () => this.api.users() });
  readonly roles = rxResource({ stream: () => this.api.roles() });

  /** Rows being edited, reset from the stored members. */
  readonly drafts = linkedSignal<MemberDraft[]>(() =>
    (this.members.value() ?? []).map((item) => ({ userId: item.user_id, roleId: item.role_id })),
  );
  readonly search = signal('');
  readonly picked = signal<number[]>([]);
  readonly pickedRole = signal(0);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  readonly usernames = computed(
    () => new Map((this.users.value() ?? []).map((user) => [user.id, user.username] as const)),
  );

  /** Roles that give something on a project. */
  readonly projectRoles = computed(() =>
    (this.roles.value() ?? []).filter((role) =>
      role.permissions.some((permission) => SCOPED_PERMISSIONS.has(permission)),
    ),
  );

  readonly addRole = computed(
    () =>
      this.pickedRole() ||
      this.projectRoles().find((role) => role.name === 'reader')?.id ||
      this.projectRoles()[0]?.id ||
      0,
  );

  /** Users whose name contains the search, without the chosen role yet. */
  readonly choices = computed(() => {
    const text = this.search().trim().toLowerCase();
    const role = this.addRole();
    const given = new Set(
      this.drafts()
        .filter((item) => item.roleId === role)
        .map((item) => item.userId),
    );
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
        .map((item) => `${item.userId}:${item.roleId}`)
        .sort()
        .join(',');
    const stored = (this.members.value() ?? []).map((item) => ({
      userId: item.user_id,
      roleId: item.role_id,
    }));
    return key(stored) !== key(this.drafts());
  });

  username(userId: number): string {
    return this.usernames().get(userId) ?? String(userId);
  }

  onSearch(event: Event): void {
    this.search.set((event.target as HTMLInputElement).value);
    this.picked.set([]);
  }

  onRole(event: Event): void {
    this.pickedRole.set(Number((event.target as HTMLSelectElement).value));
  }

  togglePick(userId: number, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.picked.update((items) =>
      checked ? [...items, userId] : items.filter((item) => item !== userId),
    );
  }

  add(): void {
    const roleId = this.addRole();
    const allowed = new Set(this.choices().map((user) => user.id));
    const picked = this.picked().filter((userId) => allowed.has(userId));
    if (!roleId || !picked.length) {
      return;
    }
    this.drafts.update((items) => [...items, ...picked.map((userId) => ({ userId, roleId }))]);
    this.picked.set([]);
  }

  changeRole(row: MemberDraft, event: Event): void {
    const roleId = Number((event.target as HTMLSelectElement).value);
    this.drafts.update((items) => {
      const others = items.filter((item) => item !== row);
      return others.some((item) => item.userId === row.userId && item.roleId === roleId)
        ? others
        : [...others, { userId: row.userId, roleId }];
    });
  }

  remove(row: MemberDraft): void {
    this.drafts.update((items) => items.filter((item) => item !== row));
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
          this.drafts().map((item) => ({ user_id: item.userId, role_id: item.roleId })),
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
