import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { describeAccessError } from '../../access/access-errors';

/** A user who has the project, being edited. */
interface MemberDraft {
  userId: number;
  readOnly: boolean;
}

/** Users listed by a search. */
const SEARCH_LIMIT = 50;

/**
 * The users who have one project (``users.manage``): several users found by a search are added
 * at once, then each row is read-only or not, or removed. The roles of a user apply to its
 * projects; the users who have every project and those of the OIDC mappings are not listed.
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

  /** Rows being edited, reset from the stored members. */
  readonly drafts = linkedSignal<MemberDraft[]>(() =>
    (this.members.value() ?? []).map((item) => ({
      userId: item.user_id,
      readOnly: item.read_only,
    })),
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
        .map((item) => `${item.userId}:${item.readOnly}`)
        .sort()
        .join(',');
    const stored = (this.members.value() ?? []).map((item) => ({
      userId: item.user_id,
      readOnly: item.read_only,
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
      ...picked.map((userId) => ({ userId, readOnly: false })),
    ]);
    this.picked.set([]);
  }

  setReadOnly(row: MemberDraft, event: Event): void {
    const readOnly = (event.target as HTMLInputElement).checked;
    this.drafts.update((items) =>
      items.map((item) => (item.userId === row.userId ? { ...item, readOnly } : item)),
    );
  }

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
          this.drafts().map((item) => ({ user_id: item.userId, read_only: item.readOnly })),
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
