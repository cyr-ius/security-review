import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { PERMISSION_META } from '../../../core/constants/labels';
import { AccessRole, Permission } from '../../../core/models/api.models';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { describeAccessError } from '../access-errors';

/** Name and description of the role being created or edited. */
interface RoleFormModel {
  name: string;
  description: string;
}

const EMPTY_ROLE: RoleFormModel = { name: '', description: '' };

/**
 * Administrator page for the roles: named sets of permissions, given to groups. The system roles
 * (reader, triager, admin) are shown but can be neither changed nor deleted.
 */
@Component({
  selector: 'app-role-list',
  imports: [DatePipe, FormField, RefreshButtonComponent, TranslatePipe],
  templateUrl: './role-list.component.html',
  styleUrl: '../access.css',
})
export class RoleListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly permissionMeta = PERMISSION_META;
  readonly roles = rxResource({ stream: () => this.api.roles() });
  readonly permissions = rxResource({ stream: () => this.api.permissions() });

  readonly roleModel = signal<RoleFormModel>({ ...EMPTY_ROLE });
  readonly roleForm = form(this.roleModel, (path) => {
    required(path.name);
    maxLength(path.name, 64);
    maxLength(path.description, 500);
  });
  /** Permissions ticked in the form (a list of checkboxes, kept apart from the model). */
  readonly selected = signal<Permission[]>([]);
  /** Role being edited (null: creation form). */
  readonly editing = signal<AccessRole | null>(null);

  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Only scoped permissions: the role may be limited to projects in a group. */
  readonly scoped = computed(() => {
    const scoped = new Set(
      (this.permissions.value() ?? []).filter((item) => item.scoped).map((item) => item.name),
    );
    return this.selected().every((permission) => scoped.has(permission));
  });

  readonly canSubmit = computed(
    () =>
      !this.busy() &&
      this.roleForm().valid() &&
      this.roleModel().name.trim().length > 0 &&
      this.selected().length > 0,
  );

  toggle(permission: Permission, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.selected.update((selected) =>
      checked ? [...selected, permission] : selected.filter((item) => item !== permission),
    );
  }

  /** Load a custom role into the form. */
  edit(role: AccessRole): void {
    this.editing.set(role);
    this.roleForm().reset({ name: role.name, description: role.description });
    this.selected.set([...role.permissions]);
    this.message.set(null);
    this.error.set(null);
  }

  resetForm(): void {
    this.editing.set(null);
    this.roleForm().reset({ ...EMPTY_ROLE });
    this.selected.set([]);
  }

  async submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!this.canSubmit()) {
      return;
    }
    const { name, description } = this.roleModel();
    const body = {
      name: name.trim(),
      description: description.trim(),
      permissions: this.selected(),
    };
    const editing = this.editing();
    await this.run(async () => {
      if (editing) {
        const updated = await firstValueFrom(this.api.updateRole(editing.id, body));
        return msg('roles.updated', { role: updated.name });
      }
      const created = await firstValueFrom(this.api.createRole(body));
      return msg('roles.created', { role: created.name });
    });
  }

  async remove(role: AccessRole): Promise<void> {
    const question = this.i18n.translate('roles.confirmDelete', {
      role: role.name,
      count: role.groups,
    });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.deleteRole(role.id));
      return msg('roles.deleted', { role: role.name });
    });
  }

  /** Run a change, show its outcome and reload the list. */
  private async run(action: () => Promise<Message>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      this.message.set(await action());
      this.resetForm();
    } catch (error: unknown) {
      this.error.set(describeAccessError(error));
    } finally {
      this.busy.set(false);
      this.roles.reload();
    }
  }
}
