import { Component, computed, inject, input, model } from '@angular/core';
import { PERMISSION_META, SCOPED_PERMISSIONS } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { Permission } from '../../../core/models/api.models';
import { MultiSelectDropdownComponent } from '../multi-select-dropdown/multi-select-dropdown.component';

/**
 * Multiple choice of the per-project permissions (reading, triage) given with a project, with
 * every project or with a token.
 */
@Component({
  selector: 'app-project-permissions',
  imports: [MultiSelectDropdownComponent],
  template: `<app-multi-select-dropdown
    [id]="id()"
    [label]="label()"
    [allLabel]="noneLabel()"
    [options]="options()"
    [selected]="permissions()"
    (selectedChange)="onChange($event)"
  />`,
})
export class ProjectPermissionsComponent {
  private readonly i18n = inject(I18nService);

  /** Id of the button (a <label for> may target it). */
  readonly id = input.required<string>();
  /** Accessible name of the choice. */
  readonly label = input.required<string>();
  readonly permissions = model<Permission[]>([]);

  onChange(values: string[]): void {
    this.permissions.set(values as Permission[]);
  }

  readonly noneLabel = computed(() => this.i18n.translate('access.noPermission'));
  readonly options = computed(() =>
    [...SCOPED_PERMISSIONS].map((permission) => ({
      value: permission,
      label: this.i18n.translate(PERMISSION_META[permission].label),
    })),
  );
}
