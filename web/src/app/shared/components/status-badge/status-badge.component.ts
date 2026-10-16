import { Component, computed, input } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { STATUS_META } from '../../../core/constants/labels';
import { FindingStatus } from '../../../core/models/api.models';

/** Finding status shown as an icon followed by its name. */
@Component({
  imports: [TranslatePipe],
  selector: 'app-status-badge',
  templateUrl: './status-badge.component.html',
  styleUrl: './status-badge.component.css',
})
export class StatusBadgeComponent {
  readonly status = input.required<FindingStatus>();

  readonly meta = computed(() => STATUS_META[this.status()]);
}
