import { Component, computed, input } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { findingStatusMeta } from '../../../core/constants/labels';
import { FindingStatus, Severity } from '../../../core/models/api.models';

/** Finding status shown as an icon followed by its name. */
@Component({
  imports: [TranslatePipe],
  selector: 'app-status-badge',
  templateUrl: './status-badge.component.html',
  styleUrl: './status-badge.component.css',
})
export class StatusBadgeComponent {
  readonly status = input.required<FindingStatus>();
  /** Severity of the finding: an open ``info`` finding is shown as unread. */
  readonly severity = input.required<Severity>();

  readonly meta = computed(() => findingStatusMeta(this.status(), this.severity()));
}
