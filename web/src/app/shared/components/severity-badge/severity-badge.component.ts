import { Component, computed, input } from '@angular/core';
import { SEVERITY_META } from '../../../core/constants/labels';
import { Severity } from '../../../core/models/api.models';

/** Severity shown as a colored icon followed by its name. */
@Component({
  selector: 'app-severity-badge',
  templateUrl: './severity-badge.component.html',
  styleUrl: './severity-badge.component.css',
})
export class SeverityBadgeComponent {
  readonly severity = input.required<Severity>();

  readonly meta = computed(() => SEVERITY_META[this.severity()]);
}
