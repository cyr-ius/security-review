import { Component, computed, input } from '@angular/core';
import { SEVERITY_META } from '../../../core/constants/labels';
import { SEVERITIES, SeverityCounts } from '../../../core/models/api.models';

/** One stat tile per severity: icon, name and number of open findings. */
@Component({
  selector: 'app-severity-counts',
  templateUrl: './severity-counts.component.html',
  styleUrl: './severity-counts.component.css',
})
export class SeverityCountsComponent {
  readonly counts = input.required<SeverityCounts>();

  readonly tiles = computed(() =>
    SEVERITIES.map((severity) => ({
      severity,
      ...SEVERITY_META[severity],
      value: this.counts()[severity] ?? 0,
    })),
  );
}
