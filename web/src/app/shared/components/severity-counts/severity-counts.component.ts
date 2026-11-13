import { NgTemplateOutlet } from '@angular/common';
import { Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { SEVERITY_META } from '../../../core/constants/labels';
import { SEVERITIES, SeverityCounts } from '../../../core/models/api.models';

/**
 * One stat tile per severity: icon, name and number of open findings. With `link`, a tile that
 * counts something opens that page filtered on its severity (`?severity=`).
 */
@Component({
  imports: [NgTemplateOutlet, RouterLink, TranslatePipe],
  selector: 'app-severity-counts',
  templateUrl: './severity-counts.component.html',
  styleUrl: './severity-counts.component.css',
})
export class SeverityCountsComponent {
  readonly counts = input.required<SeverityCounts>();

  /** Route of the findings list the tiles open (router commands); none: plain tiles. */
  readonly link = input<string | readonly string[] | null>(null);

  readonly tiles = computed(() =>
    SEVERITIES.map((severity) => ({
      severity,
      ...SEVERITY_META[severity],
      value: this.counts()[severity] ?? 0,
    })),
  );
}
