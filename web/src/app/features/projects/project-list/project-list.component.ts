import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import {
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
  SeverityCounts,
} from '../../../core/models/api.models';
import { SEVERITY_META } from '../../../core/constants/labels';
import { ApiService } from '../../../core/services/api.service';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { SeverityCountsComponent } from '../../../shared/components/severity-counts/severity-counts.component';

type SortKey = 'risk' | 'activity' | 'name';

/** Dashboard: every project with its open findings. */
@Component({
  selector: 'app-project-list',
  imports: [RouterLink, DatePipe, SeverityBadgeComponent, SeverityCountsComponent],
  templateUrl: './project-list.component.html',
  styleUrl: './project-list.component.css',
})
export class ProjectListComponent {
  private readonly api = inject(ApiService);

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;

  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly search = signal('');
  readonly sort = signal<SortKey>('risk');

  /** Open findings of every project added up. */
  readonly totals = computed<SeverityCounts>(() => {
    const totals = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
    for (const project of this.projects.value() ?? []) {
      for (const severity of SEVERITIES) {
        totals[severity] += project.open_findings_by_severity[severity];
      }
    }
    return totals;
  });

  readonly visible = computed(() => {
    const term = this.search().trim().toLowerCase();
    const rows = (this.projects.value() ?? []).filter((p) =>
      p.project.toLowerCase().includes(term),
    );
    switch (this.sort()) {
      case 'name':
        return rows.sort((a, b) => a.project.localeCompare(b.project));
      case 'activity':
        return rows.sort((a, b) => b.last_report_at.localeCompare(a.last_report_at));
      default:
        // Worst open severity first, then the number of open findings
        return rows.sort(
          (a, b) =>
            rank(b.worst_open_severity) - rank(a.worst_open_severity) ||
            b.open_findings_total - a.open_findings_total,
        );
    }
  });

  onSearch(event: Event): void {
    this.search.set((event.target as HTMLInputElement).value);
  }

  onSort(event: Event): void {
    this.sort.set((event.target as HTMLSelectElement).value as SortKey);
  }
}

function rank(severity: Severity | null): number {
  return severity ? SEVERITY_RANK[severity] : -1;
}
