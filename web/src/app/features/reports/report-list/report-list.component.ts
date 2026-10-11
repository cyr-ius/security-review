import { Component, computed, inject, input } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { SEVERITY_META } from '../../../core/constants/labels';
import { SEVERITIES, Severity } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { ReportTableComponent } from '../../../shared/components/report-table/report-table.component';

const PAGE_SIZE = 25;

/** All reports, filtered by project and risk level (filters live in the URL). */
@Component({
  selector: 'app-report-list',
  imports: [ReportTableComponent],
  templateUrl: './report-list.component.html',
  styleUrl: './report-list.component.css',
})
export class ReportListComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);

  /** Query parameters ?project=&risk=&page= */
  readonly project = input<string>();
  readonly risk = input<string>();
  readonly page = input<string>();

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;
  readonly pageSize = PAGE_SIZE;

  readonly pageNumber = computed(() => Math.max(1, Number.parseInt(this.page() ?? '1', 10) || 1));

  readonly riskLevel = computed<Severity | ''>(() => {
    const risk = this.risk() ?? '';
    return (SEVERITIES as readonly string[]).includes(risk) ? (risk as Severity) : '';
  });

  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly reports = rxResource({
    params: () => ({
      project: this.project() ?? '',
      risk_level: this.riskLevel(),
      // One extra row tells whether a next page exists
      limit: PAGE_SIZE + 1,
      offset: (this.pageNumber() - 1) * PAGE_SIZE,
    }),
    stream: ({ params }) => this.api.reports(params),
  });

  readonly rows = computed(() => (this.reports.value() ?? []).slice(0, PAGE_SIZE));
  readonly hasNext = computed(() => (this.reports.value() ?? []).length > PAGE_SIZE);

  onProject(event: Event): void {
    this.navigate({ project: (event.target as HTMLSelectElement).value || null, page: null });
  }

  onRisk(event: Event): void {
    this.navigate({ risk: (event.target as HTMLSelectElement).value || null, page: null });
  }

  goToPage(page: number): void {
    this.navigate({ page: page > 1 ? page : null });
  }

  private navigate(queryParams: Record<string, string | number | null>): void {
    this.router.navigate([], { queryParams, queryParamsHandling: 'merge' });
  }
}
