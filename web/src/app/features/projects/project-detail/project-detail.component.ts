import { DecimalPipe } from '@angular/common';
import { Component, computed, inject, input, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { DIRECTION_META, SEVERITY_META } from '../../../core/constants/labels';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { SEVERITIES, Severity, Trend } from '../../../core/models/api.models';
import { ApiService, saveBlob } from '../../../core/services/api.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { ReportTableComponent } from '../../../shared/components/report-table/report-table.component';
import { SeverityCountsComponent } from '../../../shared/components/severity-counts/severity-counts.component';
import { TrendChartComponent } from '../../../shared/components/trend-chart/trend-chart.component';

interface TrendWindow {
  days: number;
  granularity: Trend['granularity'];
  label: MessageKey;
}

/** Time windows offered for the trend (each stays well under the server bucket limit). */
const WINDOWS: readonly TrendWindow[] = [
  { days: 30, granularity: 'day', label: 'project.window30' },
  { days: 90, granularity: 'week', label: 'project.window90' },
  { days: 180, granularity: 'week', label: 'project.window180' },
  { days: 365, granularity: 'month', label: 'project.window365' },
];

const RECENT_REPORTS = 20;

/** One project: open findings, trend and latest reports. */
@Component({
  selector: 'app-project-detail',
  imports: [
    RouterLink,
    DecimalPipe,
    RefreshButtonComponent,
    ReportTableComponent,
    SeverityCountsComponent,
    TrendChartComponent,
    TranslatePipe,
  ],
  templateUrl: './project-detail.component.html',
  styleUrl: './project-detail.component.css',
})
export class ProjectDetailComponent {
  private readonly api = inject(ApiService);

  /** Route parameter :project */
  readonly project = input.required<string>();

  readonly windows = WINDOWS;
  readonly window = signal<TrendWindow>(WINDOWS[1]);
  readonly exporting = signal(false);
  readonly exportError = signal(false);

  readonly trend = rxResource({
    params: () => ({ project: this.project(), window: this.window() }),
    stream: ({ params }) =>
      this.api.trend(params.project, params.window.days, params.window.granularity),
  });

  readonly reports = rxResource({
    params: () => ({ project: this.project(), limit: RECENT_REPORTS, offset: 0 }),
    stream: ({ params }) => this.api.reports(params),
  });

  readonly direction = computed(() => {
    const direction = this.trend.value()?.direction ?? 'insufficient_data';
    return DIRECTION_META[direction] ?? DIRECTION_META['insufficient_data'];
  });

  /** Remediation times, worst severity first. */
  readonly mttr = computed(() => {
    const mttr = this.trend.value()?.summary.mttr_days ?? {};
    return SEVERITIES.filter((s) => mttr[s]).map((s) => ({
      severity: s,
      label: SEVERITY_META[s].label,
      ...mttr[s],
    }));
  });

  readonly oldest = computed(() => {
    const oldest = this.trend.value()?.summary.oldest_open_days ?? {};
    return SEVERITIES.filter((s) => oldest[s] !== undefined).map((s) => ({
      label: SEVERITY_META[s].label,
      days: oldest[s as Severity] ?? 0,
    }));
  });

  /** Reload the trend and the latest reports. */
  reload(): void {
    this.trend.reload();
    this.reports.reload();
  }

  selectWindow(window: TrendWindow): void {
    this.window.set(window);
  }

  async exportSarif(): Promise<void> {
    const project = this.project();
    this.exporting.set(true);
    this.exportError.set(false);
    try {
      const blob = await firstValueFrom(this.api.sarif({ project }));
      saveBlob(blob, `${project.replace(/[^\w.-]+/g, '_')}.sarif`);
    } catch {
      this.exportError.set(true);
    } finally {
      this.exporting.set(false);
    }
  }
}
