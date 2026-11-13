import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, computed, inject, input, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { DIRECTION_META, SEVERITY_META, STATUS_META } from '../../../core/constants/labels';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ProjectFinding, SEVERITIES, Severity, Trend } from '../../../core/models/api.models';
import { ApiService, saveBlob } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { ProjectMembersComponent } from '../project-members/project-members.component';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { SeverityCountsComponent } from '../../../shared/components/severity-counts/severity-counts.component';
import { TrendChartComponent } from '../../../shared/components/trend-chart/trend-chart.component';
import { PackageGroup, groupByPackage } from '../../../shared/utils/package-groups';

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

/** A row of the open findings: a finding (member of an unfolded package or not) or a package. */
type OpenRow =
  | { kind: 'finding'; key: string; finding: ProjectFinding; member: boolean }
  | { kind: 'package'; key: string; group: PackageGroup<ProjectFinding>; expanded: boolean };

/** Open findings listed on the page (the full list is at /projects/:project/findings). */
const TOP_OPEN_FINDINGS = 20;

/**
 * One project: open findings, trend and the worst open findings. A finding whose status an agent
 * proposed shows a blinking icon, for the triager to review the proposal.
 */
@Component({
  selector: 'app-project-detail',
  imports: [
    RouterLink,
    DatePipe,
    DecimalPipe,
    ProjectMembersComponent,
    RefreshButtonComponent,
    SeverityBadgeComponent,
    SeverityCountsComponent,
    TrendChartComponent,
    TranslatePipe,
  ],
  templateUrl: './project-detail.component.html',
  styleUrl: './project-detail.component.css',
})
export class ProjectDetailComponent {
  private readonly api = inject(ApiService);
  /** Gives the members of the project to a holder of users.manage. */
  readonly auth = inject(AuthService);

  /** Route parameter :project */
  readonly project = input.required<string>();

  readonly statusMeta = STATUS_META;
  readonly windows = WINDOWS;
  readonly window = signal<TrendWindow>(WINDOWS[1]);
  readonly exporting = signal(false);
  readonly exportError = signal(false);

  readonly trend = rxResource({
    params: () => ({ project: this.project(), window: this.window() }),
    stream: ({ params }) =>
      this.api.trend(params.project, params.window.days, params.window.granularity),
  });

  /** Worst open findings of the project, across all its reports. */
  readonly openFindings = rxResource({
    params: () => ({
      project: this.project(),
      status: ['open' as const],
      severity: [],
      reviewType: [],
      limit: TOP_OPEN_FINDINGS,
      offset: 0,
    }),
    stream: ({ params }) => this.api.projectFindings(params),
  });

  /**
   * Rows of the open findings: the advisories of one vulnerable package fold in one row,
   * followed by their own rows once unfolded.
   */
  readonly openRows = computed<OpenRow[]>(() => {
    const expanded = this.expanded();
    const rows: OpenRow[] = [];
    for (const entry of groupByPackage(this.openFindings.value()?.findings ?? [])) {
      if (entry.kind === 'finding') {
        rows.push({ kind: 'finding', key: entry.key, finding: entry.finding, member: false });
        continue;
      }
      const open = expanded.has(entry.group.key);
      rows.push({ kind: 'package', key: entry.key, group: entry.group, expanded: open });
      if (open) {
        for (const finding of entry.group.findings) {
          rows.push({ kind: 'finding', key: `finding-${finding.id}`, finding, member: true });
        }
      }
    }
    return rows;
  });
  private readonly expanded = signal<ReadonlySet<string>>(new Set());

  toggleGroup(key: string): void {
    this.expanded.update((keys) => {
      const next = new Set(keys);
      if (!next.delete(key)) {
        next.add(key);
      }
      return next;
    });
  }

  /** Report of every finding of a group, when they come from a single one. */
  sameReport(group: PackageGroup<ProjectFinding>): number | null {
    const id = group.findings[0].report_id;
    return group.findings.every((f) => f.report_id === id) ? id : null;
  }

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

  /** Reload the trend and the open findings. */
  reload(): void {
    this.trend.reload();
    this.openFindings.reload();
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
