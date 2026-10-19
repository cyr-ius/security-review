import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService, Message, msg, serverDetail } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  PendingProject,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
  SeverityCounts,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { SeverityCountsComponent } from '../../../shared/components/severity-counts/severity-counts.component';
import { SortHeaderComponent } from '../../../shared/components/sort-header/sort-header.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { TableSort } from '../../../shared/utils/table-sort';
import { filterAndSortRows } from '../../../shared/utils/table-utils';

/** Longest project name accepted by the server (token_store._clean_project). */
const MAX_PROJECT_CHARS = 200;

/** Dashboard: every project with its open findings. */
@Component({
  selector: 'app-project-list',
  imports: [
    RouterLink,
    DatePipe,
    FormField,
    SeverityBadgeComponent,
    SeverityCountsComponent,
    RefreshButtonComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './project-list.component.html',
  styleUrl: './project-list.component.css',
})
export class ProjectListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  private readonly auth = inject(AuthService);

  /** A user with projects.create may create a new project, which it then reads. */
  readonly canCreate = computed(() => this.auth.can('projects.create'));
  readonly newProject = signal({ project: '' });
  readonly newProjectForm = form(this.newProject, (path) => {
    required(path.project);
    maxLength(path.project, MAX_PROJECT_CHARS);
  });
  readonly creating = signal(false);
  readonly createError = signal<Message | null>(null);
  readonly notice = signal<Message | null>(null);

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;

  readonly projects = rxResource({ stream: () => this.api.projects() });
  /** Projects requested by an enrollment, approved or rejected by the holders of
   * projects.create (not loaded for the others). */
  readonly pending = rxResource({
    params: () => (this.canCreate() ? true : undefined),
    stream: () => this.api.pendingProjects(),
  });
  readonly deciding = signal(false);
  readonly pendingError = signal<Message | null>(null);

  readonly search = signal('');
  readonly sort = new TableSort<'name' | 'risk' | 'activity'>(
    'projects',
    ['name', 'risk', 'activity'],
    'risk',
    'desc',
  );
  readonly severityFilter = signal<Severity | 'none' | ''>('');
  readonly filters = computed<TableControlFilter[]>(() => [
    {
      key: 'severity',
      label: this.i18n.translate('projects.worst'),
      value: this.severityFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...SEVERITIES.map((severity) => ({
          value: severity,
          label: this.i18n.translate(this.severityMeta[severity].label),
        })),
        { value: 'none', label: this.i18n.translate('projects.none') },
      ],
    },
  ]);

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

  /** Open findings of every project, shown on the review button. */
  readonly openTotal = computed(() =>
    SEVERITIES.reduce((sum, severity) => sum + this.totals()[severity], 0),
  );

  readonly visible = computed(() => {
    const severity = this.severityFilter();
    const rows = (this.projects.value() ?? []).filter(
      (project) =>
        !severity ||
        (severity === 'none'
          ? project.worst_open_severity === null
          : project.worst_open_severity === severity),
    );
    const sort = this.sort.key();
    return filterAndSortRows(
      rows,
      this.search(),
      this.sort.direction(),
      (project) => project.project,
      (a, b) => {
        if (sort === 'name') {
          return a.project.localeCompare(b.project, undefined, {
            numeric: true,
            sensitivity: 'base',
          });
        }
        if (sort === 'activity') {
          return (a.last_report_at ?? '').localeCompare(b.last_report_at ?? '');
        }
        return (
          rank(a.worst_open_severity) - rank(b.worst_open_severity) ||
          a.open_findings_total - b.open_findings_total
        );
      },
    );
  });

  /** Create the project of the form; the session then reads it (its grants are reloaded). */
  async createProject(event: Event): Promise<void> {
    event.preventDefault();
    const project = this.newProject().project.trim();
    if (this.newProjectForm().invalid() || !project) {
      return;
    }
    this.creating.set(true);
    this.createError.set(null);
    this.notice.set(null);
    try {
      const created = await firstValueFrom(this.api.createProject(project));
      this.newProject.set({ project: '' });
      this.notice.set(msg('projects.created', { project: created.project }));
      this.auth.setIdentity(await firstValueFrom(this.api.me()));
      this.projects.reload();
    } catch (error: unknown) {
      this.createError.set(
        error instanceof HttpErrorResponse && typeof error.error?.detail === 'string'
          ? serverDetail(error.error.detail)
          : msg('projects.createFailed'),
      );
    } finally {
      this.creating.set(false);
    }
  }

  /** Reload the projects and the pending projects. */
  reload(): void {
    this.projects.reload();
    this.pending.reload();
  }

  async approve(request: PendingProject): Promise<void> {
    const { id, project } = request;
    if (!window.confirm(this.i18n.translate('projects.confirmApprove', { project }))) {
      return;
    }
    await this.decide(
      () => firstValueFrom(this.api.approvePendingProject(id)),
      msg('projects.approved', { project }),
    );
  }

  async reject(request: PendingProject): Promise<void> {
    const { id, project } = request;
    if (!window.confirm(this.i18n.translate('projects.confirmReject', { project }))) {
      return;
    }
    await this.decide(
      () => firstValueFrom(this.api.rejectPendingProject(id)),
      msg('projects.rejected', { project }),
    );
  }

  /** Apply a decision on a pending project and refresh both lists. */
  private async decide(action: () => Promise<unknown>, success: Message): Promise<void> {
    if (this.deciding()) {
      return;
    }
    this.deciding.set(true);
    this.pendingError.set(null);
    this.notice.set(null);
    try {
      await action();
      this.notice.set(success);
    } catch (error: unknown) {
      this.pendingError.set(
        error instanceof HttpErrorResponse && error.status === 404
          ? msg('projects.pendingGone')
          : error instanceof HttpErrorResponse && typeof error.error?.detail === 'string'
            ? serverDetail(error.error.detail)
            : msg('projects.pendingFailed'),
      );
    } finally {
      this.deciding.set(false);
      this.reload();
    }
  }

  onProjectTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'severity') {
      this.severityFilter.set(
        change.value === 'none' || SEVERITIES.includes(change.value as Severity)
          ? (change.value as Severity | 'none')
          : '',
      );
    }
  }
}

function rank(severity: Severity | null): number {
  return severity ? SEVERITY_RANK[severity] : -1;
}
