import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, disabled, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { TOKEN_ROLE_LABELS } from '../../core/constants/labels';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import {
    EnrollmentRequest,
    ProjectToken,
    ProjectTokenRole,
    Role,
} from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import {
    TableControlFilter,
    TableControlFilterChange,
    TableControlsComponent,
} from '../../shared/components/table-controls/table-controls.component';
import { compareTableText, filterAndSortRows } from '../../shared/utils/table-utils';

type EnrollmentSortKey = 'label' | 'project' | 'requester' | 'created';
type TokenSortKey = 'label' | 'projects' | 'usage' | 'created' | 'expires';

/**
 * Administrator page for tokens: enrollment requests waiting for approval, creation of MCP,
 * REST API or CI/CD tokens (with a validity) for some projects or every project, change of their
 * projects, rotation and revocation.
 */
@Component({
  selector: 'app-project-token-list',
  imports: [DatePipe, FormField, RefreshButtonComponent, TableControlsComponent, TranslatePipe],
  templateUrl: './project-token-list.component.html',
  styleUrl: './project-token-list.component.css',
})
export class ProjectTokenListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly projects = rxResource({ stream: () => this.api.projects() });
  readonly tokens = rxResource({ stream: () => this.api.projectTokens() });
  readonly enrollments = rxResource({ stream: () => this.api.enrollments() });
  /** Whether OIDC is enabled: approvals then offer web read access to the developer. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });
  readonly enrollmentSearch = signal('');
  readonly enrollmentSort = signal<EnrollmentSortKey>('created');
  readonly enrollmentDirection = signal<'asc' | 'desc'>('desc');
  readonly enrollmentKindFilter = signal<'' | 'new' | 'additional'>('');
  readonly enrollmentSortOptions = computed(() => [
    { value: 'label', label: this.i18n.translate('tokens.label') },
    { value: 'project', label: this.i18n.translate('reportTable.project') },
    { value: 'requester', label: this.i18n.translate('tokens.requester') },
    { value: 'created', label: this.i18n.translate('tokens.requestedAt') },
  ]);
  readonly enrollmentFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'kind',
      label: this.i18n.translate('users.type'),
      value: this.enrollmentKindFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        { value: 'new', label: this.i18n.translate('tokens.newToken') },
        { value: 'additional', label: this.i18n.translate('tokens.additional') },
      ],
    },
  ]);
  readonly visibleEnrollments = computed(() => {
    const kind = this.enrollmentKindFilter();
    const requests = (this.enrollments.value() ?? []).filter(
      (request) => !kind || request.kind === kind,
    );
    const sort = this.enrollmentSort();
    return filterAndSortRows(
      requests,
      this.enrollmentSearch(),
      this.enrollmentDirection(),
      (request) =>
        [
          request.label,
          this.i18n.translate(
            request.kind === 'additional' ? 'tokens.additional' : 'tokens.newToken',
          ),
          this.i18n.translate(this.roleLabel(request.role)),
          request.project,
          request.requested_by ?? '',
          request.requested_from ?? '',
        ].join(' '),
      (left, right) => {
        if (sort === 'project') {
          return compareTableText(left.project, right.project);
        }
        if (sort === 'requester') {
          return compareTableText(left.requested_by ?? '', right.requested_by ?? '');
        }
        if (sort === 'created') {
          return left.created_at.localeCompare(right.created_at);
        }
        return compareTableText(left.label, right.label);
      },
    );
  });
  readonly tokenSearch = signal('');
  readonly tokenSort = signal<TokenSortKey>('created');
  readonly tokenDirection = signal<'asc' | 'desc'>('desc');
  readonly tokenRoleFilter = signal<'' | ProjectTokenRole>('');
  readonly tokenSortOptions = computed(() => [
    { value: 'label', label: this.i18n.translate('tokens.label') },
    { value: 'projects', label: this.i18n.translate('tokens.allowedProjects') },
    { value: 'usage', label: this.i18n.translate('tokens.usage') },
    { value: 'created', label: this.i18n.translate('common.createdAt') },
    { value: 'expires', label: this.i18n.translate('tokens.expiresAt') },
  ]);
  readonly tokenFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'role',
      label: this.i18n.translate('tokens.usage'),
      value: this.tokenRoleFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...(['mcp', 'reader', 'triager', 'ci'] as ProjectTokenRole[]).map((role) => ({
          value: role,
          label: this.i18n.translate(this.roleLabel(role)),
        })),
      ],
    },
  ]);
  readonly visibleTokens = computed(() => {
    const role = this.tokenRoleFilter();
    const items = (this.tokens.value() ?? []).filter((token) => !role || token.role === role);
    const sort = this.tokenSort();
    return filterAndSortRows(
      items,
      this.tokenSearch(),
      this.tokenDirection(),
      (token) =>
        [
          token.label,
          token.project ?? '',
          ...(token.projects ?? []),
          ...(token.pending_projects ?? []),
          this.i18n.translate(this.roleLabel(token.role)),
        ].join(' '),
      (left, right) => {
        if (sort === 'projects') {
          return compareTableText(
            this.describeProjects(left.projects),
            this.describeProjects(right.projects),
          );
        }
        if (sort === 'usage') {
          return compareTableText(
            this.i18n.translate(this.roleLabel(left.role)),
            this.i18n.translate(this.roleLabel(right.role)),
          );
        }
        if (sort === 'created') {
          return left.created_at.localeCompare(right.created_at);
        }
        if (sort === 'expires') {
          return (left.expires_at ?? '').localeCompare(right.expires_at ?? '');
        }
        return compareTableText(left.label, right.label);
      },
    );
  });
  /** Web access chosen for each pending request, by request id (default: see portalAccess). */
  private readonly portalChoices = signal<Record<string, PortalAccess>>({});
  /** Model of the creation form (the projects are picked in selectedProjects). */
  readonly formModel = signal<TokenFormModel>({ ...EMPTY_TOKEN });
  readonly tokenForm = form(this.formModel, (path) => {
    required(path.label, { message: () => this.i18n.translate('tokens.labelRequired') });
    maxLength(path.label, 64);
    // The API rights only apply to a REST API token
    disabled(path.apiRole, ({ valueOf }) => valueOf(path.usage) !== 'api');
  });
  /** Every project (not offered for a CI/CD token), or only selectedProjects. */
  readonly allProjects = signal(false);
  readonly selectedProjects = signal<string[]>([]);
  /** A CI/CD token is always restricted to projects. */
  readonly creationAllProjects = computed(
    () => this.allProjects() && this.formModel().usage !== 'ci',
  );
  /** Token whose projects are being changed in its row (null: none). */
  readonly editing = signal<ProjectToken | null>(null);
  readonly editAllProjects = signal(false);
  readonly editSelected = signal<string[]>([]);
  readonly createdToken = signal<string | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);
  /** Validities offered at creation, in days ('' : default of the server). */
  readonly validities = VALIDITY_DAYS;
  /** Grace periods offered for a rotation, in hours. */
  readonly graceChoices = GRACE_HOURS;
  /** Hours during which the previous secret keeps working after a rotation. */
  readonly graceHours = signal(0);

  onEnrollmentSort(value: string): void {
    if (value === 'label' || value === 'project' || value === 'requester' || value === 'created') {
      this.enrollmentSort.set(value);
    }
  }

  onEnrollmentFilter(change: TableControlFilterChange): void {
    if (change.key === 'kind') {
      this.enrollmentKindFilter.set(
        change.value === 'new' || change.value === 'additional' ? change.value : '',
      );
    }
  }

  onTokenSort(value: string): void {
    if (
      value === 'label' ||
      value === 'projects' ||
      value === 'usage' ||
      value === 'created' ||
      value === 'expires'
    ) {
      this.tokenSort.set(value);
    }
  }

  onTokenFilter(change: TableControlFilterChange): void {
    if (change.key === 'role') {
      this.tokenRoleFilter.set(
        ['mcp', 'reader', 'triager', 'ci'].includes(change.value)
          ? (change.value as ProjectTokenRole)
          : '',
      );
    }
  }

  /** Message key of the usage of a token (MCP, or REST API with its rights). */
  roleLabel(role: Role): MessageKey {
    return TOKEN_ROLE_LABELS[role];
  }

  toggleProject(project: string, event: Event): void {
    this.selectedProjects.update((selected) => toggled(selected, project, event));
  }

  /** Text of the projects of a token: their names, or "All projects". */
  describeProjects(projects: string[] | null): string {
    return projects === null ? this.i18n.translate('reports.allProjects') : projects.join(', ');
  }

  /** Projects offered when changing a token: known projects plus those of the token. */
  editChoices(token: ProjectToken): string[] {
    const known = (this.projects.value() ?? []).map((item) => item.project);
    return [...new Set([...known, ...(token.projects ?? [])])].sort();
  }

  /** Open the change of the projects of a token in its row. */
  editProjects(token: ProjectToken): void {
    this.editing.set(token);
    this.editAllProjects.set(token.projects === null);
    this.editSelected.set(token.projects ?? []);
    this.error.set(null);
    this.message.set(null);
  }

  cancelEdit(): void {
    this.editing.set(null);
  }

  toggleEditProject(project: string, event: Event): void {
    this.editSelected.update((selected) => toggled(selected, project, event));
  }

  /** Save the projects of the edited token; giving every project asks for a confirmation. */
  async saveProjects(): Promise<void> {
    const token = this.editing();
    const all = this.editAllProjects() && token?.role !== 'ci';
    const projects = all ? null : this.editSelected();
    if (!token || this.busy() || (projects !== null && !projects.length)) {
      return;
    }
    const question = this.i18n.translate('tokens.confirmAllProjects', { label: token.label });
    if (all && token.projects !== null && !window.confirm(question)) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      const updated = await firstValueFrom(this.api.updateProjectTokenProjects(token.id, projects));
      this.editing.set(null);
      this.message.set(
        msg('tokens.projectsUpdated', {
          label: updated.label,
          projects: this.describeProjects(updated.projects),
        }),
      );
      this.tokens.reload();
      this.enrollments.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  async create(event: Event): Promise<void> {
    event.preventDefault();
    const model = this.formModel();
    const label = model.label.trim();
    const role: ProjectTokenRole = model.usage === 'api' ? model.apiRole : model.usage;
    const projects = this.creationAllProjects() ? null : this.selectedProjects();
    if (this.tokenForm().invalid() || !label || projects?.length === 0 || this.busy()) {
      this.tokenForm().markAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.createdToken.set(null);
    try {
      const days = model.validity ? Number(model.validity) : null;
      const created = await firstValueFrom(
        this.api.createProjectToken(label, projects, role, days),
      );
      this.createdToken.set(created.token);
      this.formModel.set({ ...EMPTY_TOKEN });
      this.tokenForm().reset();
      this.selectedProjects.set([]);
      this.allProjects.set(false);
      this.message.set(
        msg('tokens.created', {
          label: created.label,
          usage: this.i18n.translate(this.roleLabel(created.role)),
          projects: this.describeProjects(created.projects),
        }),
      );
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  /** Reload every list of the page. */
  reload(): void {
    this.projects.reload();
    this.tokens.reload();
    this.enrollments.reload();
  }

  /**
   * Web access offered with the approval, filled with the requester, which the administrator
   * checks or corrects (the requester name is not verified). Checked by default with OIDC (an
   * unknown name becomes an OIDC user); without it, the name must be an existing web user.
   */
  portalAccess(request: EnrollmentRequest): PortalAccess {
    return (
      this.portalChoices()[request.id] ?? {
        enabled: Boolean(request.requested_by) && Boolean(this.authConfig.value()?.oidc),
        user: request.requested_by ?? '',
      }
    );
  }

  onPortalEnabledChange(request: EnrollmentRequest, event: Event): void {
    this.setPortalAccess(request, { enabled: (event.target as HTMLInputElement).checked });
  }

  onPortalUserInput(request: EnrollmentRequest, event: Event): void {
    this.setPortalAccess(request, { user: (event.target as HTMLInputElement).value });
  }

  setPortalAccess(request: EnrollmentRequest, change: Partial<PortalAccess>): void {
    const current = this.portalAccess(request);
    this.portalChoices.update((choices) => ({
      ...choices,
      [request.id]: { ...current, ...change },
    }));
  }

  /** Web user who gets read access with the approval, or null. */
  private portalUser(request: EnrollmentRequest): string | null {
    const access = this.portalAccess(request);
    return access.enabled && access.user.trim() ? access.user.trim() : null;
  }

  async approve(request: EnrollmentRequest): Promise<void> {
    const { id, label, project, kind } = request;
    const portalUser = this.portalUser(request);
    const question = portalUser
      ? this.i18n.translate('tokens.confirmApprovePortal', { label, project, user: portalUser })
      : this.i18n.translate('tokens.confirmApprove', { label, project });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    const additional = kind === 'additional';
    await this.decide(
      () => firstValueFrom(this.api.approveEnrollment(id, portalUser)),
      portalUser
        ? msg(additional ? 'tokens.approvedAdditionalPortal' : 'tokens.approvedNewPortal', {
            label,
            project,
            user: portalUser,
          })
        : msg(additional ? 'tokens.approvedAdditional' : 'tokens.approvedNew', { label, project }),
    );
  }

  async reject(id: string, label: string): Promise<void> {
    if (this.busy() || !window.confirm(this.i18n.translate('tokens.confirmReject', { label }))) {
      return;
    }
    await this.decide(
      () => firstValueFrom(this.api.rejectEnrollment(id)),
      msg('tokens.rejected', { label }),
    );
  }

  /** Apply a decision on an enrollment request and refresh the lists. */
  private async decide(action: () => Promise<unknown>, success: Message): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await action();
      this.message.set(success);
      this.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
      // The request may have been decided anyway (already processed, or approved without
      // its web access)
      this.enrollments.reload();
    } finally {
      this.busy.set(false);
    }
  }

  async copyToken(): Promise<void> {
    const token = this.createdToken();
    if (!token) {
      return;
    }
    try {
      await navigator.clipboard.writeText(token);
      this.message.set(msg('tokens.copied'));
    } catch {
      this.error.set(msg('tokens.copyFailed'));
    }
  }

  onGraceChange(event: Event): void {
    this.graceHours.set(Number((event.target as HTMLSelectElement).value));
  }

  /** Replace the secret of a token and show the new one once. */
  async rotate(id: string, label: string): Promise<void> {
    const hours = this.graceHours();
    const question = hours
      ? this.i18n.translate('tokens.confirmRotateGrace', { label, hours })
      : this.i18n.translate('tokens.confirmRotate', { label });
    if (this.busy() || !window.confirm(question)) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.createdToken.set(null);
    try {
      const rotated = await firstValueFrom(this.api.rotateProjectToken(id, hours));
      this.createdToken.set(rotated.token);
      this.message.set(
        hours ? msg('tokens.rotatedGrace', { label, hours }) : msg('tokens.rotated', { label }),
      );
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  async revoke(id: string, label: string): Promise<void> {
    if (this.busy() || !window.confirm(this.i18n.translate('tokens.confirmRevoke', { label }))) {
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.deleteProjectToken(id));
      this.createdToken.set(null);
      this.message.set(msg('tokens.revoked', { label }));
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

/** What a project token is for: the MCP server, the REST API or a CI/CD pipeline. */
type TokenUsage = 'mcp' | 'api' | 'ci';

/** Rights of a REST API token. */
type ApiTokenRole = Exclude<ProjectTokenRole, 'mcp' | 'ci'>;

/** Fields of the token creation form. */
interface TokenFormModel {
  label: string;
  /** The MCP server, the REST API or a CI/CD pipeline. */
  usage: TokenUsage;
  /** Rights of a REST API token: read only, or read and triage. */
  apiRole: ApiTokenRole;
  /** Validity in days; '': the default of the server (SECREVIEW_TOKEN_MAX_DAYS). */
  validity: string;
}

const EMPTY_TOKEN: TokenFormModel = { label: '', usage: 'mcp', apiRole: 'reader', validity: '' };

/** Validities offered at creation, in days. */
const VALIDITY_DAYS: readonly string[] = ['30', '90', '180', '365'];

/** Grace periods offered for a rotation, in hours (at most 168 on the server). */
const GRACE_HOURS: readonly number[] = [0, 1, 24, 168];

/** Web read access given to the developer when approving its enrollment. */
interface PortalAccess {
  enabled: boolean;
  /** Username of the web user (for an OIDC user, the username claim of the provider). */
  user: string;
}

/** The selection with a project added or removed, after a checkbox change. */
function toggled(selected: string[], project: string, event: Event): string[] {
  const checked = (event.target as HTMLInputElement).checked;
  return checked ? [...selected, project] : selected.filter((item) => item !== project);
}

function describeError(error: unknown): Message {
  if (
    error instanceof HttpErrorResponse &&
    error.status === 422 &&
    !error.url?.includes('/approve')
  ) {
    return typeof error.error?.detail === 'string'
      ? msg('tokens.refusedDetail', { detail: error.error.detail })
      : msg('tokens.failed');
  }
  if (error instanceof HttpErrorResponse && error.status === 422) {
    return typeof error.error?.detail === 'string'
      ? msg('tokens.portalRefusedDetail', { detail: error.error.detail })
      : msg('tokens.portalRefused');
  }
  if (
    error instanceof HttpErrorResponse &&
    error.status === 409 &&
    error.url?.includes('/approve')
  ) {
    return msg('tokens.portalConflict');
  }
  if (error instanceof HttpErrorResponse && error.status === 404) {
    return msg('tokens.requestGone');
  }
  if (error instanceof HttpErrorResponse && error.status === 409) {
    return msg('tokens.labelConflict');
  }
  if (error instanceof HttpErrorResponse && error.status === 503) {
    return msg('tokens.notConfigured');
  }
  return msg('tokens.failed');
}
