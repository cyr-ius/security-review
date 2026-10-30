import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { PERMISSION_META, TOKEN_ROLE_LABELS } from '../../core/constants/labels';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../shared/components/help-link/help-link.component';
import {
  MultiSelectDropdownComponent,
  MultiSelectOption,
} from '../../shared/components/multi-select-dropdown/multi-select-dropdown.component';
import { ProjectPermissionsComponent } from '../../shared/components/project-permissions/project-permissions.component';
import {
  Permission,
  ProjectToken,
  ProjectTokenRole,
  TokenRole,
  TokenRoleChoice,
} from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { OAuthClientsComponent } from './oauth-clients/oauth-clients.component';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../shared/components/table-controls/table-controls.component';
import { SortHeaderComponent } from '../../shared/components/sort-header/sort-header.component';
import { TableSort } from '../../shared/utils/table-sort';
import { compareTableText, filterAndSortRows } from '../../shared/utils/table-utils';

type TokenSortKey = 'label' | 'projects' | 'usage' | 'created' | 'expires';

/**
 * Administrator page for tokens: creation of MCP, CI/CD or REST API tokens (an api token holds
 * the permissions of a role) (with a validity) for some projects or every project, change of
 * their projects, rotation and revocation.
 */
@Component({
  selector: 'app-project-token-list',
  imports: [
    ProjectPermissionsComponent,
    HelpLinkComponent,
    DatePipe,
    MultiSelectDropdownComponent,
    FormField,
    OAuthClientsComponent,
    RefreshButtonComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './project-token-list.component.html',
  styleUrl: './project-token-list.component.css',
})
export class ProjectTokenListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly projects = rxResource({ stream: () => this.api.projects() });
  readonly tokens = rxResource({ stream: () => this.api.projectTokens() });
  /** Roles an api token may hold. */
  readonly tokenRoles = rxResource({ stream: () => this.api.tokenRoles() });
  readonly tokenSearch = signal('');
  readonly tokenSort = new TableSort<TokenSortKey>(
    'project-tokens',
    ['label', 'projects', 'usage', 'created', 'expires'],
    'created',
    'desc',
  );
  readonly tokenRoleFilter = signal<'' | ProjectTokenRole>('');
  readonly tokenFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'role',
      label: this.i18n.translate('tokens.usage'),
      value: this.tokenRoleFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...(['mcp', 'ci', 'api'] as ProjectTokenRole[]).map((role) => ({
          value: role,
          label: this.i18n.translate(this.roleLabel(role)),
        })),
      ],
    },
  ]);
  readonly visibleTokens = computed(() => {
    const role = this.tokenRoleFilter();
    const items = (this.tokens.value() ?? []).filter((token) => !role || token.role === role);
    const sort = this.tokenSort.key();
    return filterAndSortRows(
      items,
      this.tokenSearch(),
      this.tokenSort.direction(),
      (token) =>
        [token.label, token.project ?? '', ...(token.projects ?? []), this.usageLabel(token)].join(
          ' ',
        ),
      (left, right) => {
        if (sort === 'projects') {
          return compareTableText(
            this.describeProjects(left.projects),
            this.describeProjects(right.projects),
          );
        }
        if (sort === 'usage') {
          return compareTableText(this.usageLabel(left), this.usageLabel(right));
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
  /** Model of the creation form (the projects are picked in selectedProjects). */
  readonly formModel = signal<TokenFormModel>({ ...EMPTY_TOKEN });
  readonly tokenForm = form(this.formModel, (path) => {
    required(path.label, { message: () => this.i18n.translate('tokens.labelRequired') });
    maxLength(path.label, 64);
    // The role only applies to an api token, which needs one
    required(path.accessRoleId, { when: ({ valueOf }) => valueOf(path.usage) === 'api' });
  });
  /** Per-project permissions of a new api token on its projects: their reading by default. */
  readonly projectPermissions = signal<Permission[]>(['reports.read']);
  /** Projects ticked for a new token, or "All projects" alone (ALL_PROJECTS). */
  readonly selectedProjects = signal<string[]>([]);
  readonly creationSearch = signal('');
  /** Ticked values, without "All projects" for a CI/CD token, always restricted to projects. */
  readonly creationSelected = computed(() =>
    this.formModel().usage === 'ci'
      ? this.selectedProjects().filter((value) => value !== ALL_PROJECTS)
      : this.selectedProjects(),
  );
  readonly creationAllProjects = computed(() => this.creationSelected().includes(ALL_PROJECTS));
  /** Projects of the new token: null for every project. */
  readonly creationProjects = computed(() =>
    this.creationAllProjects() ? null : this.creationSelected(),
  );
  readonly creationOptions = computed(() =>
    this.projectOptions(
      (this.projects.value() ?? []).map((item) => item.project),
      this.creationSearch(),
      this.formModel().usage !== 'ci',
      this.creationSelected(),
    ),
  );
  readonly creationNote = computed(() => this.projectNote(this.creationOptions()));
  /** Token whose projects are being changed in its row (null: none). */
  readonly editing = signal<ProjectToken | null>(null);
  /** Projects ticked for the edited token, or "All projects" alone (ALL_PROJECTS). */
  readonly editSelected = signal<string[]>([]);
  readonly editSearch = signal('');
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

  onTokenFilter(change: TableControlFilterChange): void {
    if (change.key === 'role') {
      this.tokenRoleFilter.set(
        ['mcp', 'ci'].includes(change.value) ? (change.value as ProjectTokenRole) : '',
      );
    }
  }

  /** Message key of the usage of a token (MCP agent, CI/CD pipeline or REST API). */
  roleLabel(role: TokenRole): MessageKey {
    return TOKEN_ROLE_LABELS[role];
  }

  /** Usage of a token, with the role or the owner of an api token. */
  usageLabel(token: ProjectToken): string {
    const usage = this.i18n.translate(this.roleLabel(token.role));
    if (token.personal) {
      return `${usage} · ${this.i18n.translate('tokens.personal')}`;
    }
    const role = this.roleOf(token);
    if (!role) {
      return usage;
    }
    const permissions = token.project_permissions.map((permission) =>
      this.i18n.translate(PERMISSION_META[permission].label),
    );
    return [usage, role.name, ...permissions].join(' · ');
  }

  /** Role of an api token, when the caller may list the roles. */
  private roleOf(token: ProjectToken): TokenRoleChoice | undefined {
    return (this.tokenRoles.value() ?? []).find((role) => role.id === token.access_role_id);
  }

  /** The projects of a token can be changed, except for a personal token (the rights of its
   * user). */
  canEditProjects(token: ProjectToken): boolean {
    return !token.personal;
  }

  /** Options of a choice of projects: "All projects" first when offered, then the projects
   * matching the search and those ticked (the menu only keeps the ticked values it shows),
   * which "All projects" already reaches when ticked. */
  private projectOptions(
    projects: string[],
    search: string,
    withAllProjects: boolean,
    selected: string[],
  ): MultiSelectOption[] {
    const term = search.trim().toLowerCase();
    const allPicked = selected.includes(ALL_PROJECTS);
    return [
      ...(withAllProjects
        ? [
            {
              value: ALL_PROJECTS,
              label: this.i18n.translate('reports.allProjects'),
              strong: true,
              divider: true,
              standalone: true,
            },
          ]
        : []),
      ...projects
        .filter((project) => project.toLowerCase().includes(term) || selected.includes(project))
        .map((project) => ({
          value: project,
          label: project,
          monospace: true,
          disabled: allPicked,
        })),
    ];
  }

  /** Text under the projects: loading, or no project found. */
  private projectNote(options: MultiSelectOption[]): string | null {
    if (this.projects.isLoading() && !this.projects.hasValue()) {
      return this.i18n.translate('common.loading');
    }
    return options.some((option) => option.value !== ALL_PROJECTS)
      ? null
      : this.i18n.translate('access.noProjectFound');
  }

  /** Ticking "All projects" unticks the projects, which it already reaches. */
  picked(values: string[]): string[] {
    return values.includes(ALL_PROJECTS) ? [ALL_PROJECTS] : values;
  }

  /** Text of the projects of a token: their names, "All projects", or "No project" (a personal
   * MCP token whose user reads none). */
  describeProjects(projects: string[] | null): string {
    if (projects === null) {
      return this.i18n.translate('reports.allProjects');
    }
    return projects.length ? projects.join(', ') : this.i18n.translate('apiTokens.noProject');
  }

  /** Projects offered when changing a token: known projects plus those of the token. */
  editChoices(token: ProjectToken): string[] {
    const known = (this.projects.value() ?? []).map((item) => item.project);
    return [...new Set([...known, ...(token.projects ?? [])])].sort();
  }

  editOptions(token: ProjectToken): MultiSelectOption[] {
    return this.projectOptions(
      this.editChoices(token),
      this.editSearch(),
      token.role !== 'ci',
      this.editSelected(),
    );
  }

  editNote(token: ProjectToken): string | null {
    return this.projectNote(this.editOptions(token));
  }

  /** Open the change of the projects of a token in its row. */
  editProjects(token: ProjectToken): void {
    this.editing.set(token);
    this.editSelected.set(token.projects ?? [ALL_PROJECTS]);
    this.editSearch.set('');
    this.error.set(null);
    this.message.set(null);
  }

  cancelEdit(): void {
    this.editing.set(null);
  }

  /** Save the projects of the edited token; giving every project asks for a confirmation. */
  async saveProjects(): Promise<void> {
    const token = this.editing();
    const all = this.editSelected().includes(ALL_PROJECTS) && token?.role !== 'ci';
    const projects = all ? null : this.editSelected().filter((project) => project !== ALL_PROJECTS);
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
    const role: ProjectTokenRole = model.usage;
    const accessRoleId = role === 'api' ? Number(model.accessRoleId) : null;
    const projects = this.creationProjects();
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
        this.api.createProjectToken(
          label,
          projects,
          role,
          days,
          accessRoleId,
          role === 'api' ? this.projectPermissions() : [],
        ),
      );
      this.createdToken.set(created.token);
      this.formModel.set({ ...EMPTY_TOKEN });
      this.tokenForm().reset();
      this.selectedProjects.set([]);
      this.creationSearch.set('');
      this.projectPermissions.set(['reports.read']);
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

/** Fields of the token creation form. */
interface TokenFormModel {
  label: string;
  /** What the token is for: the MCP server, a CI/CD pipeline or the REST API. */
  usage: ProjectTokenRole;
  /** Role of an api token (id as text; '': none chosen). */
  accessRoleId: string;
  /** Validity in days; '': the default of the server (SECREVIEW_TOKEN_MAX_DAYS). */
  validity: string;
}

const EMPTY_TOKEN: TokenFormModel = { label: '', usage: 'mcp', accessRoleId: '', validity: '' };

/** Validities offered at creation, in days. */
const VALIDITY_DAYS: readonly string[] = ['30', '90', '180', '365'];

/** Grace periods offered for a rotation, in hours (at most 168 on the server). */
const GRACE_HOURS: readonly number[] = [0, 1, 24, 168];

/** Value of "All projects" in a choice of projects (no project name holds a "*"). */
const ALL_PROJECTS = '*';

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && error.status === 422) {
    return typeof error.error?.detail === 'string'
      ? msg('tokens.refusedDetail', { detail: error.error.detail })
      : msg('tokens.failed');
  }
  if (error instanceof HttpErrorResponse && error.status === 404) {
    return msg('tokens.tokenGone');
  }
  if (error instanceof HttpErrorResponse && error.status === 409) {
    return msg('tokens.labelConflict');
  }
  if (error instanceof HttpErrorResponse && error.status === 503) {
    return msg('tokens.notConfigured');
  }
  return msg('tokens.failed');
}
