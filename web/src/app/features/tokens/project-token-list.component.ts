import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, disabled, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { TOKEN_ROLE_LABELS } from '../../core/constants/labels';
import { I18nService, Message, msg } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { EnrollmentRequest, ProjectTokenRole, Role } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/**
 * Administrator page for project tokens: enrollment requests waiting for approval, creation of
 * MCP, REST API or CI/CD tokens and revocation.
 */
@Component({
  selector: 'app-project-token-list',
  imports: [DatePipe, FormField, RefreshButtonComponent, TranslatePipe],
  templateUrl: './project-token-list.component.html',
  styleUrl: './project-token-list.component.css',
})
export class ProjectTokenListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly projects = rxResource({ stream: () => this.api.projects() });
  readonly tokens = rxResource({ stream: () => this.api.projectTokens() });
  readonly enrollments = rxResource({ stream: () => this.api.enrollments() });
  /** Whether SSO is enabled: approvals then offer web read access to the developer. */
  readonly authConfig = rxResource({ stream: () => this.api.authConfig() });
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
  readonly selectedProjects = signal<string[]>([]);
  readonly createdToken = signal<string | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Message key of the usage of a token (MCP, or REST API with its rights). */
  roleLabel(role: Role): MessageKey {
    return TOKEN_ROLE_LABELS[role];
  }

  toggleProject(project: string, event: Event): void {
    const checked = (event.target as HTMLInputElement).checked;
    this.selectedProjects.update((selected) =>
      checked ? [...selected, project] : selected.filter((item) => item !== project),
    );
  }

  async create(event: Event): Promise<void> {
    event.preventDefault();
    const model = this.formModel();
    const label = model.label.trim();
    const role: ProjectTokenRole = model.usage === 'api' ? model.apiRole : model.usage;
    const projects = this.selectedProjects();
    if (this.tokenForm().invalid() || !label || !projects.length || this.busy()) {
      this.tokenForm().markAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    this.createdToken.set(null);
    try {
      const created = await firstValueFrom(this.api.createProjectToken(label, projects, role));
      this.createdToken.set(created.token);
      this.formModel.set({ ...EMPTY_TOKEN });
      this.tokenForm().reset();
      this.selectedProjects.set([]);
      this.message.set(
        msg('tokens.created', {
          label: created.label,
          usage: this.i18n.translate(this.roleLabel(created.role)),
          projects: projects.join(', '),
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
   * unknown name becomes an SSO user); without it, the name must be an existing web user.
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
}

const EMPTY_TOKEN: TokenFormModel = { label: '', usage: 'mcp', apiRole: 'reader' };

/** Web read access given to the developer when approving its enrollment. */
interface PortalAccess {
  enabled: boolean;
  /** Username of the web user (for an SSO user, the username claim of the provider). */
  user: string;
}

function describeError(error: unknown): Message {
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
