import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { TOKEN_ROLE_LABELS } from '../../../core/constants/labels';
import { MessageKey } from '../../../core/i18n/messages';
import { PersonalTokenRole, ProjectToken } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';

/**
 * Personal tokens of the logged-in user (My account): REST API tokens (Swagger, scripts), which
 * hold the current rights of the user, MCP tokens for its agent and CI tokens for
 * security-review-ci on its workstation, which reach the projects the user may read (with the
 * mcp_tokens.create permission). The secret is shown once.
 */
@Component({
  selector: 'app-api-tokens',
  imports: [DatePipe, FormField, TranslatePipe],
  templateUrl: './api-tokens.component.html',
  styleUrl: './api-tokens.component.css',
})
export class ApiTokensComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  private readonly auth = inject(AuthService);

  readonly tokens = rxResource({ stream: () => this.api.myTokens() });
  readonly model = signal<ApiTokenFormModel>({ ...EMPTY_FORM });
  readonly tokenForm = form(this.model, (path) => {
    required(path.label, { message: () => this.i18n.translate('tokens.labelRequired') });
    maxLength(path.label, 64);
  });
  readonly validities = VALIDITY_DAYS;
  /** The MCP and CI usages are offered only to a user with mcp_tokens.create (the server checks it). */
  readonly roles = computed(() =>
    PERSONAL_ROLES.filter((role) => role === 'api' || this.auth.can('mcp_tokens.create')),
  );
  readonly createdToken = signal<string | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  async create(event: Event): Promise<void> {
    event.preventDefault();
    const { label, validity, role } = this.model();
    if (this.tokenForm().invalid() || !label.trim() || this.busy()) {
      this.tokenForm().markAsTouched();
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      const created = await firstValueFrom(
        this.api.createMyToken(label.trim(), validity ? Number(validity) : null, role),
      );
      this.createdToken.set(created.token);
      this.tokenForm().reset({ ...EMPTY_FORM });
      this.tokens.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }

  /** Message key of the usage of a token (REST API, MCP or CI). */
  roleLabel(role: PersonalTokenRole): MessageKey {
    return TOKEN_ROLE_LABELS[role];
  }

  /** Projects of a token: those an MCP or CI token reaches now, the rights of the user for the API. */
  projectsText(token: ProjectToken): string {
    if (token.role !== 'mcp' && token.role !== 'ci') {
      return this.i18n.translate('apiTokens.yourRights');
    }
    if (token.projects === null) {
      return this.i18n.translate('reports.allProjects');
    }
    return token.projects.length
      ? token.projects.join(', ')
      : this.i18n.translate('apiTokens.noProject');
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
      await firstValueFrom(this.api.deleteMyToken(id));
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

/** Fields of the creation form. */
interface ApiTokenFormModel {
  label: string;
  /** Validity in days; '': the default of the server (SECREVIEW_TOKEN_MAX_DAYS). */
  validity: string;
  role: PersonalTokenRole;
}

const EMPTY_FORM: ApiTokenFormModel = { label: '', validity: '', role: 'api' };

/** Roles of the personal tokens, in display order. */
const PERSONAL_ROLES: readonly PersonalTokenRole[] = ['api', 'mcp', 'ci'];

/** Validities offered at creation, in days. */
const VALIDITY_DAYS: readonly string[] = ['30', '90', '180', '365'];

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && error.status === 422) {
    return typeof error.error?.detail === 'string'
      ? msg('tokens.refusedDetail', { detail: error.error.detail })
      : msg('tokens.failed');
  }
  return msg('tokens.failed');
}
