import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, pattern, readonly, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg, serverDetail } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { OpenGrepRule, OpenGrepRuleProposal } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

/** Bounds of the API: rule id (rules.opengrep_rule_store.RULE_ID), YAML file, rejection reason. */
const RULE_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$/;
const MAX_RULE_CHARS = 262_144;
const MAX_REASON_CHARS = 1000;

const NEW_RULE_TEMPLATE =
  'rules:\n' +
  '  - id: example-rule\n' +
  '    message: Example security rule\n' +
  '    languages: [python]\n' +
  '    severity: WARNING\n' +
  '    pattern: eval($VALUE)\n';

/** Values of the rule editor: a rule file, or a proposal with its rejection reason. */
interface RuleFormModel {
  id: string;
  content: string;
  rejectReason: string;
}

const EMPTY_RULE: RuleFormModel = { id: '', content: '', rejectReason: '' };

/** Administration page for YAML rules used by OpenGrep and the rules proposed by agents. */
@Component({
  selector: 'app-opengrep-rule-list',
  imports: [DatePipe, FormField, TranslatePipe],
  templateUrl: './opengrep-rule-list.component.html',
  styleUrl: './opengrep-rule-list.component.css',
})
export class OpenGrepRuleListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);

  readonly canManage = computed(() => this.auth.can('rules.manage'));
  readonly catalog = rxResource({ stream: () => this.api.opengrepRules() });
  readonly proposals = rxResource({
    params: () => this.canManage() || undefined,
    stream: () => this.api.opengrepProposals(),
  });
  /** Proposal opened in the editor, approved or rejected there. */
  readonly proposal = signal<OpenGrepRuleProposal | null>(null);
  readonly deciding = signal(false);
  readonly search = signal('');
  readonly selectedId = signal<string | null>(null);
  readonly isNew = signal(false);
  readonly saving = signal(false);
  readonly validating = signal(false);
  readonly deleting = signal(false);
  readonly error = signal<Message | null>(null);
  readonly notice = signal<Message | null>(null);
  readonly validationOutput = signal<string | null>(null);

  readonly formModel = signal<RuleFormModel>({ ...EMPTY_RULE });
  readonly ruleForm = form(this.formModel, (path) => {
    required(path.id, { message: () => this.i18n.translate('opengrepRules.idRequired') });
    pattern(path.id, RULE_ID_PATTERN, {
      message: () => this.i18n.translate('opengrepRules.idPattern'),
    });
    // The id of an installed rule or of a proposal never changes
    readonly(path.id, () => !this.isNew() || !this.canManage());
    required(path.content, {
      message: () => this.i18n.translate('opengrepRules.contentRequired'),
    });
    maxLength(path.content, MAX_RULE_CHARS);
    readonly(path.content, () => !this.canManage());
    maxLength(path.rejectReason, MAX_REASON_CHARS);
  });

  readonly filteredRules = computed(() => {
    const query = this.search().trim().toLocaleLowerCase();
    return (this.catalog.value()?.rules ?? []).filter((rule) =>
      rule.id.toLocaleLowerCase().includes(query),
    );
  });

  readonly pendingProposals = computed(() => this.proposals.value()?.proposals ?? []);

  readonly hasSelection = computed(
    () => this.isNew() || this.selectedId() !== null || this.proposal() !== null,
  );

  startCreate(): void {
    this.clearMessages();
    this.proposal.set(null);
    this.isNew.set(true);
    this.selectedId.set(null);
    this.load({ id: '', content: NEW_RULE_TEMPLATE });
  }

  async select(rule: OpenGrepRule): Promise<void> {
    this.clearMessages();
    try {
      const selected = await firstValueFrom(this.api.opengrepRule(rule.id));
      this.proposal.set(null);
      this.isNew.set(false);
      this.selectedId.set(selected.id);
      this.load(selected);
    } catch (error: unknown) {
      this.error.set(describeError(error));
    }
  }

  review(proposal: OpenGrepRuleProposal): void {
    this.clearMessages();
    this.isNew.set(false);
    this.selectedId.set(null);
    this.proposal.set(proposal);
    this.load({ id: proposal.rule_id, content: proposal.content });
  }

  async approve(): Promise<void> {
    const proposal = this.proposal();
    if (!proposal || !this.checkForm()) return;
    this.deciding.set(true);
    this.clearMessages();
    try {
      const content = this.formModel().content;
      await firstValueFrom(this.api.approveOpenGrepProposal(proposal.id, content));
      this.proposal.set(null);
      this.selectedId.set(proposal.rule_id);
      this.notice.set(msg('opengrepRules.approved'));
      this.proposals.reload();
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.deciding.set(false);
    }
  }

  async reject(): Promise<void> {
    const proposal = this.proposal();
    if (!proposal || this.ruleForm.rejectReason().invalid()) return;
    this.deciding.set(true);
    this.clearMessages();
    try {
      const reason = this.formModel().rejectReason.trim();
      await firstValueFrom(this.api.rejectOpenGrepProposal(proposal.id, reason || null));
      this.proposal.set(null);
      this.load({ id: '', content: '' });
      this.notice.set(msg('opengrepRules.rejected'));
      this.proposals.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.deciding.set(false);
    }
  }

  async validate(): Promise<void> {
    if (!this.checkForm()) return;
    this.validating.set(true);
    this.clearMessages();
    try {
      const result = await firstValueFrom(this.api.validateOpenGrepRule(this.payload()));
      this.validationOutput.set(result.message);
      this.notice.set(msg('opengrepRules.validationPassed'));
    } catch (error: unknown) {
      const message = describeError(error);
      this.error.set(message);
      this.validationOutput.set(this.i18n.translate(message));
    } finally {
      this.validating.set(false);
    }
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.proposal() || !this.checkForm()) return;
    this.saving.set(true);
    this.clearMessages();
    try {
      const payload = this.payload();
      const saved = this.isNew()
        ? await firstValueFrom(this.api.createOpenGrepRule(payload))
        : await firstValueFrom(this.api.updateOpenGrepRule(payload.id, payload));
      this.isNew.set(false);
      this.selectedId.set(saved.id);
      this.load(saved);
      this.notice.set(msg('opengrepRules.saved'));
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.saving.set(false);
    }
  }

  async remove(): Promise<void> {
    const id = this.selectedId();
    if (
      !id ||
      !this.canManage() ||
      !window.confirm(this.i18n.translate('opengrepRules.confirmDelete', { id }))
    ) {
      return;
    }
    this.deleting.set(true);
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteOpenGrepRule(id));
      this.selectedId.set(null);
      this.isNew.set(false);
      this.load({ id: '', content: '' });
      this.notice.set(msg('opengrepRules.deleted'));
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.deleting.set(false);
    }
  }

  /** Fills the editor with a rule, clearing the rejection reason and the touched state. */
  private load(rule: { id: string; content: string }): void {
    this.formModel.set({ id: rule.id, content: rule.content, rejectReason: '' });
    this.ruleForm().reset();
  }

  /** True when the identifier and the YAML are valid; shows their errors otherwise. */
  private checkForm(): boolean {
    if (this.ruleForm.id().invalid() || this.ruleForm.content().invalid()) {
      this.ruleForm().markAsTouched();
      return false;
    }
    return true;
  }

  private payload(): { id: string; content: string } {
    const model = this.formModel();
    return { id: model.id.trim(), content: model.content };
  }

  private clearMessages(): void {
    this.error.set(null);
    this.notice.set(null);
    this.validationOutput.set(null);
  }
}

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && typeof error.error?.detail === 'string') {
    return serverDetail(error.error.detail);
  }
  return msg('opengrepRules.failed');
}
