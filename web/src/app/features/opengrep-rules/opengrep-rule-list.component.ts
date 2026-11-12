import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, pattern, readonly, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg, serverDetail } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SEVERITY_META } from '../../core/constants/labels';
import {
  OpenGrepRule,
  OpenGrepRuleProposal,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
} from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { HelpLinkComponent } from '../../shared/components/help-link/help-link.component';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import { SortHeaderComponent } from '../../shared/components/sort-header/sort-header.component';
import {
  TableControlMultiFilter,
  TableControlMultiFilterChange,
  TableControlsComponent,
  knownValues,
  matchesFilter,
} from '../../shared/components/table-controls/table-controls.component';
import { TableSort } from '../../shared/utils/table-sort';
import { compareTableText, filterAndSortRows } from '../../shared/utils/table-utils';
import { OpenGrepRuleSummary, summarizeRule } from './opengrep-rule-summary';

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

type RuleSortKey = 'id' | 'language' | 'severity' | 'updated';

/** A rule file of the table, with what its YAML says. */
interface RuleRow extends OpenGrepRuleSummary {
  rule: OpenGrepRule;
}

/** Severities an OpenGrep rule can give (ERROR, WARNING, INFO). */
const RULE_SEVERITIES: readonly Severity[] = SEVERITIES.filter((severity) =>
  ['high', 'medium', 'low'].includes(severity),
);

/**
 * OpenGrep rules page: the rule files in a table (search, filters by language and severity,
 * sort), each opened in a modal YAML editor, and above it the rules proposed by the agents,
 * approved or rejected in the same editor.
 */
@Component({
  selector: 'app-opengrep-rule-list',
  imports: [
    DatePipe,
    FormField,
    HelpLinkComponent,
    RefreshButtonComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './opengrep-rule-list.component.html',
  styleUrl: './opengrep-rule-list.component.css',
})
export class OpenGrepRuleListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);
  /** Modal dialog hosting the YAML editor. */
  private readonly editorDialog = viewChild.required<ElementRef<HTMLDialogElement>>('editorDialog');

  readonly severityMeta = SEVERITY_META;
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
  readonly sort = new TableSort<RuleSortKey>(
    'opengrep-rules',
    ['id', 'language', 'severity', 'updated'],
    'id',
    'asc',
  );
  readonly languageFilter = signal<string[]>([]);
  readonly severityFilter = signal<Severity[]>([]);
  /** True while the editor dialog is open: the messages are shown in it. */
  readonly editorOpen = signal(false);
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

  /** Every rule file with what its YAML says (languages, severity, message, CWE). */
  readonly rows = computed<RuleRow[]>(() =>
    (this.catalog.value()?.rules ?? []).map((rule) => ({ rule, ...summarizeRule(rule.content) })),
  );

  /** Languages of the rules, for the filter. */
  private readonly languages = computed(() =>
    [...new Set(this.rows().flatMap((row) => row.languages))].sort(compareTableText),
  );

  readonly filters = computed<TableControlMultiFilter[]>(() => [
    {
      key: 'language',
      label: this.i18n.translate('opengrepRules.language'),
      allLabel: this.i18n.translate('common.all'),
      values: this.languageFilter(),
      options: this.languages().map((language) => ({ value: language, label: language })),
    },
    {
      key: 'severity',
      label: this.i18n.translate('opengrepRules.severity'),
      allLabel: this.i18n.translate('common.all'),
      values: this.severityFilter(),
      options: RULE_SEVERITIES.map((severity) => ({
        value: severity,
        label: this.i18n.translate(SEVERITY_META[severity].label),
      })),
    },
  ]);

  readonly visibleRules = computed(() => {
    const languages = this.languageFilter();
    const severities = this.severityFilter();
    const filtered = this.rows().filter(
      (row) =>
        (!languages.length || row.languages.some((language) => languages.includes(language))) &&
        (!severities.length || (row.severity !== null && matchesFilter(severities, row.severity))),
    );
    const sort = this.sort.key();
    return filterAndSortRows(
      filtered,
      this.search(),
      this.sort.direction(),
      (row) => [row.rule.id, row.message, row.cwe, row.languages.join(' ')].join(' '),
      (left, right) => {
        if (sort === 'language') {
          return compareTableText(left.languages.join(', '), right.languages.join(', '));
        }
        if (sort === 'severity') {
          return (
            (left.severity ? SEVERITY_RANK[left.severity] : 99) -
            (right.severity ? SEVERITY_RANK[right.severity] : 99)
          );
        }
        if (sort === 'updated') {
          return left.rule.updated_at.localeCompare(right.rule.updated_at);
        }
        return compareTableText(left.rule.id, right.rule.id);
      },
    );
  });

  readonly pendingProposals = computed(() => this.proposals.value()?.proposals ?? []);

  onTableFilter({ key, values }: TableControlMultiFilterChange): void {
    if (key === 'language') {
      this.languageFilter.set(knownValues(values, this.languages()));
    } else if (key === 'severity') {
      this.severityFilter.set(knownValues(values, RULE_SEVERITIES));
    }
  }

  reload(): void {
    this.catalog.reload();
    if (this.canManage()) {
      this.proposals.reload();
    }
  }

  startCreate(): void {
    this.clearMessages();
    this.proposal.set(null);
    this.isNew.set(true);
    this.selectedId.set(null);
    this.load({ id: '', content: NEW_RULE_TEMPLATE });
    this.openEditor();
  }

  async select(rule: OpenGrepRule): Promise<void> {
    this.clearMessages();
    try {
      const selected = await firstValueFrom(this.api.opengrepRule(rule.id));
      this.proposal.set(null);
      this.isNew.set(false);
      this.selectedId.set(selected.id);
      this.load(selected);
      this.openEditor();
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
    this.openEditor();
  }

  closeEditor(): void {
    const dialog = this.editorDialog().nativeElement;
    if (dialog.open) {
      dialog.close();
    } else {
      this.onEditorClosed();
    }
  }

  /** Resets the editor when the dialog closes (close button, Escape key, or after an action). */
  onEditorClosed(): void {
    this.editorOpen.set(false);
    this.isNew.set(false);
    this.selectedId.set(null);
    this.proposal.set(null);
    this.validationOutput.set(null);
  }

  async approve(): Promise<void> {
    const proposal = this.proposal();
    if (!proposal || !this.checkForm()) return;
    this.deciding.set(true);
    this.clearMessages();
    try {
      const content = this.formModel().content;
      await firstValueFrom(this.api.approveOpenGrepProposal(proposal.id, content));
      this.closeEditor();
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
      this.closeEditor();
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
      await firstValueFrom(
        this.isNew()
          ? this.api.createOpenGrepRule(payload)
          : this.api.updateOpenGrepRule(payload.id, payload),
      );
      this.closeEditor();
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
      this.closeEditor();
      this.notice.set(msg('opengrepRules.deleted'));
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.deleting.set(false);
    }
  }

  private openEditor(): void {
    this.editorOpen.set(true);
    const dialog = this.editorDialog().nativeElement;
    if (!dialog.open) {
      dialog.showModal();
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
