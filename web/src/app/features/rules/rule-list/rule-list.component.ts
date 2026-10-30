import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService, Message, msg, serverDetail } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { MarkdownFieldComponent } from '../../../shared/components/markdown-field/markdown-field.component';
import {
  CustomRule,
  CustomRuleWrite,
  RuleOrigin,
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
} from '../../../core/models/api.models';
import { ApiService, saveBlob } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import {
  PackFile,
  PackFileError,
  PackTransferComponent,
} from '../../../shared/components/pack-transfer/pack-transfer.component';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { SortHeaderComponent } from '../../../shared/components/sort-header/sort-header.component';
import { TableSort } from '../../../shared/utils/table-sort';
import { compareTableText, filterAndSortRows } from '../../../shared/utils/table-utils';

interface RuleFormModel {
  id: string;
  title: string;
  severity: Severity | '';
  cwe: string;
  languages: string;
  pattern: string;
  advice: string;
  ignore_case: boolean;
}

const EMPTY_RULE: RuleFormModel = {
  id: '',
  title: '',
  severity: '',
  cwe: '',
  languages: 'python',
  pattern: '',
  advice: '',
  ignore_case: true,
};

type RuleSortKey = 'id' | 'severity' | 'updated';

/** Admin view for the scan rules stored in the database (default and custom). */
@Component({
  selector: 'app-rule-list',
  imports: [
    HelpLinkComponent,
    MarkdownFieldComponent,
    PackTransferComponent,
    DatePipe,
    FormField,
    RefreshButtonComponent,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './rule-list.component.html',
  styleUrl: './rule-list.component.css',
})
export class RuleListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly i18n = inject(I18nService);
  /** Modal dialog hosting the create / edit form. */
  private readonly editorDialog = viewChild.required<ElementRef<HTMLDialogElement>>('editorDialog');

  /** False for a user who may only read the rules (rules.read). */
  readonly canManage = computed(() => this.auth.can('rules.manage'));
  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;
  readonly catalog = rxResource({ stream: () => this.api.customRules() });
  /** Origin filter of the table ('' shows every rule). */
  readonly originFilter = signal<RuleOrigin | ''>('');
  readonly search = signal('');
  readonly sort = new TableSort<RuleSortKey>('rules', ['id', 'severity', 'updated'], 'id', 'asc');
  readonly severityFilter = signal<Severity | ''>('');
  readonly filters = computed<TableControlFilter[]>(() => [
    {
      key: 'origin',
      label: this.i18n.translate('rules.origin'),
      value: this.originFilter(),
      options: [
        { value: '', label: this.i18n.translate('rules.allOrigins') },
        { value: 'builtin', label: this.i18n.translate('rules.builtinPlural') },
        { value: 'custom', label: this.i18n.translate('rules.customPlural') },
      ],
    },
    {
      key: 'severity',
      label: this.i18n.translate('rules.severity'),
      value: this.severityFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...SEVERITIES.map((severity) => ({
          value: severity,
          label: this.i18n.translate(this.severityMeta[severity].label),
        })),
      ],
    },
  ]);
  readonly visibleRules = computed(() => {
    const rules = this.catalog.value()?.rules ?? [];
    const origin = this.originFilter();
    const severity = this.severityFilter();
    const filtered = rules.filter(
      (rule) => (!origin || rule.origin === origin) && (!severity || rule.severity === severity),
    );
    const sort = this.sort.key();
    return filterAndSortRows(
      filtered,
      this.search(),
      this.sort.direction(),
      (rule) =>
        [rule.id, rule.title, rule.cwe, rule.languages.join(' '), rule.pattern, rule.advice].join(
          ' ',
        ),
      (left, right) => {
        if (sort === 'severity') {
          return SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity];
        }
        if (sort === 'updated') {
          return left.updated_at.localeCompare(right.updated_at);
        }
        return compareTableText(left.id, right.id);
      },
    );
  });
  readonly formModel = signal<RuleFormModel>({ ...EMPTY_RULE });
  readonly ruleForm = form(this.formModel, (path) => {
    required(path.id, { message: () => this.i18n.translate('rules.idRequired') });
    maxLength(path.id, 50);
    required(path.title, { message: () => this.i18n.translate('rules.titleRequired') });
    maxLength(path.title, 300);
    required(path.severity, { message: () => this.i18n.translate('rules.severityRequired') });
    required(path.languages, { message: () => this.i18n.translate('rules.languagesRequired') });
    maxLength(path.languages, 1056);
    maxLength(path.cwe, 20);
    required(path.pattern, { message: () => this.i18n.translate('rules.patternRequired') });
    maxLength(path.pattern, 500);
    maxLength(path.advice, 5000);
  });
  readonly editingId = signal<string | null>(null);
  readonly creating = signal(false);
  readonly saving = signal(false);
  readonly reloading = signal(false);
  readonly error = signal<Message | null>(null);
  /** Error raised while saving, shown inside the modal. */
  readonly formError = signal<Message | null>(null);
  readonly notice = signal<Message | null>(null);
  /** True while a pack is exported or imported. */
  readonly transferring = signal(false);

  startCreate(): void {
    this.clearMessages();
    this.editingId.set(null);
    this.formModel.set({ ...EMPTY_RULE });
    this.creating.set(true);
    this.openEditor();
  }

  startEdit(rule: CustomRule): void {
    this.clearMessages();
    this.creating.set(false);
    this.editingId.set(rule.id);
    this.formModel.set({
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      cwe: rule.cwe,
      languages: rule.languages.join(', '),
      pattern: rule.pattern,
      advice: rule.advice,
      ignore_case: rule.ignore_case,
    });
    this.openEditor();
  }

  /** Closes the modal; the dialog `close` event then resets the editor state. */
  cancelEdit(): void {
    const dialog = this.editorDialog().nativeElement;
    if (dialog.open) {
      dialog.close();
    } else {
      this.onEditorClosed();
    }
  }

  /** Resets the editor state when the modal closes (buttons, Escape key or save). */
  onEditorClosed(): void {
    this.creating.set(false);
    this.editingId.set(null);
    this.formError.set(null);
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.ruleForm().invalid()) {
      this.ruleForm().markAsTouched();
      return;
    }
    const model = this.formModel();
    const payload: CustomRuleWrite = {
      id: model.id.trim(),
      title: model.title.trim(),
      severity: model.severity as Severity,
      cwe: model.cwe.trim(),
      languages: model.languages
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
      pattern: model.pattern,
      advice: model.advice,
      ignore_case: model.ignore_case,
    };
    this.saving.set(true);
    this.clearMessages();
    this.formError.set(null);
    try {
      const id = this.editingId();
      if (id) {
        await firstValueFrom(this.api.updateCustomRule(id, payload));
        this.notice.set(msg('rules.updated', { id }));
      } else {
        await firstValueFrom(this.api.createCustomRule(payload));
        this.notice.set(msg('rules.created', { id: payload.id }));
      }
      this.cancelEdit();
      this.catalog.reload();
    } catch (error: unknown) {
      this.formError.set(describeError(error));
    } finally {
      this.saving.set(false);
    }
  }

  async toggle(rule: CustomRule): Promise<void> {
    this.clearMessages();
    try {
      await firstValueFrom(this.api.setCustomRuleEnabled(rule.id, !rule.enabled));
      this.notice.set(
        msg(rule.enabled ? 'rules.disabledNotice' : 'rules.enabledNotice', { id: rule.id }),
      );
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    }
  }

  onOriginFilter(event: Event): void {
    this.setOriginFilter((event.target as HTMLSelectElement).value);
  }

  setOriginFilter(value: string): void {
    this.originFilter.set(value === 'builtin' || value === 'custom' ? value : '');
  }

  onTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'origin') {
      this.setOriginFilter(change.value);
    } else if (change.key === 'severity') {
      this.severityFilter.set(
        SEVERITIES.includes(change.value as Severity) ? (change.value as Severity) : '',
      );
    }
  }

  async remove(rule: CustomRule): Promise<void> {
    if (!window.confirm(this.i18n.translate('rules.confirmDelete', { id: rule.id }))) {
      return;
    }
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteCustomRule(rule.id));
      this.notice.set(msg('rules.deleted', { id: rule.id }));
      if (this.editingId() === rule.id) {
        this.cancelEdit();
      }
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    }
  }

  async reload(): Promise<void> {
    this.reloading.set(true);
    this.clearMessages();
    try {
      const result = await firstValueFrom(this.api.reloadCustomRules());
      this.notice.set(msg('rules.reloaded', { count: result.loaded_rules }));
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.reloading.set(false);
    }
  }

  /** Download the security-review-rules.toml pack. */
  async exportPack(): Promise<void> {
    this.clearMessages();
    this.transferring.set(true);
    try {
      saveBlob(
        await firstValueFrom(this.api.exportRulePack(['rules'])),
        'security-review-rules.toml',
      );
    } catch {
      this.error.set(msg('pack.exportFailed'));
    } finally {
      this.transferring.set(false);
    }
  }

  /** Import a TOML pack chosen by the user (all or nothing), then reload the list. */
  async importPack(file: PackFile): Promise<void> {
    this.clearMessages();
    this.transferring.set(true);
    try {
      const result = await firstValueFrom(this.api.importRulePack(file.name, file.content));
      this.notice.set(
        msg('pack.rulesImported', {
          file: file.name,
          rules: result.rules,
          items: result.checklist_items,
          disabled: result.disabled_rules,
        }),
      );
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.transferring.set(false);
    }
  }

  onPackRejected(reason: PackFileError): void {
    this.clearMessages();
    this.error.set(msg(reason === 'tooLarge' ? 'pack.tooLarge' : 'pack.unreadable'));
  }

  private openEditor(): void {
    this.formError.set(null);
    const dialog = this.editorDialog().nativeElement;
    if (!dialog.open) {
      dialog.showModal();
    }
  }

  private clearMessages(): void {
    this.error.set(null);
    this.notice.set(null);
  }
}

function describeError(error: unknown): Message {
  if (error instanceof HttpErrorResponse && typeof error.error?.detail === 'string') {
    return serverDetail(error.error.detail);
  }
  return msg('rules.failed');
}
