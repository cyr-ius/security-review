import { HttpErrorResponse } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { CustomRule, CustomRuleWrite, SEVERITIES, Severity } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';

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

/** Admin view for TOML-backed custom scan rules. */
@Component({
  selector: 'app-rule-list',
  imports: [FormField],
  templateUrl: './rule-list.component.html',
  styleUrl: './rule-list.component.css',
})
export class RuleListComponent {
  private readonly api = inject(ApiService);

  readonly severities = SEVERITIES;
  readonly catalog = rxResource({ stream: () => this.api.customRules() });
  readonly formModel = signal<RuleFormModel>({ ...EMPTY_RULE });
  readonly ruleForm = form(this.formModel, (path) => {
    required(path.id, { message: "L'identifiant est obligatoire" });
    maxLength(path.id, 50);
    required(path.title, { message: 'Le titre est obligatoire' });
    maxLength(path.title, 300);
    required(path.severity, { message: 'La sévérité est obligatoire' });
    required(path.languages, { message: 'Au moins un langage est requis' });
    maxLength(path.languages, 1056);
    maxLength(path.cwe, 20);
    required(path.pattern, { message: 'Le motif est obligatoire' });
    maxLength(path.pattern, 500);
    maxLength(path.advice, 5000);
  });
  readonly editingId = signal<string | null>(null);
  readonly creating = signal(false);
  readonly saving = signal(false);
  readonly reloading = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  startCreate(): void {
    this.clearMessages();
    this.editingId.set(null);
    this.formModel.set({ ...EMPTY_RULE });
    this.creating.set(true);
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
  }

  cancelEdit(): void {
    this.creating.set(false);
    this.editingId.set(null);
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
      languages: model.languages.split(',').map((item) => item.trim()).filter(Boolean),
      pattern: model.pattern,
      advice: model.advice,
      ignore_case: model.ignore_case,
    };
    this.saving.set(true);
    this.clearMessages();
    try {
      const id = this.editingId();
      if (id) {
        await firstValueFrom(this.api.updateCustomRule(id, payload));
        this.notice.set(`Règle ${id} modifiée.`);
      } else {
        await firstValueFrom(this.api.createCustomRule(payload));
        this.notice.set(`Règle ${payload.id} créée.`);
      }
      this.cancelEdit();
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.saving.set(false);
    }
  }

  async toggle(rule: CustomRule): Promise<void> {
    this.clearMessages();
    try {
      await firstValueFrom(this.api.setCustomRuleEnabled(rule.id, !rule.enabled));
      this.notice.set(`Règle ${rule.id} ${rule.enabled ? 'désactivée' : 'activée'}.`);
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    }
  }

  async remove(rule: CustomRule): Promise<void> {
    if (!window.confirm(`Supprimer définitivement la règle ${rule.id} ?`)) {
      return;
    }
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteCustomRule(rule.id));
      this.notice.set(`Règle ${rule.id} supprimée.`);
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
      this.notice.set(`${result.loaded_rules} règle(s) TOML rechargée(s).`);
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.reloading.set(false);
    }
  }

  private clearMessages(): void {
    this.error.set(null);
    this.notice.set(null);
  }
}

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    return error.error?.detail ?? 'La modification des règles a échoué.';
  }
  return 'La modification des règles a échoué.';
}
