import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { MessageKey } from '../../core/i18n/messages';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { OpenGrepRule } from '../../core/models/api.models';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';

/** Administration page for YAML rules used by OpenGrep. */
@Component({
  selector: 'app-opengrep-rule-list',
  imports: [DatePipe, TranslatePipe],
  templateUrl: './opengrep-rule-list.component.html',
  styleUrl: './opengrep-rule-list.component.css',
})
export class OpenGrepRuleListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);

  readonly canManage = computed(() => this.auth.can('rules.manage'));
  readonly catalog = rxResource({ stream: () => this.api.opengrepRules() });
  readonly search = signal('');
  readonly selectedId = signal<string | null>(null);
  readonly ruleId = signal('');
  readonly content = signal('');
  readonly isNew = signal(false);
  readonly saving = signal(false);
  readonly validating = signal(false);
  readonly deleting = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<MessageKey | null>(null);
  readonly validationOutput = signal<string | null>(null);

  readonly filteredRules = computed(() => {
    const query = this.search().trim().toLocaleLowerCase();
    return (this.catalog.value()?.rules ?? []).filter((rule) =>
      rule.id.toLocaleLowerCase().includes(query),
    );
  });

  readonly hasSelection = computed(() => this.isNew() || this.selectedId() !== null);

  startCreate(): void {
    this.clearMessages();
    this.isNew.set(true);
    this.selectedId.set(null);
    this.ruleId.set('');
    this.content.set(
      'rules:\n' +
        '  - id: example-rule\n' +
        '    message: Example security rule\n' +
        '    languages: [python]\n' +
        '    severity: WARNING\n' +
        '    pattern: eval($VALUE)\n',
    );
  }

  async select(rule: OpenGrepRule): Promise<void> {
    this.clearMessages();
    try {
      const selected = await firstValueFrom(this.api.opengrepRule(rule.id));
      this.isNew.set(false);
      this.selectedId.set(selected.id);
      this.ruleId.set(selected.id);
      this.content.set(selected.content);
    } catch (error: unknown) {
      this.error.set(this.describeError(error));
    }
  }

  async validate(): Promise<void> {
    const payload = this.payload();
    if (!payload) return;
    this.validating.set(true);
    this.clearMessages();
    try {
      const result = await firstValueFrom(this.api.validateOpenGrepRule(payload));
      this.validationOutput.set(result.message);
      this.notice.set('opengrepRules.validationPassed');
    } catch (error: unknown) {
      this.error.set(this.describeError(error));
      this.validationOutput.set(this.describeError(error));
    } finally {
      this.validating.set(false);
    }
  }

  async save(): Promise<void> {
    const payload = this.payload();
    if (!payload) return;
    this.saving.set(true);
    this.clearMessages();
    try {
      const saved = this.isNew()
        ? await firstValueFrom(this.api.createOpenGrepRule(payload))
        : await firstValueFrom(this.api.updateOpenGrepRule(payload.id, payload));
      this.isNew.set(false);
      this.selectedId.set(saved.id);
      this.ruleId.set(saved.id);
      this.content.set(saved.content);
      this.notice.set('opengrepRules.saved');
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(this.describeError(error));
    } finally {
      this.saving.set(false);
    }
  }

  async remove(): Promise<void> {
    const id = this.selectedId();
    if (!id || !this.canManage() || !window.confirm(`Delete OpenGrep rule "${id}"?`)) return;
    this.deleting.set(true);
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteOpenGrepRule(id));
      this.selectedId.set(null);
      this.isNew.set(false);
      this.ruleId.set('');
      this.content.set('');
      this.notice.set('opengrepRules.deleted');
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(this.describeError(error));
    } finally {
      this.deleting.set(false);
    }
  }

  private payload(): { id: string; content: string } | null {
    const id = this.ruleId().trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$/.test(id)) {
      this.error.set('Use an identifier of 3 to 80 letters, digits, dots, underscores or hyphens.');
      return null;
    }
    if (!this.content().trim()) {
      this.error.set('The YAML content cannot be empty.');
      return null;
    }
    return { id, content: this.content() };
  }

  private clearMessages(): void {
    this.error.set(null);
    this.notice.set(null);
    this.validationOutput.set(null);
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const detail = error.error?.detail;
      if (typeof detail === 'string') return detail;
      return error.status ? `Request failed (HTTP ${error.status}).` : 'The server is unreachable.';
    }
    return 'The operation failed.';
  }
}
