import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg, serverDetail } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { MarkdownFieldComponent } from '../../../shared/components/markdown-field/markdown-field.component';
import { ChecklistItem, ChecklistItemWrite } from '../../../core/models/api.models';
import { ApiService, saveBlob } from '../../../core/services/api.service';
import {
  PackFile,
  PackFileError,
  PackTransferComponent,
} from '../../../shared/components/pack-transfer/pack-transfer.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { SortHeaderComponent } from '../../../shared/components/sort-header/sort-header.component';
import { TableSort } from '../../../shared/utils/table-sort';
import { compareTableText, filterAndSortRows } from '../../../shared/utils/table-utils';

interface ChecklistFormModel {
  domain: string;
  id: string;
  title: string;
  what_to_look_for: string;
  cwe: string;
}

const EMPTY_ITEM: ChecklistFormModel = {
  domain: '',
  id: '',
  title: '',
  what_to_look_for: '',
  cwe: '',
};

type ChecklistSortKey = 'domain' | 'title';

/** Admin view for checklist items grouped by their review domain. */
@Component({
  selector: 'app-checklist-list',
  imports: [
    MarkdownFieldComponent,
    PackTransferComponent,
    FormField,
    SortHeaderComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './checklist-list.component.html',
  styleUrl: './checklist-list.component.css',
})
export class ChecklistListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  private readonly editorDialog = viewChild.required<ElementRef<HTMLDialogElement>>('editorDialog');

  readonly catalog = rxResource({ stream: () => this.api.checklistItems() });
  readonly domainFilter = signal('');
  readonly search = signal('');
  readonly sort = new TableSort<ChecklistSortKey>(
    'checklists',
    ['domain', 'title'],
    'domain',
    'asc',
  );
  readonly originFilter = signal<'all' | 'builtin' | 'custom'>('all');
  readonly domains = computed(() =>
    [...new Set((this.catalog.value()?.checklist_items ?? []).map((item) => item.domain))].sort(),
  );
  readonly filters = computed<TableControlFilter[]>(() => [
    {
      key: 'domain',
      label: this.i18n.translate('checklists.domain'),
      value: this.domainFilter(),
      options: [
        { value: '', label: this.i18n.translate('checklists.allDomains') },
        ...this.domains().map((domain) => ({ value: domain, label: domain })),
      ],
    },
    {
      key: 'origin',
      label: this.i18n.translate('rules.origin'),
      value: this.originFilter(),
      options: [
        { value: 'all', label: this.i18n.translate('common.all') },
        { value: 'builtin', label: this.i18n.translate('rules.builtin') },
        { value: 'custom', label: this.i18n.translate('rules.custom') },
      ],
    },
  ]);
  readonly visibleItems = computed(() => {
    const domain = this.domainFilter();
    const origin = this.originFilter();
    const items = (this.catalog.value()?.checklist_items ?? []).filter(
      (item) => (!domain || item.domain === domain) && (origin === 'all' || item.origin === origin),
    );
    const sort = this.sort.key();
    return filterAndSortRows(
      items,
      this.search(),
      this.sort.direction(),
      (item) => [item.domain, item.id, item.title, item.what_to_look_for, item.cwe].join(' '),
      (left, right) =>
        compareTableText(left[sort], right[sort]) ||
        compareTableText(left.domain, right.domain) ||
        compareTableText(left.id, right.id),
    );
  });
  readonly formModel = signal<ChecklistFormModel>({ ...EMPTY_ITEM });
  readonly itemForm = form(this.formModel, (path) => {
    required(path.domain, { message: () => this.i18n.translate('checklists.domainRequired') });
    maxLength(path.domain, 31);
    required(path.id, { message: () => this.i18n.translate('rules.idRequired') });
    maxLength(path.id, 50);
    required(path.title, { message: () => this.i18n.translate('rules.titleRequired') });
    maxLength(path.title, 300);
    required(path.what_to_look_for, {
      message: () => this.i18n.translate('checklists.checkRequired'),
    });
    maxLength(path.what_to_look_for, 5000);
    maxLength(path.cwe, 20);
  });
  readonly editingItem = signal<{ domain: string; id: string } | null>(null);
  readonly creating = signal(false);
  readonly saving = signal(false);
  readonly error = signal<Message | null>(null);
  readonly formError = signal<Message | null>(null);
  readonly notice = signal<Message | null>(null);
  /** True while a pack is exported or imported. */
  readonly transferring = signal(false);

  onDomainFilter(event: Event): void {
    this.setDomainFilter((event.target as HTMLSelectElement).value);
  }

  setDomainFilter(value: string): void {
    this.domainFilter.set(value);
  }

  onTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'domain') {
      this.setDomainFilter(change.value);
    } else if (change.key === 'origin') {
      this.originFilter.set(
        change.value === 'builtin' || change.value === 'custom' ? change.value : 'all',
      );
    }
  }

  startCreate(): void {
    this.clearMessages();
    this.editingItem.set(null);
    this.formModel.set({ ...EMPTY_ITEM });
    this.creating.set(true);
    this.openEditor();
  }

  startEdit(item: ChecklistItem): void {
    this.clearMessages();
    this.creating.set(false);
    this.editingItem.set({ domain: item.domain, id: item.id });
    this.formModel.set({
      domain: item.domain,
      id: item.id,
      title: item.title,
      what_to_look_for: item.what_to_look_for,
      cwe: item.cwe,
    });
    this.openEditor();
  }

  cancelEdit(): void {
    const dialog = this.editorDialog().nativeElement;
    if (dialog.open) {
      dialog.close();
    } else {
      this.onEditorClosed();
    }
  }

  onEditorClosed(): void {
    this.creating.set(false);
    this.editingItem.set(null);
    this.formError.set(null);
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.itemForm().invalid()) {
      this.itemForm().markAsTouched();
      return;
    }
    const model = this.formModel();
    const payload: ChecklistItemWrite = {
      domain: model.domain.trim().toLowerCase(),
      id: model.id.trim(),
      title: model.title.trim(),
      what_to_look_for: model.what_to_look_for.trim(),
      cwe: model.cwe.trim(),
    };
    this.saving.set(true);
    this.clearMessages();
    this.formError.set(null);
    try {
      const editing = this.editingItem();
      if (editing) {
        await firstValueFrom(this.api.updateChecklistItem(editing.domain, editing.id, payload));
        this.notice.set(msg('checklists.updated', { id: `${editing.domain}/${editing.id}` }));
      } else {
        await firstValueFrom(this.api.createChecklistItem(payload));
        this.notice.set(msg('checklists.created', { id: `${payload.domain}/${payload.id}` }));
      }
      this.cancelEdit();
      this.catalog.reload();
    } catch (error: unknown) {
      this.formError.set(describeError(error));
    } finally {
      this.saving.set(false);
    }
  }

  async remove(item: ChecklistItem): Promise<void> {
    const id = `${item.domain}/${item.id}`;
    if (!window.confirm(this.i18n.translate('checklists.confirmDelete', { id }))) {
      return;
    }
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteChecklistItem(item.domain, item.id));
      this.notice.set(msg('checklists.deleted', { id }));
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    }
  }

  /** Download the security-review-checklists.toml pack. */
  async exportPack(): Promise<void> {
    this.clearMessages();
    this.transferring.set(true);
    try {
      saveBlob(
        await firstValueFrom(this.api.exportRulePack(['checklist'])),
        'security-review-checklists.toml',
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
  return msg('checklists.failed');
}
