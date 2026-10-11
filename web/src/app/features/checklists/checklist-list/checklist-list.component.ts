import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { ChecklistItem, ChecklistItemWrite } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';

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

/** Admin view for checklist items grouped by their review domain. */
@Component({
  selector: 'app-checklist-list',
  imports: [FormField],
  templateUrl: './checklist-list.component.html',
  styleUrl: './checklist-list.component.css',
})
export class ChecklistListComponent {
  private readonly api = inject(ApiService);
  private readonly editorDialog = viewChild.required<ElementRef<HTMLDialogElement>>('editorDialog');

  readonly catalog = rxResource({ stream: () => this.api.checklistItems() });
  readonly domainFilter = signal('');
  readonly domains = computed(() =>
    [...new Set((this.catalog.value()?.checklist_items ?? []).map((item) => item.domain))].sort(),
  );
  readonly visibleItems = computed(() => {
    const items = this.catalog.value()?.checklist_items ?? [];
    const domain = this.domainFilter();
    return domain ? items.filter((item) => item.domain === domain) : items;
  });
  readonly formModel = signal<ChecklistFormModel>({ ...EMPTY_ITEM });
  readonly itemForm = form(this.formModel, (path) => {
    required(path.domain, { message: 'Le domaine est obligatoire' });
    maxLength(path.domain, 31);
    required(path.id, { message: "L'identifiant est obligatoire" });
    maxLength(path.id, 50);
    required(path.title, { message: 'Le titre est obligatoire' });
    maxLength(path.title, 300);
    required(path.what_to_look_for, { message: 'Le point de contrôle est obligatoire' });
    maxLength(path.what_to_look_for, 5000);
    maxLength(path.cwe, 20);
  });
  readonly editingItem = signal<{ domain: string; id: string } | null>(null);
  readonly creating = signal(false);
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);
  readonly formError = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  setDomainFilter(value: string): void {
    this.domainFilter.set(value);
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
        this.notice.set(`Checklist ${editing.domain}/${editing.id} modifiée.`);
      } else {
        await firstValueFrom(this.api.createChecklistItem(payload));
        this.notice.set(`Checklist ${payload.domain}/${payload.id} créée.`);
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
    if (!window.confirm(`Supprimer définitivement ${item.domain}/${item.id} ?`)) {
      return;
    }
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteChecklistItem(item.domain, item.id));
      this.notice.set(`Checklist ${item.domain}/${item.id} supprimée.`);
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    }
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

function describeError(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    return error.error?.detail ?? 'La modification de la checklist a échoué.';
  }
  return 'La modification de la checklist a échoué.';
}
