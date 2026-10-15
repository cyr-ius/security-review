import { HttpErrorResponse } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength, pattern, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { DevStandard, DevStandardSummary, DevStandardWrite } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';

/** Editable fields; the lists are typed as comma separated text. */
interface StandardFormModel {
  slug: string;
  title: string;
  description: string;
  technologies: string;
  file_patterns: string;
  content: string;
  enabled: boolean;
}

const EMPTY_STANDARD: StandardFormModel = {
  slug: '',
  title: '',
  description: '',
  technologies: '',
  file_patterns: '',
  content: '',
  enabled: true,
};

/** Same limits as the API (standards.py). */
const MAX_CONTENT_CHARS = 50_000;

/** Development standards served to the developers' AI: read by everyone, edited by admins. */
@Component({
  selector: 'app-standard-list',
  imports: [FormField],
  templateUrl: './standard-list.component.html',
  styleUrl: './standard-list.component.css',
})
export class StandardListComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly editorDialog = viewChild.required<ElementRef<HTMLDialogElement>>('editorDialog');
  private readonly viewerDialog = viewChild.required<ElementRef<HTMLDialogElement>>('viewerDialog');

  readonly isAdmin = computed(() => this.auth.identity()?.role === 'admin');
  readonly catalog = rxResource({ stream: () => this.api.devStandards() });
  readonly query = signal('');
  readonly visibleStandards = computed(() => {
    const standards = this.catalog.value()?.standards ?? [];
    const query = this.query().trim().toLowerCase();
    if (!query) {
      return standards;
    }
    return standards.filter((item) =>
      [item.slug, item.title, item.description, ...item.technologies, ...item.file_patterns]
        .join(' ')
        .toLowerCase()
        .includes(query),
    );
  });

  readonly formModel = signal<StandardFormModel>({ ...EMPTY_STANDARD });
  readonly standardForm = form(this.formModel, (path) => {
    required(path.slug, { message: "L'identifiant est obligatoire" });
    maxLength(path.slug, 50);
    pattern(path.slug, /^[a-z0-9][a-z0-9._+-]*$/, {
      message: 'Minuscules, chiffres et . _ + - uniquement',
    });
    required(path.title, { message: 'Le titre est obligatoire' });
    maxLength(path.title, 200);
    maxLength(path.description, 500);
    required(path.content, { message: 'Le contenu est obligatoire' });
    maxLength(path.content, MAX_CONTENT_CHARS);
  });
  readonly editingSlug = signal<string | null>(null);
  readonly creating = signal(false);
  readonly viewed = signal<DevStandard | null>(null);
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);
  readonly formError = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  setQuery(value: string): void {
    this.query.set(value);
  }

  async view(item: DevStandardSummary): Promise<void> {
    this.clearMessages();
    try {
      this.viewed.set(await firstValueFrom(this.api.devStandard(item.slug)));
      const dialog = this.viewerDialog().nativeElement;
      if (!dialog.open) {
        dialog.showModal();
      }
    } catch (error: unknown) {
      this.error.set(describeError(error, 'Impossible de charger la norme.'));
    }
  }

  closeViewer(): void {
    const dialog = this.viewerDialog().nativeElement;
    if (dialog.open) {
      dialog.close();
    }
  }

  startCreate(): void {
    this.clearMessages();
    this.editingSlug.set(null);
    this.formModel.set({ ...EMPTY_STANDARD });
    this.creating.set(true);
    this.openEditor();
  }

  async startEdit(item: DevStandardSummary): Promise<void> {
    this.clearMessages();
    try {
      const standard = await firstValueFrom(this.api.devStandard(item.slug));
      this.closeViewer();
      this.creating.set(false);
      this.editingSlug.set(standard.slug);
      this.formModel.set({
        slug: standard.slug,
        title: standard.title,
        description: standard.description,
        technologies: standard.technologies.join(', '),
        file_patterns: standard.file_patterns.join(', '),
        content: standard.content,
        enabled: standard.enabled,
      });
      this.openEditor();
    } catch (error: unknown) {
      this.error.set(describeError(error, 'Impossible de charger la norme.'));
    }
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
    this.editingSlug.set(null);
    this.formError.set(null);
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.standardForm().invalid()) {
      this.standardForm().markAsTouched();
      return;
    }
    const model = this.formModel();
    const payload: DevStandardWrite = {
      slug: model.slug.trim(),
      title: model.title.trim(),
      description: model.description.trim(),
      technologies: splitList(model.technologies).map((item) => item.toLowerCase()),
      file_patterns: splitList(model.file_patterns),
      content: model.content.trim(),
      enabled: model.enabled,
    };
    this.saving.set(true);
    this.clearMessages();
    this.formError.set(null);
    try {
      const editing = this.editingSlug();
      if (editing) {
        await firstValueFrom(this.api.updateDevStandard(editing, payload));
        this.notice.set(`Norme ${editing} modifiée.`);
      } else {
        await firstValueFrom(this.api.createDevStandard(payload));
        this.notice.set(`Norme ${payload.slug} créée.`);
      }
      this.cancelEdit();
      this.catalog.reload();
    } catch (error: unknown) {
      this.formError.set(describeError(error, "L'enregistrement de la norme a échoué."));
    } finally {
      this.saving.set(false);
    }
  }

  async remove(item: DevStandardSummary): Promise<void> {
    if (!window.confirm(`Supprimer définitivement la norme ${item.slug} ?`)) {
      return;
    }
    this.clearMessages();
    try {
      await firstValueFrom(this.api.deleteDevStandard(item.slug));
      this.notice.set(`Norme ${item.slug} supprimée.`);
      this.catalog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error, 'La suppression de la norme a échoué.'));
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

/** Split a comma or newline separated list, dropping empty entries. */
function splitList(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function describeError(error: unknown, fallback: string): string {
  if (error instanceof HttpErrorResponse && typeof error.error?.detail === 'string') {
    return error.error.detail;
  }
  return fallback;
}
