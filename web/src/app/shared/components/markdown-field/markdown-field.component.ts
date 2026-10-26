import {
  Component,
  ElementRef,
  booleanAttribute,
  input,
  model,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { FormValueControl } from '@angular/forms/signals';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { MarkdownViewComponent } from '../markdown-view/markdown-view.component';

export type MarkdownFieldMode = 'edit' | 'split' | 'preview';

/**
 * Text area bound with [formField], with a button that opens the same text in full screen,
 * next to its rendered Markdown. The full screen editor edits the form value directly: closing
 * it goes back to the form, which still saves or cancels the changes.
 */
@Component({
  selector: 'app-markdown-field',
  imports: [MarkdownViewComponent, TranslatePipe],
  templateUrl: './markdown-field.component.html',
  styleUrl: './markdown-field.component.css',
})
export class MarkdownFieldComponent implements FormValueControl<string> {
  readonly value = model('');
  readonly disabled = input(false);
  readonly invalid = input(false);
  readonly touched = input(false);
  readonly touch = output<void>();

  /** id of the compact text area, for the <label for> of the form. */
  readonly inputId = input.required<string>();
  /** Title of the full screen editor (the label of the field). */
  readonly label = input.required<string>();
  readonly rows = input(4);
  readonly monospace = input(false, { transform: booleanAttribute });
  readonly describedBy = input<string>();

  private readonly compactInput = viewChild.required<ElementRef<HTMLTextAreaElement>>('compact');
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');

  readonly expanded = signal(false);
  readonly mode = signal<MarkdownFieldMode>('split');
  readonly modes: readonly MarkdownFieldMode[] = ['edit', 'split', 'preview'];
  readonly modeMeta: Record<MarkdownFieldMode, { label: MessageKey; icon: string }> = {
    edit: { label: 'markdown.edit', icon: 'bi-pencil' },
    split: { label: 'markdown.split', icon: 'bi-layout-split' },
    preview: { label: 'markdown.preview', icon: 'bi-eye' },
  };

  onInput(event: Event): void {
    this.value.set((event.target as HTMLTextAreaElement).value);
  }

  expand(): void {
    const dialog = this.dialog().nativeElement;
    this.expanded.set(true);
    if (!dialog.open) {
      dialog.showModal();
    }
  }

  collapse(): void {
    const dialog = this.dialog().nativeElement;
    if (dialog.open) {
      dialog.close();
    }
  }

  onClosed(): void {
    this.expanded.set(false);
    this.touch.emit();
    this.focus();
  }

  focus(options?: FocusOptions): void {
    this.compactInput().nativeElement.focus(options);
  }
}
