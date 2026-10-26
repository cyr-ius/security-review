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
import { mapScroll, textOffsetTops } from '../../utils/scroll-sync';
import { MarkdownViewComponent } from '../markdown-view/markdown-view.component';

export type MarkdownFieldMode = 'edit' | 'split' | 'preview';

type MarkdownPane = 'text' | 'preview';

/** Positions of the Markdown blocks in both panes, valid for one text and one layout. */
interface PaneAnchors {
  key: string;
  text: number[];
  preview: number[];
}

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
  private readonly textPane = viewChild<ElementRef<HTMLTextAreaElement>>('textPane');
  private readonly previewPane = viewChild<ElementRef<HTMLElement>>('previewPane');
  private readonly previewView = viewChild(MarkdownViewComponent);
  private anchors: PaneAnchors | null = null;
  /** Pane scrolled by the code: its next scroll event is not synchronized back. */
  private scrolledByCode: MarkdownPane | null = null;

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

  /** Side by side, scroll the other pane so that it shows the same Markdown block. */
  onPaneScroll(pane: MarkdownPane): void {
    if (this.scrolledByCode === pane) {
      this.scrolledByCode = null;
      return;
    }
    const text = this.textPane()?.nativeElement;
    const preview = this.previewPane()?.nativeElement;
    const view = this.previewView();
    if (this.mode() !== 'split' || !text || !preview || !view) {
      return;
    }
    const anchors = this.paneAnchors(text, preview, view.rendered().offsets);
    const [target, other]: [HTMLElement, MarkdownPane] =
      pane === 'text' ? [preview, 'preview'] : [text, 'text'];
    const top =
      pane === 'text'
        ? mapScroll(text.scrollTop, anchors.text, anchors.preview, text, preview)
        : mapScroll(preview.scrollTop, anchors.preview, anchors.text, preview, text);
    // Without a change of position, the browser sends no scroll event to skip.
    if (Math.abs(target.scrollTop - top) >= 1) {
      this.scrolledByCode = other;
      target.scrollTop = top;
    }
  }

  /** Measured again when the text or the width of a pane changes. */
  private paneAnchors(
    text: HTMLTextAreaElement,
    preview: HTMLElement,
    offsets: readonly number[],
  ): PaneAnchors {
    const key = `${text.clientWidth}:${preview.clientWidth}:${text.value}`;
    if (this.anchors?.key !== key) {
      const blocks = preview.querySelectorAll<HTMLElement>('.markdown-view > div');
      this.anchors = {
        key,
        text: textOffsetTops(text, offsets),
        preview: Array.from(blocks, (block) => block.offsetTop),
      };
    }
    return this.anchors;
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
