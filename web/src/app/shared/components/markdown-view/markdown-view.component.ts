import { Component, ViewEncapsulation, computed, input } from '@angular/core';
import { renderMarkdown } from '../../utils/markdown';

/** Markdown text rendered as HTML (see renderMarkdown), for previews and read-only views. */
@Component({
  selector: 'app-markdown-view',
  template: '<div class="markdown-view" [innerHTML]="rendered().html"></div>',
  styleUrl: './markdown-view.component.css',
  // The styles reach the HTML inserted by [innerHTML]; they are scoped by class.
  encapsulation: ViewEncapsulation.None,
})
export class MarkdownViewComponent {
  readonly text = input.required<string>();
  readonly rendered = computed(() => renderMarkdown(this.text()));
}
