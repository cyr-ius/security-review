import { Component, computed, inject, input } from '@angular/core';
import { DOCS_URL, DOC_LINKS, DocLink, DocTopic } from '../../../core/constants/doc-links';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/**
 * Circled question mark placed next to a title: it opens, in a new tab, the page of the
 * documentation explaining the screen, in French for a French interface, else in English.
 */
@Component({
  imports: [TranslatePipe],
  selector: 'app-help-link',
  template: `<a
    class="link-secondary"
    [href]="url()"
    target="_blank"
    rel="noopener noreferrer"
    [title]="'common.helpLink' | t"
    [attr.aria-label]="'common.helpLink' | t"
    ><i class="bi bi-question-circle" aria-hidden="true"></i
  ></a>`,
  styles: ':host { font-size: 0.85em; vertical-align: 0.1em; margin-inline-start: 0.35rem; }',
})
export class HelpLinkComponent {
  private readonly i18n = inject(I18nService);

  /** Subject of the documentation to open. */
  readonly topic = input.required<DocTopic>();

  readonly url = computed(() => {
    const link: DocLink = DOC_LINKS[this.topic()];
    const french = this.i18n.language() === 'fr';
    const anchor = link.anchor ? '#' + (french ? link.anchor.fr : link.anchor.en) : '';
    return DOCS_URL + (french ? 'fr/' : '') + link.path + anchor;
  });
}
