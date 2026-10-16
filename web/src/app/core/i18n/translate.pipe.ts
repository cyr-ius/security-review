import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService, Message, MessageParams } from './i18n.service';
import { MessageKey } from './messages';

/**
 * Translate a message key in a template: `{{ 'layout.projects' | t }}`, with parameters
 * `{{ 'tokens.created' | t: { label: name } }}`, or a Message kept by the component.
 *
 * Impure so that it runs again when the language changes (the key and parameters do not).
 */
@Pipe({ name: 't', pure: false })
export class TranslatePipe implements PipeTransform {
  private readonly i18n = inject(I18nService);

  transform(message: MessageKey | Message, params?: MessageParams): string {
    return this.i18n.translate(message, params);
  }
}
