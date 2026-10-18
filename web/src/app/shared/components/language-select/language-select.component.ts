import { Component, inject } from '@angular/core';
import { LANGUAGES, LANGUAGE_NAMES } from '../../../core/i18n/catalog';
import { I18nService, isLanguage } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** Picker of the language of the web interface (English, French, Spanish). */
@Component({
  selector: 'app-language-select',
  imports: [TranslatePipe],
  templateUrl: './language-select.component.html',
  styleUrl: './language-select.component.css',
})
export class LanguageSelectComponent {
  readonly i18n = inject(I18nService);
  readonly languages = LANGUAGES;
  readonly names = LANGUAGE_NAMES;

  onChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    if (isLanguage(value)) {
      this.i18n.setLanguage(value);
    }
  }
}
