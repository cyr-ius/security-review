import { Component, computed, effect, signal } from '@angular/core';
import { FormField, form, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from '../settings-page';

/** How the report language is chosen in the form. */
type LanguageMode = 'inherit' | 'agent' | 'custom';

/** Same rule as the server: a language name or code, nothing that could carry instructions. */
const LANGUAGE_PATTERN = /^[\p{L} \-_()]{0,40}$/u;

/** Fields of the report language form. */
interface LanguageFormModel {
  mode: LanguageMode;
  language: string;
}

/** Administrator page: language of the review reports (overrides SECREVIEW_REPORT_LANGUAGE). */
@Component({
  selector: 'app-language-settings',
  imports: [FormField, RefreshButtonComponent, TranslatePipe],
  templateUrl: './language-settings.component.html',
  styleUrl: '../settings.css',
})
export class LanguageSettingsComponent extends SettingsPage {
  readonly languageModel = signal<LanguageFormModel>({ mode: 'inherit', language: '' });
  readonly languageForm = form(this.languageModel, (path) => {
    validate(path.language, ({ value, valueOf }) =>
      valueOf(path.mode) === 'custom' && !LANGUAGE_PATTERN.test(value().trim())
        ? { kind: 'pattern', message: this.i18n.translate('settings.languagePattern') }
        : undefined,
    );
  });
  readonly languageMode = computed(() => this.languageModel().mode);

  readonly languageSuggestions = [
    'French',
    'English',
    'German',
    'Spanish',
    'Italian',
    'Portuguese',
  ];

  readonly languageValid = computed(() => this.languageForm().valid());

  constructor() {
    super();
    // Fill the form with the stored value each time it is loaded
    effect(() => {
      const value = this.settings.value();
      if (!value) {
        return;
      }
      const stored = value.report_language.value;
      this.languageForm().reset({
        mode: stored === null ? 'inherit' : stored === '' ? 'agent' : 'custom',
        language: stored ?? '',
      });
    });
  }

  async saveLanguage(event: Event): Promise<void> {
    event.preventDefault();
    const { mode, language } = this.languageModel();
    const value = mode === 'inherit' ? null : mode === 'agent' ? '' : language.trim();
    if (mode === 'custom' && (!value || !this.languageValid())) {
      this.error.set(msg('settings.languageMissing'));
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(value)),
      msg('settings.languageSaved'),
    );
  }
}
