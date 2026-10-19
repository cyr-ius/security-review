import { Component, computed, linkedSignal } from '@angular/core';
import { FormField, form, validate } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from '../settings-page';

/** How the report language is chosen in the form (without SECREVIEW_REPORT_LANGUAGE). */
type LanguageMode = 'agent' | 'custom';

/** Same rule as the server: a language name or code, nothing that could carry instructions. */
const LANGUAGE_PATTERN = /^[\p{L} \-_()]{0,40}$/u;

/** Fields of the report language form. */
interface LanguageFormModel {
  mode: LanguageMode;
  language: string;
}

/**
 * Administrator page: language of the review reports. SECREVIEW_REPORT_LANGUAGE, when set, takes
 * precedence: the page then only shows it.
 */
@Component({
  selector: 'app-language-settings',
  imports: [FormField, RefreshButtonComponent, TranslatePipe],
  templateUrl: './language-settings.component.html',
  styleUrl: '../settings.css',
})
export class LanguageSettingsComponent extends SettingsPage {
  /** Filled with the stored value each time it is loaded, then edited by the form. */
  readonly languageModel = linkedSignal<LanguageFormModel>(() => {
    const stored = this.settings.value()?.report_language.value;
    return { mode: stored ? 'custom' : 'agent', language: stored ?? '' };
  });
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

  async saveLanguage(event: Event): Promise<void> {
    event.preventDefault();
    const { mode, language } = this.languageModel();
    const value = mode === 'agent' ? null : language.trim();
    if (mode === 'custom' && (!value || !this.languageValid())) {
      this.error.set(msg('settings.languageMissing'));
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(value)),
      msg('settings.languageSaved'),
    );
  }

  /** Delete the stored value that SECREVIEW_REPORT_LANGUAGE hides. */
  async deleteStored(): Promise<void> {
    await this.run(
      () => firstValueFrom(this.api.setReportLanguage(null)),
      msg('settings.storedDeleted'),
    );
  }
}
