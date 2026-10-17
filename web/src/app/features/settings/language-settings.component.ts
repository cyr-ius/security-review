import { Component, computed, effect, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';
import { SettingsPage } from './settings-page';

/** How the report language is chosen in the form. */
type LanguageMode = 'inherit' | 'agent' | 'custom';

/** Same rule as the server: a language name or code, nothing that could carry instructions. */
const LANGUAGE_PATTERN = /^[\p{L} \-_()]{0,40}$/u;

/** Administrator page: language of the review reports (overrides SECREVIEW_REPORT_LANGUAGE). */
@Component({
  selector: 'app-language-settings',
  imports: [RefreshButtonComponent, TranslatePipe],
  templateUrl: './language-settings.component.html',
  styleUrl: './settings.css',
})
export class LanguageSettingsComponent extends SettingsPage {
  readonly languageMode = signal<LanguageMode>('inherit');
  readonly language = signal('');

  readonly languageSuggestions = [
    'French',
    'English',
    'German',
    'Spanish',
    'Italian',
    'Portuguese',
  ];

  readonly languageValid = computed(
    () => this.languageMode() !== 'custom' || LANGUAGE_PATTERN.test(this.language().trim()),
  );

  constructor() {
    super();
    // Fill the form with the stored value each time it is loaded
    effect(() => {
      const value = this.settings.value();
      if (!value) {
        return;
      }
      const stored = value.report_language.value;
      this.languageMode.set(stored === null ? 'inherit' : stored === '' ? 'agent' : 'custom');
      this.language.set(stored ?? '');
    });
  }

  onLanguageMode(event: Event): void {
    this.languageMode.set((event.target as HTMLSelectElement).value as LanguageMode);
  }

  async saveLanguage(event: Event): Promise<void> {
    event.preventDefault();
    const mode = this.languageMode();
    const value = mode === 'inherit' ? null : mode === 'agent' ? '' : this.language().trim();
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
