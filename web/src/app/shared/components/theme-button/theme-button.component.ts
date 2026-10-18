import { Component, computed, inject } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { MessageKey } from '../../../core/i18n/messages';
import { ThemeChoice } from '../../../core/models/api.models';
import { ThemeService } from '../../../core/services/theme.service';

/** Icon and label of each theme choice. */
const CHOICES: Record<ThemeChoice, { icon: string; label: MessageKey }> = {
  auto: { icon: 'bi-circle-half', label: 'theme.auto' },
  light: { icon: 'bi-sun', label: 'theme.light' },
  dark: { icon: 'bi-moon-stars', label: 'theme.dark' },
};

/** Button of the theme: each click moves to the next choice (automatic, light, dark). */
@Component({
  selector: 'app-theme-button',
  imports: [TranslatePipe],
  templateUrl: './theme-button.component.html',
})
export class ThemeButtonComponent {
  readonly theme = inject(ThemeService);

  readonly current = computed(() => CHOICES[this.theme.choice()]);
  readonly next = computed(() => CHOICES[this.theme.nextChoice()]);

  onClick(): void {
    void this.theme.cycle();
  }
}
