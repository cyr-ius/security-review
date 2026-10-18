import { Injectable, effect, signal } from '@angular/core';

type Theme = 'light' | 'dark';

const THEME_KEY = 'secreview.theme';

/** Light / dark theme (Bootstrap color modes), remembered per browser. */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly themeValue = signal<Theme>(initialTheme());
  readonly theme = this.themeValue.asReadonly();

  constructor() {
    effect(() => {
      const theme = this.themeValue();
      document.documentElement.setAttribute('data-bs-theme', theme);
      try {
        localStorage.setItem(THEME_KEY, theme);
      } catch {
        // Preference not remembered
      }
    });
  }

  toggle(): void {
    this.themeValue.update((theme) => (theme === 'dark' ? 'light' : 'dark'));
  }
}

function initialTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
  } catch {
    // Fall back on the system preference
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
