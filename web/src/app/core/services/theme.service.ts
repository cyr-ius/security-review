import { Injectable, computed, effect, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ThemeChoice } from '../models/api.models';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';

/** Theme applied to the page (Bootstrap color mode). */
export type Theme = 'light' | 'dark';

const THEME_KEY = 'secreview.theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';
/** Order of the theme button: each click moves to the next choice. */
const CYCLE: readonly ThemeChoice[] = ['auto', 'light', 'dark'];

/**
 * Light, dark or automatic theme (Bootstrap color modes).
 *
 * The choice of a logged-in user is kept in its account (GET and PUT /api/v1/me/preferences),
 * for every browser it uses; the browser also remembers the last one, so that the login page
 * and the first render use it. Automatic follows the system preference, live.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);

  private readonly choiceValue = signal<ThemeChoice>(storedChoice());
  /** What the user chose. */
  readonly choice = this.choiceValue.asReadonly();

  private readonly systemDark = signal(prefersDark());

  /** Theme applied to the page. */
  readonly theme = computed<Theme>(() => {
    const choice = this.choiceValue();
    if (choice === 'auto') {
      return this.systemDark() ? 'dark' : 'light';
    }
    return choice;
  });

  /** Choice the theme button moves to. */
  readonly nextChoice = computed(
    () => CYCLE[(CYCLE.indexOf(this.choiceValue()) + 1) % CYCLE.length],
  );

  constructor() {
    try {
      window
        .matchMedia(DARK_QUERY)
        .addEventListener('change', (event) => this.systemDark.set(event.matches));
    } catch {
      // No media queries (tests): the light theme applies to "auto"
    }
    effect(() => {
      document.documentElement.setAttribute('data-bs-theme', this.theme());
    });
    effect(() => {
      const choice = this.choiceValue();
      try {
        localStorage.setItem(THEME_KEY, choice);
      } catch {
        // Preference not remembered by the browser
      }
    });
  }

  /** Apply the theme kept in the account of the logged-in user. */
  async load(): Promise<void> {
    try {
      const preferences = await firstValueFrom(this.api.preferences());
      this.choiceValue.set(preferences.theme);
    } catch {
      // Bearer token or older controller: the choice of this browser stays
    }
  }

  /** Apply ``choice`` and keep it in the account of the logged-in user. */
  async choose(choice: ThemeChoice): Promise<void> {
    this.choiceValue.set(choice);
    if (!this.auth.identity()?.auth_source) {
      return; // Login page or bearer token: only this browser remembers it
    }
    try {
      await firstValueFrom(this.api.setPreferences({ theme: choice }));
    } catch {
      // Kept by this browser only
    }
  }

  /** Move to the next choice (automatic, light, dark). */
  cycle(): Promise<void> {
    return this.choose(this.nextChoice());
  }
}

function storedChoice(): ThemeChoice {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === 'light' || stored === 'dark' || stored === 'auto') {
      return stored;
    }
  } catch {
    // Fall back on the system preference
  }
  return 'auto';
}

function prefersDark(): boolean {
  try {
    return window.matchMedia(DARK_QUERY).matches;
  } catch {
    return false;
  }
}
