import { Injectable, effect, signal } from '@angular/core';
import { DEFAULT_LANGUAGE, LANGUAGES, Language } from './catalog';
import { MESSAGES, MessageKey } from './messages';

const LANGUAGE_KEY = 'secreview.language';

/** Parameters replacing the `{name}` placeholders of a message. */
export type MessageParams = Record<string, string | number>;

/**
 * A message to show later, with its parameters. Screens keep messages in this form (not as
 * text) so that a message already shown follows a change of language.
 */
export interface Message {
  key: MessageKey;
  params?: MessageParams;
}

/** Shorthand for a Message. */
export function msg(key: MessageKey, params?: MessageParams): Message {
  return { key, params };
}

/** An error detail sent by the server, shown as is (the API answers in English). */
export function serverDetail(detail: string): Message {
  return msg('common.serverDetail', { detail });
}

/**
 * Language of the web interface (English, French or Spanish), remembered per browser.
 *
 * The first visit follows the languages of the browser. translate reads the language signal,
 * so a template or a computed that calls it is refreshed when the language changes.
 */
@Injectable({ providedIn: 'root' })
export class I18nService {
  private readonly languageValue = signal<Language>(initialLanguage());
  readonly language = this.languageValue.asReadonly();

  constructor() {
    effect(() => {
      const language = this.languageValue();
      document.documentElement.setAttribute('lang', language);
      try {
        localStorage.setItem(LANGUAGE_KEY, language);
      } catch {
        // Preference not remembered
      }
    });
  }

  /** Switch the interface to ``language`` (remembered for the next visits). */
  setLanguage(language: Language): void {
    this.languageValue.set(language);
  }

  /** Text of a message key (or Message) in the current language, placeholders replaced. */
  translate(message: MessageKey | Message, params?: MessageParams): string {
    const key = typeof message === 'string' ? message : message.key;
    const values = typeof message === 'string' ? params : { ...message.params, ...params };
    const text = MESSAGES[this.language()][key] ?? MESSAGES[DEFAULT_LANGUAGE][key] ?? key;
    return values ? interpolate(text, values) : text;
  }
}

/** Replace each `{name}` of message by params[name] (unknown names are kept as is). */
export function interpolate(message: string, params: MessageParams): string {
  return message.replace(/\{(\w+)\}/g, (placeholder, name: string) =>
    name in params ? String(params[name]) : placeholder,
  );
}

/** Whether value is one of the languages of the interface. */
export function isLanguage(value: unknown): value is Language {
  return typeof value === 'string' && (LANGUAGES as readonly string[]).includes(value);
}

/** Stored choice, else the first browser language the interface offers, else English. */
function initialLanguage(): Language {
  try {
    const stored = localStorage.getItem(LANGUAGE_KEY);
    if (isLanguage(stored)) {
      return stored;
    }
  } catch {
    // Fall back on the browser languages
  }
  for (const tag of navigator.languages ?? [navigator.language]) {
    const primary = tag?.split('-')[0]?.toLowerCase();
    if (isLanguage(primary)) {
      return primary;
    }
  }
  return DEFAULT_LANGUAGE;
}
