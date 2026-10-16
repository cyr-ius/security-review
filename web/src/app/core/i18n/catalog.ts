/** Languages of the web interface. */
export const LANGUAGES = ['en', 'fr', 'es'] as const;

export type Language = (typeof LANGUAGES)[number];

/** Language used when the browser asks for none of LANGUAGES. */
export const DEFAULT_LANGUAGE: Language = 'en';

/** Name of each language, written in that language (shown in the language picker). */
export const LANGUAGE_NAMES: Record<Language, string> = {
  en: 'English',
  fr: 'Français',
  es: 'Español',
};

/** Messages of one screen in every language, keyed by message key. */
export interface Catalog<K extends string> {
  en: Record<K, string>;
  fr: Record<NoInfer<K>, string>;
  es: Record<NoInfer<K>, string>;
}

/**
 * Declare the messages of one screen. The keys come from the English messages: a key missing
 * from (or unknown to) the French or Spanish messages is a compile error.
 *
 * A message may hold `{name}` placeholders, replaced by the parameters given to translate.
 */
export function defineMessages<K extends string>(catalog: Catalog<K>): Catalog<K> {
  return catalog;
}
