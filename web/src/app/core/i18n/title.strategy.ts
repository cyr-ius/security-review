import { Injectable, effect, inject, signal } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { RouterStateSnapshot, TitleStrategy } from '@angular/router';
import { I18nService } from './i18n.service';
import { MessageKey } from './messages';

const APP_NAME = 'Security Review';

/**
 * Page title of the routes: their `title` is a message key, translated in the current language
 * and written again when the language changes.
 */
@Injectable({ providedIn: 'root' })
export class I18nTitleStrategy extends TitleStrategy {
  private readonly title = inject(Title);
  private readonly i18n = inject(I18nService);
  private readonly key = signal<MessageKey | null>(null);

  constructor() {
    super();
    effect(() => {
      const key = this.key();
      this.title.setTitle(key ? `${this.i18n.translate(key)} · ${APP_NAME}` : APP_NAME);
    });
  }

  override updateTitle(snapshot: RouterStateSnapshot): void {
    this.key.set((this.buildTitle(snapshot) as MessageKey | undefined) ?? null);
  }
}
