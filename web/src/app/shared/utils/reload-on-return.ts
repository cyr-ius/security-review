import { DOCUMENT, DestroyRef, inject } from '@angular/core';

/**
 * Call `reload` each time the browser tab of the page becomes visible again, so that a page
 * that follows outside activity (reviews saved by agents or the CI, audit events...) shows it
 * without a click. `when` skips a reload that would lose what the user is doing, such as the
 * pages added by "load more". To call in an injection context (field or constructor).
 */
export function reloadOnReturn(reload: () => void, when: () => boolean = () => true): void {
  const document = inject(DOCUMENT);
  const listener = (): void => {
    if (document.visibilityState === 'visible' && when()) {
      reload();
    }
  };
  document.addEventListener('visibilitychange', listener);
  inject(DestroyRef).onDestroy(() => document.removeEventListener('visibilitychange', listener));
}
