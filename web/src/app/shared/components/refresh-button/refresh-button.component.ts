import { Component, effect, input, output, signal, untracked } from '@angular/core';

/** Whether the user asked the system to minimize animations. */
const REDUCED_MOTION =
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * Outline button that reloads a page. Its icon turns while `loading` is true and always ends
 * on a full turn, so that a fast reload still shows a smooth rotation instead of a jolt.
 */
@Component({
  selector: 'app-refresh-button',
  templateUrl: './refresh-button.component.html',
  styleUrl: './refresh-button.component.css',
})
export class RefreshButtonComponent {
  /** True while the data shown by the page is being fetched. */
  readonly loading = input(false);
  readonly label = input('Actualiser');
  readonly refresh = output<void>();

  /** True while the icon turns: it starts with the loading and stops at the end of a turn. */
  readonly spinning = signal(false);

  constructor() {
    effect(() => {
      const loading = this.loading();
      untracked(() => {
        if (loading) {
          this.spinning.set(true);
        } else if (REDUCED_MOTION) {
          // No animation, hence no end of turn to wait for
          this.spinning.set(false);
        }
      });
    });
  }

  /** Start the rotation at once and ask the page to reload. */
  onClick(): void {
    if (!REDUCED_MOTION) {
      this.spinning.set(true);
    }
    this.refresh.emit();
  }

  /** At the end of each turn, stop if the loading is over. */
  onTurnEnd(): void {
    if (!this.loading()) {
      this.spinning.set(false);
    }
  }
}
