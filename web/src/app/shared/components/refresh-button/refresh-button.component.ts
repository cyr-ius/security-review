import { Component, input, linkedSignal, output } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** Whether the user asked the system to minimize animations. */
const REDUCED_MOTION =
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * Outline button that reloads a page. Its icon turns while `loading` is true and always ends
 * on a full turn, so that a fast reload still shows a smooth rotation instead of a jolt.
 */
@Component({
  imports: [TranslatePipe],
  selector: 'app-refresh-button',
  templateUrl: './refresh-button.component.html',
  styleUrl: './refresh-button.component.css',
})
export class RefreshButtonComponent {
  /** True while the data shown by the page is being fetched. */
  readonly loading = input(false);
  /** Text of the button (default: the translation of "Refresh"). */
  readonly label = input<string>();
  readonly refresh = output<void>();

  /**
   * True while the icon turns: it starts with the loading and stops at the end of a turn
   * (onTurnEnd), or at once without animations.
   */
  readonly spinning = linkedSignal<boolean, boolean>({
    source: this.loading,
    computation: (loading, previous) => loading || (!REDUCED_MOTION && (previous?.value ?? false)),
  });

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
