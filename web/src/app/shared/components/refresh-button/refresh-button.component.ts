import { Component, input, linkedSignal, output } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/**
 * Outline button that reloads a page. Its icon turns while `loading` is true and always ends
 * on a full turn, so that a fast reload still shows a smooth rotation instead of a jolt. The
 * rotation is only slowed down when the system asks for reduced motion.
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
   * (onTurnEnd).
   */
  readonly spinning = linkedSignal<boolean, boolean>({
    source: this.loading,
    computation: (loading, previous) => loading || (previous?.value ?? false),
  });

  /** Start the rotation at once and ask the page to reload. */
  onClick(): void {
    this.spinning.set(true);
    this.refresh.emit();
  }

  /** At the end of each turn, stop if the loading is over. */
  onTurnEnd(): void {
    if (!this.loading()) {
      this.spinning.set(false);
    }
  }
}
