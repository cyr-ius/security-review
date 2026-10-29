import { Component, DestroyRef, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { HealthService } from '../../core/services/health.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/** Delay before the first automatic retry, doubled after each failure up to the maximum. */
const FIRST_RETRY_SECONDS = 5;
const MAX_RETRY_SECONDS = 60;

/**
 * Page shown while the controller does not answer (at load, or when a request finds no
 * backend). It checks again on its own, with a growing delay, or when the user retries, and goes
 * back to the requested page once the controller answers.
 */
@Component({
  selector: 'app-backend-unavailable',
  imports: [RefreshButtonComponent, TranslatePipe],
  templateUrl: './backend-unavailable.component.html',
  styleUrl: './backend-unavailable.component.css',
})
export class BackendUnavailableComponent {
  private readonly health = inject(HealthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly checking = signal(false);
  /** The last retry found no backend either. */
  readonly stillDown = signal(false);
  /** Seconds before the next automatic retry. */
  readonly secondsLeft = signal(FIRST_RETRY_SECONDS);

  private delay = FIRST_RETRY_SECONDS;
  private readonly ticker = setInterval(() => this.tick(), 1000);

  constructor() {
    inject(DestroyRef).onDestroy(() => clearInterval(this.ticker));
  }

  async retry(): Promise<void> {
    if (this.checking()) {
      return;
    }
    this.checking.set(true);
    try {
      if (await this.health.check(true)) {
        clearInterval(this.ticker);
        await this.router.navigateByUrl(this.returnUrl());
        return;
      }
      this.stillDown.set(true);
      this.delay = Math.min(this.delay * 2, MAX_RETRY_SECONDS);
      this.secondsLeft.set(this.delay);
    } finally {
      this.checking.set(false);
    }
  }

  private tick(): void {
    // Paused while a check runs or the tab is hidden
    if (this.checking() || document.hidden) {
      return;
    }
    const left = this.secondsLeft() - 1;
    if (left <= 0) {
      void this.retry();
    } else {
      this.secondsLeft.set(left);
    }
  }

  /** Requested page, local paths only (no open redirect). */
  private returnUrl(): string {
    const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';
    const local = returnUrl.startsWith('/') && !returnUrl.startsWith('//');
    return local && !returnUrl.startsWith('/unavailable') ? returnUrl : '/';
  }
}
