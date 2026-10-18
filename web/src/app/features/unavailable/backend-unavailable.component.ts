import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { HealthService } from '../../core/services/health.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/**
 * Page shown while the controller does not answer (at load, or when a request finds no
 * backend). Retry checks it again and goes back to the requested page.
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

  async retry(): Promise<void> {
    this.checking.set(true);
    try {
      if (await this.health.check(true)) {
        await this.router.navigateByUrl(this.returnUrl());
      } else {
        this.stillDown.set(true);
      }
    } finally {
      this.checking.set(false);
    }
  }

  /** Requested page, local paths only (no open redirect). */
  private returnUrl(): string {
    const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';
    const local = returnUrl.startsWith('/') && !returnUrl.startsWith('//');
    return local && !returnUrl.startsWith('/unavailable') ? returnUrl : '/';
  }
}
