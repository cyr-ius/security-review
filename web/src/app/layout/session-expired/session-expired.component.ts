import { Component, ElementRef, effect, inject, viewChild } from '@angular/core';
import { Router } from '@angular/router';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AuthService } from '../../core/services/auth.service';

/**
 * Dialog shown when the controller no longer accepts the session (expired, revoked, password
 * changed elsewhere): the user logs in again and comes back to the same page.
 */
@Component({
  selector: 'app-session-expired',
  imports: [TranslatePipe],
  templateUrl: './session-expired.component.html',
  styleUrl: './session-expired.component.css',
})
export class SessionExpiredComponent {
  readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  private readonly button = viewChild<ElementRef<HTMLButtonElement>>('loginButton');

  constructor() {
    // Move the focus into the dialog when it opens (side effect on the DOM)
    effect(() => this.button()?.nativeElement.focus());
  }

  async loginAgain(): Promise<void> {
    const returnUrl = this.router.url;
    this.auth.acknowledgeExpiry();
    await this.router.navigate(['/login'], { queryParams: { returnUrl } });
  }
}
