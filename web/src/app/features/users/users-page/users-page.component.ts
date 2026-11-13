import { Component, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';
import { DocTopic } from '../../../core/constants/doc-links';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';

/**
 * Users page: one title and subtitle, then the accounts, the roles and the OIDC sign-in, one
 * tab each (one route each, so that a tab can be linked to). All three need users.manage.
 */
@Component({
  selector: 'app-users-page',
  imports: [HelpLinkComponent, RouterLink, RouterLinkActive, RouterOutlet, TranslatePipe],
  templateUrl: './users-page.component.html',
})
export class UsersPageComponent {
  private readonly router = inject(Router);

  private readonly url = toSignal(
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd),
      map(() => this.router.url),
    ),
    { initialValue: this.router.url },
  );

  /** The help link opens the documentation of the open tab. */
  readonly helpTopic = computed<DocTopic>(() => {
    const url = this.url();
    if (url.startsWith('/users/roles')) return 'roles';
    if (url.startsWith('/users/sso')) return 'sso';
    return 'users';
  });
}
