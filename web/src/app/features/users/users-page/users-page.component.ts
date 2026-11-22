import { Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';
import { DocTopic } from '../../../core/constants/doc-links';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';

/** A tab that can be refreshed from the button of the page header. */
export interface RefreshableTab {
  readonly refreshing: () => boolean;
  refresh(): void;
}

function isRefreshable(component: object): component is RefreshableTab {
  return 'refresh' in component && 'refreshing' in component;
}

/**
 * Users page: one title and subtitle, then the accounts, the roles and the OIDC sign-in, one
 * tab each (one route each, so that a tab can be linked to). All three need users.manage.
 */
@Component({
  selector: 'app-users-page',
  imports: [
    HelpLinkComponent,
    RefreshButtonComponent,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
    TranslatePipe,
  ],
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

  /** Open tab, when it can be refreshed: the button sits in the header, as on the other pages. */
  readonly refreshable = signal<RefreshableTab | null>(null);

  onActivate(component: object): void {
    this.refreshable.set(isRefreshable(component) ? component : null);
  }

  /** The help link opens the documentation of the open tab. */
  readonly helpTopic = computed<DocTopic>(() => {
    const url = this.url();
    if (url.startsWith('/users/roles')) return 'roles';
    if (url.startsWith('/users/sso')) return 'sso';
    return 'users';
  });
}
