import { Component, computed, inject } from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';
import { DocTopic } from '../../../core/constants/doc-links';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';

/**
 * Rules page: one title and subtitle, then the pattern rules and the OpenGrep rules, one tab
 * each (one route each, so that a tab can be linked to).
 */
@Component({
  selector: 'app-rules-page',
  imports: [HelpLinkComponent, RouterLink, RouterLinkActive, RouterOutlet, TranslatePipe],
  templateUrl: './rules-page.component.html',
})
export class RulesPageComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  private readonly url = toSignal(
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd),
      map(() => this.router.url),
    ),
    { initialValue: this.router.url },
  );

  /** The help link opens the documentation of the open tab. */
  readonly helpTopic = computed<DocTopic>(() =>
    this.url().startsWith('/rules/opengrep') ? 'opengrepRules' : 'rules',
  );

  /** OpenGrep rules proposed by agents and waiting for a decision (only rules.manage decides). */
  readonly pendingProposals = rxResource({
    params: () => this.auth.can('rules.manage') || undefined,
    stream: () => this.api.opengrepProposals(),
  });
}
