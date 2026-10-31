import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { rxResource, toSignal } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter, firstValueFrom, map } from 'rxjs';
import { ROLE_META } from '../core/constants/labels';
import { I18nService } from '../core/i18n/i18n.service';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { MessageKey } from '../core/i18n/messages';
import { Permission } from '../core/models/api.models';
import { ApiService } from '../core/services/api.service';
import { AuthService } from '../core/services/auth.service';
import { ControllerUrlService } from '../core/services/controller-url.service';
import { ThemeService } from '../core/services/theme.service';
import { LanguageSelectComponent } from '../shared/components/language-select/language-select.component';
import { ThemeButtonComponent } from '../shared/components/theme-button/theme-button.component';
import { describeGrants } from '../shared/utils/permission-utils';
import { SessionExpiredComponent } from './session-expired/session-expired.component';

/** Below Bootstrap's lg breakpoint the sidebar is a rail of icons. */
const NARROW_QUERY = '(max-width: 991.98px)';
const COLLAPSED_KEY = 'secreview.sidebarCollapsed';

function storedCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === 'true';
  } catch {
    return false;
  }
}

/** One entry of the sidebar. */
interface NavItem {
  path: string;
  label: MessageKey;
  icon: string;
  /** Shown only to the users that hold it (the route has the same permission guard). */
  permission?: Permission;
}

/** Application shell: sidebar navigation, top bar and the routed page. */
@Component({
  selector: 'app-layout',
  imports: [
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    TranslatePipe,
    LanguageSelectComponent,
    SessionExpiredComponent,
    ThemeButtonComponent,
  ],
  templateUrl: './layout.component.html',
  styleUrl: './layout.component.css',
  // Escape closes the menu, wherever the focus is
  host: { '(document:keydown.escape)': 'onEscape()' },
})
export class LayoutComponent {
  readonly auth = inject(AuthService);
  private readonly api = inject(ApiService);
  readonly theme = inject(ThemeService);
  readonly controllerUrl = inject(ControllerUrlService);
  private readonly router = inject(Router);
  private readonly i18n = inject(I18nService);

  readonly mainNav: readonly NavItem[] = [
    { path: '/projects', label: 'layout.projects', icon: 'bi-grid-1x2' },
    { path: '/reports', label: 'layout.reports', icon: 'bi-file-earmark-text' },
  ];

  /** Review of the findings, in the projects whose reports the user reads. */
  private readonly reviewItems: readonly NavItem[] = [
    {
      path: '/findings',
      label: 'layout.findings',
      icon: 'bi-shield-check',
      permission: 'reports.read',
    },
    {
      path: '/risk-acceptances',
      label: 'acceptances.title',
      icon: 'bi-shield-exclamation',
      permission: 'reports.read',
    },
  ];

  /** What the reviews rely on: scan rules, checklists and development standards. */
  private readonly referenceItems: readonly NavItem[] = [
    { path: '/rules', label: 'layout.rules', icon: 'bi-sliders', permission: 'rules.read' },
    { path: '/opengrep-rules', label: 'layout.opengrepRules', icon: 'bi-filetype-yml', permission: 'rules.read' },
    {
      path: '/checklists',
      label: 'layout.checklists',
      icon: 'bi-list-check',
      permission: 'rules.read',
    },
    {
      path: '/standards',
      label: 'layout.standards',
      icon: 'bi-journal-code',
      permission: 'standards.read',
    },
  ];

  private readonly adminItems: readonly NavItem[] = [
    {
      path: '/settings/general',
      label: 'layout.general',
      icon: 'bi-sliders',
      permission: 'settings.manage',
    },
    { path: '/users', label: 'layout.users', icon: 'bi-people', permission: 'users.manage' },
    { path: '/roles', label: 'layout.roles', icon: 'bi-shield-check', permission: 'users.manage' },
    { path: '/tokens', label: 'layout.tokens', icon: 'bi-key', permission: 'tokens.manage' },
    { path: '/sso', label: 'layout.sso', icon: 'bi-person-badge', permission: 'users.manage' },
    {
      path: '/settings/advisories',
      label: 'layout.advisories',
      icon: 'bi-database',
      permission: 'settings.manage',
    },
    {
      path: '/settings/connectors',
      label: 'connectors.title',
      icon: 'bi-plug',
      permission: 'settings.manage',
    },
    { path: '/audit', label: 'layout.audit', icon: 'bi-journal-text', permission: 'audit.read' },
  ];

  /** Sidebar opened in full over the page (small screens, or after the expand button). */
  readonly menuOpen = signal(false);

  /** Large screens: the user reduced the sidebar to its icons (remembered by the browser). */
  readonly collapsed = signal(storedCollapsed());

  /** Small screen: the sidebar is reduced to its icons unless opened. */
  readonly narrow = signal(false);

  /** Sidebar shown as a rail of icons. */
  readonly rail = computed(() => !this.menuOpen() && (this.narrow() || this.collapsed()));

  /** Entries of the Revue section the current user may open. */
  readonly reviewNav = computed(() => this.allowed(this.reviewItems));

  /** Counts the navigations, so that the badges follow the triage done on the pages. */
  private readonly navigations = toSignal(
    this.router.events.pipe(
      filter((event) => event instanceof NavigationEnd),
      map((_, index) => index),
    ),
    { initialValue: -1 },
  );

  /** Open findings in the scope of the user, shown on the Findings entry (one row loaded). */
  private readonly openFindings = rxResource({
    params: () => (this.auth.can('reports.read') ? { navigation: this.navigations() } : undefined),
    stream: () =>
      this.api.projectFindings({ status: [], severity: [], reviewType: [], limit: 1, offset: 0 }),
  });

  /** Number shown next to an entry of the sidebar (null: no badge). */
  badge(item: NavItem): number | null {
    return item.path === '/findings' && this.openFindings.hasValue()
      ? this.openFindings.value().total
      : null;
  }

  /** Entries of the Référentiel section the current user may open. */
  readonly referenceNav = computed(() => this.allowed(this.referenceItems));

  /** Entries of the Administration section the current user may open. */
  readonly adminNav = computed(() => this.allowed(this.adminItems));

  readonly role = computed(() => ROLE_META[this.auth.identity()?.role ?? 'user']);
  /** Permissions of the caller, shown when hovering its role. */
  readonly permissions = computed(() =>
    describeGrants(this.auth.identity()?.permissions ?? {}, this.i18n).join('\n'),
  );

  /** Up to two initials of the client name, for the avatar. */
  readonly initials = computed(() => {
    const words = (this.auth.identity()?.client ?? '').split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2);
    return letters.toUpperCase();
  });

  constructor() {
    // The theme kept in the account of the user replaces the one of this browser
    void this.theme.load();
    try {
      const query = window.matchMedia(NARROW_QUERY);
      this.narrow.set(query.matches);
      const onChange = (event: MediaQueryListEvent) => {
        this.narrow.set(event.matches);
        this.menuOpen.set(false);
      };
      query.addEventListener('change', onChange);
      inject(DestroyRef).onDestroy(() => query.removeEventListener('change', onChange));
    } catch {
      // No media queries (tests): the large-screen layout applies
    }
  }

  /** Expand or reduce the sidebar: a drawer on small screens, remembered on large ones. */
  toggleSidebar(): void {
    if (this.narrow()) {
      this.menuOpen.update((open) => !open);
      return;
    }
    const collapsed = !this.collapsed();
    this.collapsed.set(collapsed);
    try {
      localStorage.setItem(COLLAPSED_KEY, String(collapsed));
    } catch {
      // Not remembered by the browser
    }
  }

  /** Items whose permission the current user holds. */
  private allowed(items: readonly NavItem[]): NavItem[] {
    return items.filter((item) => !item.permission || this.auth.can(item.permission));
  }

  closeMenu(): void {
    this.menuOpen.set(false);
  }

  onEscape(): void {
    this.closeMenu();
  }

  async logout(): Promise<void> {
    try {
      // Written to the audit log; the tab drops its session whatever the answer
      await firstValueFrom(this.api.logout());
    } catch {
      // Expired session or unreachable controller: nothing to record
    }
    this.auth.logout();
    await this.router.navigate(['/login']);
  }
}
