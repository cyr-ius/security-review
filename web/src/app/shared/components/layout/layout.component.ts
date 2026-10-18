import { Component, HostListener, computed, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { ROLE_META } from '../../../core/constants/labels';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { MessageKey } from '../../../core/i18n/messages';
import { Permission } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';
import { ThemeService } from '../../../core/services/theme.service';
import { LanguageSelectComponent } from '../language-select/language-select.component';

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
  imports: [RouterOutlet, RouterLink, RouterLinkActive, TranslatePipe, LanguageSelectComponent],
  templateUrl: './layout.component.html',
  styleUrl: './layout.component.css',
})
export class LayoutComponent {
  readonly auth = inject(AuthService);
  private readonly api = inject(ApiService);
  readonly theme = inject(ThemeService);
  private readonly router = inject(Router);

  readonly mainNav: readonly NavItem[] = [
    { path: '/projects', label: 'layout.projects', icon: 'bi-grid-1x2' },
    { path: '/reports', label: 'layout.reports', icon: 'bi-file-earmark-text' },
  ];

  /** What the reviews rely on: scan rules, checklists and development standards. */
  private readonly referenceItems: readonly NavItem[] = [
    { path: '/rules', label: 'layout.rules', icon: 'bi-sliders', permission: 'rules.manage' },
    {
      path: '/checklists',
      label: 'layout.checklists',
      icon: 'bi-list-check',
      permission: 'rules.manage',
    },
    {
      path: '/standards',
      label: 'layout.standards',
      icon: 'bi-journal-code',
      permission: 'standards.manage',
    },
  ];

  private readonly adminItems: readonly NavItem[] = [
    { path: '/users', label: 'layout.users', icon: 'bi-people', permission: 'users.manage' },
    { path: '/groups', label: 'layout.groups', icon: 'bi-diagram-3', permission: 'users.manage' },
    { path: '/roles', label: 'layout.roles', icon: 'bi-shield-check', permission: 'users.manage' },
    { path: '/tokens', label: 'layout.tokens', icon: 'bi-key', permission: 'tokens.manage' },
    { path: '/audit', label: 'layout.audit', icon: 'bi-journal-text', permission: 'audit.read' },
    { path: '/sso', label: 'layout.sso', icon: 'bi-person-badge', permission: 'users.manage' },
    {
      path: '/settings/language',
      label: 'layout.reportLanguage',
      icon: 'bi-translate',
      permission: 'settings.manage',
    },
    {
      path: '/settings/proxy',
      label: 'layout.proxy',
      icon: 'bi-hdd-network',
      permission: 'settings.manage',
    },
    {
      path: '/settings/advisories',
      label: 'layout.advisories',
      icon: 'bi-database',
      permission: 'settings.manage',
    },
  ];

  /** Sidebar shown as a drawer on small screens. */
  readonly menuOpen = signal(false);

  /** Entries of the Référentiel section the current user may open. */
  readonly referenceNav = computed(() => this.allowed(this.referenceItems));

  /** Entries of the Administration section the current user may open. */
  readonly adminNav = computed(() => this.allowed(this.adminItems));

  readonly role = computed(() => ROLE_META[this.auth.identity()?.role ?? 'reader']);

  /** Up to two initials of the client name, for the avatar. */
  readonly initials = computed(() => {
    const words = (this.auth.identity()?.client ?? '').split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2);
    return letters.toUpperCase();
  });

  /** Items whose permission the current user holds. */
  private allowed(items: readonly NavItem[]): NavItem[] {
    return items.filter((item) => !item.permission || this.auth.can(item.permission));
  }

  closeMenu(): void {
    this.menuOpen.set(false);
  }

  @HostListener('document:keydown.escape')
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
