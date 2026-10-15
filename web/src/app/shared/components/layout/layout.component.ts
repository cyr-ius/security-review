import { Component, HostListener, computed, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ROLE_META } from '../../../core/constants/labels';
import { AuthService } from '../../../core/services/auth.service';
import { ThemeService } from '../../../core/services/theme.service';

/** One entry of the sidebar. */
interface NavItem {
  path: string;
  label: string;
  icon: string;
  /** Shown to administrators only (the route has the admin guard). */
  adminOnly?: boolean;
}

/** Application shell: sidebar navigation, top bar and the routed page. */
@Component({
  selector: 'app-layout',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './layout.component.html',
  styleUrl: './layout.component.css',
})
export class LayoutComponent {
  readonly auth = inject(AuthService);
  readonly theme = inject(ThemeService);
  private readonly router = inject(Router);

  readonly mainNav: readonly NavItem[] = [
    { path: '/projects', label: 'Projets', icon: 'bi-grid-1x2' },
    { path: '/reports', label: 'Rapports', icon: 'bi-file-earmark-text' },
  ];

  /** What the reviews rely on: scan rules, checklists and development standards. */
  private readonly referenceItems: readonly NavItem[] = [
    { path: '/rules', label: 'Règles', icon: 'bi-sliders', adminOnly: true },
    { path: '/checklists', label: 'Checklists', icon: 'bi-list-check', adminOnly: true },
    { path: '/standards', label: 'Normes', icon: 'bi-journal-code', adminOnly: true },
  ];

  readonly adminNav: readonly NavItem[] = [
    { path: '/users', label: 'Utilisateurs', icon: 'bi-people' },
    { path: '/tokens', label: 'Jetons', icon: 'bi-key' },
    { path: '/role-mappings', label: 'Rôles SSO', icon: 'bi-person-badge' },
    { path: '/settings', label: 'Paramètres', icon: 'bi-gear' },
  ];

  /** Sidebar shown as a drawer on small screens. */
  readonly menuOpen = signal(false);

  readonly isAdmin = computed(() => this.auth.identity()?.role === 'admin');

  /** Entries of the Référentiel section the current user may open. */
  readonly referenceNav = computed(() =>
    this.referenceItems.filter((item) => !item.adminOnly || this.isAdmin()),
  );

  readonly role = computed(() => ROLE_META[this.auth.identity()?.role ?? 'reader']);

  /** Up to two initials of the client name, for the avatar. */
  readonly initials = computed(() => {
    const words = (this.auth.identity()?.client ?? '').split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2);
    return letters.toUpperCase();
  });

  closeMenu(): void {
    this.menuOpen.set(false);
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    this.closeMenu();
  }

  logout(): void {
    this.auth.logout();
    this.router.navigate(['/login']);
  }
}
