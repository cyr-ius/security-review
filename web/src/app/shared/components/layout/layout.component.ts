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

  readonly adminNav: readonly NavItem[] = [
    { path: '/rules', label: 'Règles', icon: 'bi-sliders' },
    { path: '/checklists', label: 'Checklists', icon: 'bi-list-check' },
    { path: '/tokens', label: 'Jetons', icon: 'bi-key' },
  ];

  /** Sidebar shown as a drawer on small screens. */
  readonly menuOpen = signal(false);

  readonly isAdmin = computed(() => this.auth.identity()?.role === 'admin');

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
