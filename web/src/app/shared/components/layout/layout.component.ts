import { Component, computed, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';
import { ThemeService } from '../../../core/services/theme.service';

/** Application shell: navigation bar and the routed page. */
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

  readonly roleLabel = computed(() => {
    const identity = this.auth.identity();
    if (!identity) {
      return '';
    }
    return identity.auth_enabled
      ? `${identity.client} · ${identity.role}`
      : 'Accès sans authentification';
  });

  logout(): void {
    this.auth.logout();
    this.router.navigate(['/login']);
  }
}
