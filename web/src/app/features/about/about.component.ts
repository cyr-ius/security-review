import { Component, inject, resource } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { ApiService } from '../../core/services/api.service';
import { HealthService } from '../../core/services/health.service';
import { RefreshButtonComponent } from '../../shared/components/refresh-button/refresh-button.component';

/** About page: version, documentation, source code, issues, Swagger and backend status. */
@Component({
  selector: 'app-about',
  imports: [RefreshButtonComponent, TranslatePipe],
  templateUrl: './about.component.html',
  styleUrl: './about.component.css',
})
export class AboutComponent {
  private readonly api = inject(ApiService);
  private readonly health = inject(HealthService);

  readonly about = rxResource({ stream: () => this.api.about() });
  /** Live check of the backend, done when the page opens and on demand. */
  readonly backend = resource({ loader: () => this.health.check(true) });

  /** Link to open a new issue on the repository. */
  newIssueUrl(issues: string): string {
    return `${issues}/new`;
  }
}
