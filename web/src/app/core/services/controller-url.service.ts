import { Injectable, computed, inject } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';

/**
 * Whether the public URL of the controller is known (SECREVIEW_CONTROLLER_URL or stored value).
 * Read only for the users who may set it: the shell shows them a banner while it is missing.
 */
@Injectable({ providedIn: 'root' })
export class ControllerUrlService {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);

  private readonly settings = rxResource({
    // undefined: the request is not sent
    params: () => (this.auth.can('settings.manage') ? true : undefined),
    stream: () => this.api.appSettings(),
  });

  /** True once the settings are read and neither the variable nor the database gives the URL. */
  readonly missing = computed(
    () => this.settings.hasValue() && !this.settings.value().controller_url.effective,
  );

  reload(): void {
    this.settings.reload();
  }
}
