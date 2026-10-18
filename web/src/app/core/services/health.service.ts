import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

/** Public liveness endpoint of the controller API (http_server.API_HEALTH_PATH). */
export const HEALTH_URL = '/api/health';

/**
 * Whether the controller answers. Checked once when the application loads (backendGuard), then
 * again when a request finds no backend (errorInterceptor) or the user retries.
 */
@Injectable({ providedIn: 'root' })
export class HealthService {
  private readonly http = inject(HttpClient);

  /** null: not checked yet. */
  private readonly availableValue = signal<boolean | null>(null);
  readonly available = this.availableValue.asReadonly();

  /** True when the controller answers; ``force`` checks again even if it answered before. */
  async check(force = false): Promise<boolean> {
    if (!force && this.availableValue() === true) {
      return true;
    }
    try {
      await firstValueFrom(this.http.get(HEALTH_URL));
      this.availableValue.set(true);
    } catch (error: unknown) {
      // Any answer of the controller itself (429 included) means it is there
      this.availableValue.set(!isUnreachable(error));
    }
    return this.availableValue() ?? false;
  }

  /** A request found no backend. */
  markUnavailable(): void {
    this.availableValue.set(false);
  }
}

/** True for an error that means the controller does not answer (network, proxy or timeout). */
export function isUnreachable(error: unknown): boolean {
  if (!(error instanceof HttpErrorResponse)) {
    return true;
  }
  return error.status === 0 || error.status === 502 || error.status === 504;
}
