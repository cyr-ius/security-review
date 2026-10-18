import { Injectable, computed, signal } from '@angular/core';
import { Identity, Permission } from '../models/api.models';

const TOKEN_KEY = 'secreview.token';

/**
 * Holds the bearer token and the identity of the current user.
 *
 * The token lives in sessionStorage: it is dropped when the tab is closed and is never
 * shared with other tabs or written to disk by the application.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly tokenValue = signal<string | null>(readStoredToken());
  private readonly identityValue = signal<Identity | null>(null);
  private readonly sessionExpiredValue = signal(false);

  /** Session token of the login (null when not logged in). */
  readonly token = this.tokenValue.asReadonly();

  /** Identity returned by /api/v1/me once the token has been checked. */
  readonly identity = this.identityValue.asReadonly();

  /** True once the session was refused while browsing: the "Session expired" dialog shows. */
  readonly sessionExpired = this.sessionExpiredValue.asReadonly();

  readonly canTriage = computed(() => this.identity()?.can_triage ?? false);

  /** True when the user holds ``permission`` (on ``project`` when one is given). */
  can(permission: Permission, project?: string): boolean {
    const grants = this.identity()?.permissions ?? {};
    if (!(permission in grants)) {
      return false;
    }
    const projects = grants[permission];
    return project === undefined || projects === null || !!projects?.includes(project);
  }

  /** Keep the identity checked by /api/v1/me. */
  setIdentity(identity: Identity): void {
    this.identityValue.set(identity);
  }

  /** Store a token (the identity is loaded by the guard). */
  login(token: string): void {
    this.sessionExpiredValue.set(false);
    this.tokenValue.set(token);
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch {
      // Storage may be disabled: the token then only lives in memory
    }
  }

  /** End a session the controller no longer accepts, and say so to the user. */
  expire(): void {
    this.logout();
    this.sessionExpiredValue.set(true);
  }

  /** The user read the "Session expired" dialog. */
  acknowledgeExpiry(): void {
    this.sessionExpiredValue.set(false);
  }

  /** Forget the token and the identity. */
  logout(): void {
    this.tokenValue.set(null);
    this.identityValue.set(null);
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      // Nothing stored
    }
  }
}

function readStoredToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
