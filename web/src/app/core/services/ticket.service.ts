import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../i18n/i18n.service';
import {
  Finding,
  TicketDestination,
  TicketKind,
  TicketSystem,
  TicketingFieldInfo,
} from '../models/api.models';
import { ApiService } from './api.service';

/** Systems each project may send its findings to, from GET /ticketing/destinations. */
export function kindsByProject(
  destinations: readonly TicketDestination[],
): ReadonlyMap<string, readonly TicketKind[]> {
  const kinds = new Map<string, TicketKind[]>();
  for (const { project, kind } of destinations) {
    kinds.set(project, [...(kinds.get(project) ?? []), kind]);
  }
  return kinds;
}

/** Sending of a finding to Jira or ServiceNow from the finding cards. */
@Injectable({ providedIn: 'root' })
export class TicketService {
  private readonly api = inject(ApiService);

  /** Id of the finding being sent (null: none). */
  private readonly sendingId = signal<number | null>(null);
  readonly sending = this.sendingId.asReadonly();

  /** Create the ticket of ``finding``; the finding comes back with its ticket. */
  async send<F extends Finding>(
    finding: F,
    kind: TicketKind,
  ): Promise<{ finding: F } | { error: Message }> {
    this.sendingId.set(finding.id);
    try {
      const ticket = await firstValueFrom(this.api.sendFindingTicket(finding.id, kind));
      const tickets = [...finding.tickets.filter((t) => t.kind !== kind), ticket];
      return { finding: { ...finding, tickets } };
    } catch (err: unknown) {
      return { error: refusal(err) };
    } finally {
      this.sendingId.set(null);
    }
  }
}

/** Message of a refused ticket (the server explains why in English). */
function refusal(err: unknown): Message {
  if (!(err instanceof HttpErrorResponse)) {
    return msg('ticketing.refused', { detail: '' });
  }
  const detail = typeof err.error?.detail === 'string' ? err.error.detail : '';
  if (err.status === 403) {
    return msg('ticketing.forbidden');
  }
  if (err.status === 409) {
    return msg('ticketing.notReady', { detail });
  }
  return msg('ticketing.refused', { detail: detail || String(err.status) });
}

/** Text of a field declared by a connector in ``language``, else in English. */
export function fieldText(
  field: TicketingFieldInfo,
  key: 'label' | 'help' | 'placeholder',
  language: string,
): string {
  return field.translations[language]?.[key] || field[key];
}

/** Names of the ticketing systems by kind (the kind when unknown). */
export function systemNames(systems: readonly TicketSystem[]): ReadonlyMap<string, string> {
  return new Map(systems.map((system) => [system.kind, system.name]));
}
