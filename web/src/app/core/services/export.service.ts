import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../i18n/i18n.service';
import {
  Finding,
  ConnectorDestination,
  ConnectorKind,
  ConnectorSystem,
  ConnectorFieldInfo,
} from '../models/api.models';
import { ApiService } from './api.service';

/** Systems each project may send its findings to, from GET /connectors/destinations. */
export function kindsByProject(
  destinations: readonly ConnectorDestination[],
): ReadonlyMap<string, readonly ConnectorKind[]> {
  const kinds = new Map<string, ConnectorKind[]>();
  for (const { project, kind } of destinations) {
    kinds.set(project, [...(kinds.get(project) ?? []), kind]);
  }
  return kinds;
}

/** Sending of a finding through a connector from the finding cards. */
@Injectable({ providedIn: 'root' })
export class ExportService {
  private readonly api = inject(ApiService);

  /** Id of the finding being sent (null: none). */
  private readonly sendingId = signal<number | null>(null);
  readonly sending = this.sendingId.asReadonly();

  /** Export ``finding``; the finding comes back with its record. */
  async send<F extends Finding>(
    finding: F,
    kind: ConnectorKind,
  ): Promise<{ finding: F } | { error: Message }> {
    this.sendingId.set(finding.id);
    try {
      const record = await firstValueFrom(this.api.exportFinding(finding.id, kind));
      const exports = [...finding.exports.filter((e) => e.kind !== kind), record];
      return { finding: { ...finding, exports } };
    } catch (err: unknown) {
      return { error: refusal(err) };
    } finally {
      this.sendingId.set(null);
    }
  }
}

/** Message of a refused export (the server explains why in English). */
function refusal(err: unknown): Message {
  if (!(err instanceof HttpErrorResponse)) {
    return msg('exports.refused', { detail: '' });
  }
  const detail = typeof err.error?.detail === 'string' ? err.error.detail : '';
  if (err.status === 403) {
    return msg('exports.forbidden');
  }
  if (err.status === 409) {
    return msg('exports.notReady', { detail });
  }
  return msg('exports.refused', { detail: detail || String(err.status) });
}

/** Text of a field declared by a connector in ``language``, else in English. */
export function fieldText(
  field: ConnectorFieldInfo,
  key: 'label' | 'help' | 'placeholder',
  language: string,
): string {
  return field.translations[language]?.[key] || field[key];
}

/** Names of the connectors by kind (the kind when unknown). */
export function systemNames(systems: readonly ConnectorSystem[]): ReadonlyMap<string, string> {
  return new Map(systems.map((system) => [system.kind, system.name]));
}
