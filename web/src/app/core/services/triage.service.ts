import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, firstValueFrom } from 'rxjs';
import { Message, msg } from '../i18n/i18n.service';
import { Finding, FindingDecision, FindingSeverityChange } from '../models/api.models';
import { ApiService } from './api.service';

/** Saved finding, or why the decision was refused. */
export type TriageResult = { finding: Finding } | { error: Message };

/** Saved findings of a bulk decision, or why it was refused (nothing saved). */
export type BulkTriageResult = { findings: Finding[] } | { error: Message };

/** What a finding card asks to save: a status, or a severity raised by an analyst. */
export type TriageChange = FindingDecision | FindingSeverityChange;

/**
 * Triage decisions of the finding cards (report and project findings pages): a status, a
 * severity raised by an analyst, or the rejection of the status proposed by an agent.
 */
@Injectable({ providedIn: 'root' })
export class TriageService {
  private readonly api = inject(ApiService);

  /** Id of the finding whose decision is being saved (null: none). */
  private readonly savingId = signal<number | null>(null);
  readonly saving = this.savingId.asReadonly();

  /** A bulk decision is being saved. */
  private readonly savingManyState = signal(false);
  readonly savingMany = this.savingManyState.asReadonly();

  /** Save the same status on ``findings``: all of them or none (the server refuses at once). */
  async decideMany(
    findings: readonly Finding[],
    decision: FindingDecision,
  ): Promise<BulkTriageResult> {
    this.savingManyState.set(true);
    try {
      const ids = findings.map((f) => f.id);
      return { findings: await firstValueFrom(this.api.updateFindingsStatus(ids, decision)) };
    } catch (err: unknown) {
      return { error: bulkRefusal(err) };
    } finally {
      this.savingManyState.set(false);
    }
  }

  /** Save a decision on ``finding``; ``null`` rejects the status proposed by an agent. */
  async decide(finding: Finding, decision: TriageChange | null): Promise<TriageResult> {
    const severity = decision !== null && 'severity' in decision;
    let request: Observable<Finding>;
    if (decision === null) {
      request = this.api.rejectFindingProposal(finding.id);
    } else if ('severity' in decision) {
      request = this.api.updateFindingSeverity(finding.id, decision);
    } else {
      request = this.api.updateFindingStatus(finding.id, decision);
    }
    this.savingId.set(finding.id);
    try {
      return { finding: await firstValueFrom(request) };
    } catch (err: unknown) {
      return { error: refusal(err, finding.id, severity) };
    } finally {
      this.savingId.set(null);
    }
  }
}

/** Message of a refused decision. */
function refusal(err: unknown, id: number, severity: boolean): Message {
  const code = err instanceof HttpErrorResponse ? err.status : 0;
  if (code === 403) {
    return msg('report.triageForbidden');
  }
  if (severity) {
    return code === 422
      ? msg('report.severityInvalid', { id })
      : msg('report.severityFailed', { id });
  }
  return code === 422 ? msg('report.triageInvalid', { id }) : msg('report.triageFailed', { id });
}

/** Message of a refused bulk decision, with the reason given by the server when it names one. */
function bulkRefusal(err: unknown): Message {
  const code = err instanceof HttpErrorResponse ? err.status : 0;
  if (code === 403) {
    return msg('report.triageForbidden');
  }
  if (code === 422 || code === 404) {
    const detail = err instanceof HttpErrorResponse ? err.error?.detail : null;
    const id = typeof detail === 'string' ? /Finding (\d+)/.exec(detail)?.[1] : undefined;
    if (id) {
      return code === 404
        ? msg('projectFindings.bulkNotFound', { id })
        : msg('projectFindings.bulkInvalid', { id });
    }
  }
  return msg('projectFindings.bulkFailed');
}
