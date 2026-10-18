import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, firstValueFrom } from 'rxjs';
import { Message, msg } from '../i18n/i18n.service';
import { Finding, FindingDecision } from '../models/api.models';
import { ApiService } from './api.service';

/** Saved finding, or why the decision was refused. */
export type TriageResult = { finding: Finding } | { error: Message };

/**
 * Triage decisions of the finding cards (report and project findings pages): a status, or the
 * rejection of the status proposed by an agent.
 */
@Injectable({ providedIn: 'root' })
export class TriageService {
  private readonly api = inject(ApiService);

  /** Id of the finding whose decision is being saved (null: none). */
  private readonly savingId = signal<number | null>(null);
  readonly saving = this.savingId.asReadonly();

  /** Save a decision on ``finding``; ``null`` rejects the status proposed by an agent. */
  async decide(finding: Finding, decision: FindingDecision | null): Promise<TriageResult> {
    const request: Observable<Finding> = decision
      ? this.api.updateFindingStatus(finding.id, decision)
      : this.api.rejectFindingProposal(finding.id);
    this.savingId.set(finding.id);
    try {
      return { finding: await firstValueFrom(request) };
    } catch (err: unknown) {
      return { error: refusal(err, finding.id) };
    } finally {
      this.savingId.set(null);
    }
  }
}

/** Message of a refused decision. */
function refusal(err: unknown, id: number): Message {
  const code = err instanceof HttpErrorResponse ? err.status : 0;
  if (code === 403) {
    return msg('report.triageForbidden');
  }
  return code === 422 ? msg('report.triageInvalid', { id }) : msg('report.triageFailed', { id });
}
