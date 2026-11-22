import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, disabled, form, max, min, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';

/** Longest interval between two codebase reviews (reports.codebase_review.MAX_INTERVAL_DAYS). */
const MAX_INTERVAL_DAYS = 3650;
/** Interval offered when the periodic review is turned on. */
const DEFAULT_INTERVAL_DAYS = 90;

/**
 * Review of the whole repository asked of the MCP agent on one project: its state for every
 * reader, and the request (once and/or periodic) for a holder of findings.triage on the project.
 */
@Component({
  selector: 'app-project-codebase-review',
  imports: [DatePipe, FormField, TranslatePipe],
  templateUrl: './project-codebase-review.component.html',
})
export class ProjectCodebaseReviewComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);

  readonly project = input.required<string>();

  readonly state = rxResource({
    params: () => this.project(),
    stream: ({ params }) => this.api.codebaseReview(params),
  });

  /** An agent never asks it of itself: a person who triages the project does. */
  readonly canEdit = computed(() => this.auth.can('findings.triage', this.project()));

  /** Folded by default: the header already gives the latest and next reviews. */
  readonly expanded = signal(false);
  readonly saving = signal(false);
  readonly error = signal<Message | null>(null);
  readonly message = signal<Message | null>(null);

  /** Filled with the stored settings each time they are loaded, then edited by the form. */
  readonly model = linkedSignal(() => {
    const state = this.state.value();
    return {
      requested: state?.requested ?? false,
      periodic: state?.interval_days != null,
      interval: state?.interval_days ?? DEFAULT_INTERVAL_DAYS,
    };
  });
  readonly settingsForm = form(this.model, (path) => {
    required(path.interval);
    min(path.interval, 1);
    max(path.interval, MAX_INTERVAL_DAYS);
    disabled(path.interval, ({ valueOf }) => !valueOf(path.periodic));
  });

  toggle(): void {
    this.expanded.update((expanded) => !expanded);
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    const { requested, periodic, interval } = this.model();
    const days = Number(interval);
    if (periodic && (this.settingsForm.interval().invalid() || !Number.isInteger(days))) {
      this.error.set(msg('project.codebaseReviewInvalid'));
      return;
    }
    this.saving.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      const saved = await firstValueFrom(
        this.api.setCodebaseReview(this.project(), requested, periodic ? days : null),
      );
      this.state.set(saved);
      this.message.set(msg('project.codebaseReviewSaved'));
    } catch {
      this.error.set(msg('project.codebaseReviewSaveFailed'));
    } finally {
      this.saving.set(false);
    }
  }
}
