import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, disabled, form, max, min, required } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { CodebaseReviewState } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { AuthService } from '../../../core/services/auth.service';

/** Longest interval between two codebase reviews (reports.codebase_review.MAX_INTERVAL_DAYS). */
const MAX_INTERVAL_DAYS = 3650;
/** Interval offered when the periodic review is turned on. */
const DEFAULT_INTERVAL_DAYS = 90;

/** Settings of the form from the stored state. */
function settingsOf(state: CodebaseReviewState | undefined): {
  requested: boolean;
  periodic: boolean;
  interval: number;
} {
  return {
    requested: state?.requested ?? false,
    periodic: state?.interval_days != null,
    interval: state?.interval_days ?? DEFAULT_INTERVAL_DAYS,
  };
}

/**
 * Review of the whole repository asked of the MCP agent on one project: its state for every
 * reader, and the request (once and/or periodic) for a holder of findings.triage on the project.
 */
@Component({
  selector: 'app-project-codebase-review',
  imports: [DatePipe, FormField, TranslatePipe],
  templateUrl: './project-codebase-review.component.html',
  styleUrl: './project-codebase-review.component.css',
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
  /** Number of saves sent, so that only the answer of the latest one is shown. */
  private calls = 0;
  readonly error = signal<Message | null>(null);
  readonly message = signal<Message | null>(null);

  /** Filled with the stored settings each time they are loaded, then edited by the form. */
  readonly model = linkedSignal(() => settingsOf(this.state.value()));
  readonly settingsForm = form(this.model, (path) => {
    required(path.interval);
    min(path.interval, 1);
    max(path.interval, MAX_INTERVAL_DAYS);
    disabled(path.interval, ({ valueOf }) => !valueOf(path.periodic));
  });

  toggle(): void {
    this.expanded.update((expanded) => !expanded);
  }

  /** Enter in the interval field saves it, as leaving the field does. */
  submit(event: Event): void {
    event.preventDefault();
    void this.save();
  }

  /** Save the settings as soon as a box is ticked or the interval is changed: no save button. */
  async save(): Promise<void> {
    // Read the model once every listener of the change event ran, formField included
    await Promise.resolve();
    const { requested, periodic, interval } = this.model();
    const days = Number(interval);
    this.message.set(null);
    if (periodic && (this.settingsForm.interval().invalid() || !Number.isInteger(days))) {
      this.error.set(msg('project.codebaseReviewInvalid'));
      return;
    }
    const call = ++this.calls;
    this.saving.set(true);
    this.error.set(null);
    try {
      const saved = await firstValueFrom(
        this.api.setCodebaseReview(this.project(), requested, periodic ? days : null),
      );
      // A later change already sent the newer settings: its answer wins
      if (call === this.calls) {
        this.state.set(saved);
        this.message.set(msg('project.codebaseReviewSaved'));
      }
    } catch {
      if (call === this.calls) {
        // Back to the stored settings: the form never shows what was not saved
        this.model.set(settingsOf(this.state.value()));
        this.error.set(msg('project.codebaseReviewSaveFailed'));
      }
    } finally {
      if (call === this.calls) {
        this.saving.set(false);
      }
    }
  }
}
