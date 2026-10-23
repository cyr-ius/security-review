import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, output, signal } from '@angular/core';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  SEVERITIES,
  Severity,
  TicketTarget,
  TicketingConnector,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { fieldText } from '../../../core/services/ticket.service';
import { describeError } from '../settings-page';

/** Longest destination accepted by the server (ticketing.api.MAX_FIELD_CHARS). */
const MAX_DESTINATION_CHARS = 500;

/** Destination of a project being set. */
interface TargetFormModel {
  project: string;
  destination: string;
  /** Lowest severity sent automatically ('': by hand only). */
  auto: Severity | '';
}

/**
 * Where the findings of each project go in one connector (Jira project key, ServiceNow
 * assignment group...), with the optional automatic sending, in its settings dialog.
 */
@Component({
  selector: 'app-connector-targets',
  imports: [DatePipe, FormField, TranslatePipe],
  templateUrl: './connector-targets.component.html',
})
export class ConnectorTargetsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly connector = input.required<TicketingConnector>();
  /** Destinations of this connector. */
  readonly targets = input.required<readonly TicketTarget[]>();
  readonly projectNames = input.required<readonly string[]>();
  /** A destination was saved or deleted: the page reloads them. */
  readonly changed = output<void>();

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;

  readonly targetModel = signal<TargetFormModel>(newTarget());
  readonly targetForm = form(this.targetModel, (path) => {
    maxLength(path.destination, MAX_DESTINATION_CHARS);
  });

  readonly destinationLabel = computed(() =>
    fieldText(this.connector().destination, 'label', this.i18n.language()),
  );
  readonly destinationPlaceholder = computed(() =>
    fieldText(this.connector().destination, 'placeholder', this.i18n.language()),
  );

  readonly busy = signal(false);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);

  /** Fill the form with a destination, to change it. */
  edit(target: TicketTarget): void {
    this.targetModel.set({
      project: target.project,
      destination: target.destination,
      auto: target.auto_min_severity ?? '',
    });
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    const { project, destination, auto } = this.targetModel();
    if (this.targetForm().invalid()) {
      return;
    }
    if (!project) {
      this.error.set(msg('connectors.projectMissing'));
      return;
    }
    await this.run(async () => {
      await firstValueFrom(
        this.api.setTicketTarget(project, this.connector().kind, {
          destination: destination.trim(),
          auto_min_severity: auto || null,
        }),
      );
      this.targetModel.set(newTarget());
      return msg('connectors.targetSaved');
    });
  }

  async delete(target: TicketTarget): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.deleteTicketTarget(target.project, target.kind));
      return msg('connectors.targetDeleted');
    });
  }

  private async run(action: () => Promise<Message>): Promise<void> {
    this.busy.set(true);
    this.message.set(null);
    this.error.set(null);
    try {
      this.message.set(await action());
      this.changed.emit();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

function newTarget(): TargetFormModel {
  return { project: '', destination: '', auto: '' };
}
