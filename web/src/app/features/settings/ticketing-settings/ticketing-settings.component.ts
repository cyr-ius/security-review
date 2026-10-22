import { DatePipe } from '@angular/common';
import { Component, computed, inject, linkedSignal, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { SEVERITIES, Severity, TicketTarget } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { fieldText } from '../../../core/services/ticket.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { describeError } from '../settings-page';
import { TicketingConnectionComponent } from './ticketing-connection.component';

/** Longest destination accepted by the server (ticketing.api.MAX_FIELD_CHARS). */
const MAX_DESTINATION_CHARS = 500;

/** Destination of a project being set. */
interface TargetFormModel {
  project: string;
  kind: string;
  destination: string;
  /** Lowest severity sent automatically ('': by hand only). */
  auto: Severity | '';
}

/**
 * Administrator page: connection of each ticketing system (built-in or third-party connector)
 * and where the findings of each project go, with the optional automatic sending.
 */
@Component({
  selector: 'app-ticketing-settings',
  imports: [
    DatePipe,
    FormField,
    RefreshButtonComponent,
    TicketingConnectionComponent,
    TranslatePipe,
  ],
  templateUrl: './ticketing-settings.component.html',
  styleUrl: '../settings.css',
})
export class TicketingSettingsComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;

  readonly settings = rxResource({ stream: () => this.api.ticketing() });
  readonly targets = rxResource({ stream: () => this.api.ticketTargets() });
  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly connectors = computed(() => this.settings.value()?.connectors ?? []);
  readonly names = computed(
    () => new Map(this.connectors().map((connector) => [connector.kind, connector.name])),
  );
  readonly projectNames = computed(() =>
    (this.projects.value() ?? []).map((p) => p.project).sort((a, b) => a.localeCompare(b)),
  );

  /** Reset to the first system once the systems are known. */
  readonly targetModel = linkedSignal<TargetFormModel>(() => newTarget(this.connectors()[0]?.kind));
  readonly targetForm = form(this.targetModel, (path) => {
    maxLength(path.destination, MAX_DESTINATION_CHARS);
  });

  /** Destination field of the chosen system. */
  readonly destinationField = computed(
    () => this.connectors().find((c) => c.kind === this.targetModel().kind)?.destination ?? null,
  );
  readonly destinationLabel = computed(() => {
    const field = this.destinationField();
    return field ? fieldText(field, 'label', this.i18n.language()) : '';
  });
  readonly destinationPlaceholder = computed(() => {
    const field = this.destinationField();
    return field ? fieldText(field, 'placeholder', this.i18n.language()) : '';
  });

  readonly loading = computed(() => this.settings.isLoading() || this.targets.isLoading());
  readonly busy = signal(false);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);

  reload(): void {
    this.settings.reload();
    this.targets.reload();
    this.projects.reload();
  }

  /** Name of a system (its kind when its connector is no longer loaded). */
  systemName(kind: string): string {
    return this.names().get(kind) ?? kind;
  }

  /** Fill the form with a destination, to change it. */
  edit(target: TicketTarget): void {
    this.targetModel.set({
      project: target.project,
      kind: target.kind,
      destination: target.destination,
      auto: target.auto_min_severity ?? '',
    });
  }

  async saveTarget(event: Event): Promise<void> {
    event.preventDefault();
    const { project, kind, destination, auto } = this.targetModel();
    if (this.targetForm().invalid()) {
      return;
    }
    if (!project) {
      this.error.set(msg('ticketing.projectMissing'));
      return;
    }
    await this.run(async () => {
      await firstValueFrom(
        this.api.setTicketTarget(project, kind, {
          destination: destination.trim(),
          auto_min_severity: auto || null,
        }),
      );
      this.targetModel.set(newTarget(kind));
      return msg('ticketing.targetSaved');
    });
  }

  async deleteTarget(target: TicketTarget): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.deleteTicketTarget(target.project, target.kind));
      return msg('ticketing.targetDeleted');
    });
  }

  private async run(action: () => Promise<Message>): Promise<void> {
    this.busy.set(true);
    this.message.set(null);
    this.error.set(null);
    try {
      this.message.set(await action());
      this.targets.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}

function newTarget(kind = ''): TargetFormModel {
  return { project: '', kind, destination: '', auto: '' };
}
