import { Component, computed, inject, input, linkedSignal, output, signal } from '@angular/core';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { I18nService, Message, msg } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  TicketingConnector,
  TicketingFieldInfo,
  TicketingUpdate,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { fieldText } from '../../../core/services/ticket.service';
import { describeError } from '../settings-page';

/** Longest value accepted by the server (ticketing.api.MAX_FIELD_CHARS). */
const MAX_VALUE_CHARS = 500;

/**
 * Connection of one ticketing system. Its fields are those the connector declares (the URL
 * first): a field whose SECREVIEW_* variable is set is only shown; a secret is never sent back
 * by the server ('***', kept when saved unchanged).
 */
@Component({
  selector: 'app-ticketing-connection',
  imports: [FormField, TranslatePipe],
  templateUrl: './ticketing-connection.component.html',
  styleUrl: '../settings.css',
})
export class TicketingConnectionComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly connector = input.required<TicketingConnector>();
  /** The connection was saved: the page reloads the settings. */
  readonly changed = output<void>();

  /** Values of the form, by field name, filled with the stored values. */
  readonly model = linkedSignal<Record<string, string>>(() =>
    Object.fromEntries(this.connector().fields.map((f) => [f.name, f.value ?? ''])),
  );
  readonly connectionForm = form(this.model, (path) => {
    for (const field of this.connector().fields) {
      maxLength(path[field.name], MAX_VALUE_CHARS);
    }
  });

  /** Fields the web interface may change. */
  readonly editable = computed(() => this.connector().fields.filter((f) => !f.env_set));

  readonly busy = signal(false);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);

  /** Text of a field in the language of the interface. */
  text(field: TicketingFieldInfo, key: 'label' | 'help' | 'placeholder'): string {
    return fieldText(field, key, this.i18n.language());
  }

  /** Values of the editable fields ('' deletes the stored value). */
  private values(): TicketingUpdate {
    const model = this.model();
    const values: TicketingUpdate = {};
    for (const field of this.editable()) {
      const value = field.secret ? (model[field.name] ?? '') : (model[field.name] ?? '').trim();
      values[field.name] = value || null;
    }
    return values;
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.connectionForm().invalid()) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.setTicketing(this.connector().kind, this.values()));
      this.message.set(msg('ticketing.saved'));
      this.changed.emit();
    });
  }

  /** Test the values of the form, without saving them. */
  async test(): Promise<void> {
    await this.run(async () => {
      const kind = this.connector().kind;
      const result = await firstValueFrom(this.api.testTicketing(kind, this.values()));
      if (result.ok) {
        this.message.set(msg('ticketing.testOk'));
      } else {
        this.error.set(msg('ticketing.testFailed', { message: result.message ?? '' }));
      }
    });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.message.set(null);
    this.error.set(null);
    try {
      await action();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}
