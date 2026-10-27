import { NgTemplateOutlet } from '@angular/common';
import {
  Component,
  ElementRef,
  computed,
  inject,
  linkedSignal,
  signal,
  viewChild,
} from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { FormField, form, maxLength } from '@angular/forms/signals';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { HelpLinkComponent } from '../../../shared/components/help-link/help-link.component';
import { AuditSyslogSettings, AuditSyslogUpdate } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { describeError } from '../../settings/settings-page';

/** Syslog server chosen here, when SECREVIEW_AUDIT_SYSLOG_ADDRESS is not set. */
type SyslogMode = 'none' | 'custom';

/** A syslog setting that can be deleted when its variable hides it. */
type SyslogField = 'address' | 'facility';

const SYSLOG_SOURCE_LABELS: Record<AuditSyslogSettings['effective']['source'], MessageKey> = {
  web: 'settings.sourceWeb',
  environment: 'settings.sourceEnvironment',
  none: 'settings.sourceNone',
};

/** Longest address accepted by the server (audit_syslog.MAX_ADDRESS_CHARS). */
const MAX_ADDRESS_CHARS = 500;

/** Fields of the syslog form ('' as facility: none set here, the default applies). */
interface SyslogFormModel {
  mode: SyslogMode;
  address: string;
  facility: string;
}

/**
 * Button of the audit log page header, for the holders of settings.manage: its icon tells
 * whether the audit events are forwarded to a syslog server, and it opens the dialog that sets
 * that server. SECREVIEW_AUDIT_SYSLOG_ADDRESS and SECREVIEW_AUDIT_SYSLOG_FACILITY, when set,
 * take precedence: their field is then only shown.
 */
@Component({
  selector: 'app-audit-syslog',
  imports: [HelpLinkComponent, FormField, NgTemplateOutlet, TranslatePipe],
  templateUrl: './audit-syslog.component.html',
  styleUrl: './audit-syslog.component.css',
})
export class AuditSyslogComponent {
  private readonly api = inject(ApiService);

  readonly syslog = rxResource({ stream: () => this.api.auditSyslog() });
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);
  readonly busy = signal(false);

  /** Modal dialog hosting the syslog settings. */
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('syslogDialog');

  /** True when the controller forwards the audit events to a syslog server. */
  readonly forwarding = computed(() => !!this.syslog.value()?.effective.address);
  readonly buttonTitle = computed<Message>(() => {
    const address = this.syslog.value()?.effective.address;
    return address ? msg('audit.syslogOnTitle', { address }) : msg('audit.syslogOffTitle');
  });

  /** Filled with the stored values each time they are loaded, then edited by the form. */
  readonly model = linkedSignal<SyslogFormModel>(() => {
    const current = this.syslog.value();
    const address = current?.address.value;
    return {
      mode: address ? 'custom' : 'none',
      address: address ?? '',
      facility: current?.facility.value ?? '',
    };
  });
  readonly syslogForm = form(this.model, (path) => {
    maxLength(path.address, MAX_ADDRESS_CHARS);
  });

  readonly source = computed(() => {
    const source = this.syslog.value()?.effective.source;
    return source ? SYSLOG_SOURCE_LABELS[source] : null;
  });

  /** Open the dialog with the settings in use (reloaded: unsaved edits are dropped). */
  open(): void {
    this.syslog.reload();
    const dialog = this.dialog().nativeElement;
    if (!dialog.open) {
      dialog.showModal();
    }
  }

  /** Close the dialog; its `close` event then clears the messages. */
  close(): void {
    this.dialog().nativeElement.close();
  }

  /** Clear the messages when the dialog closes (button or Escape key). */
  onClosed(): void {
    this.message.set(null);
    this.error.set(null);
  }

  async save(event: Event): Promise<void> {
    event.preventDefault();
    const current = this.syslog.value();
    if (!current) {
      return;
    }
    const model = this.model();
    const address = model.address.trim();
    const values: AuditSyslogUpdate = {};
    if (!current.address.env_set) {
      if (this.syslogForm().invalid() || (model.mode === 'custom' && !address)) {
        this.error.set(msg('audit.syslogMissing'));
        return;
      }
      values.address = model.mode === 'none' ? null : address;
    }
    if (!current.facility.env_set) {
      values.facility = model.facility || null;
    }
    await this.run(values, msg('audit.syslogSaved'));
  }

  /** Delete a stored value that its variable hides. */
  async deleteStored(field: SyslogField): Promise<void> {
    await this.run({ [field]: null }, msg('settings.storedDeleted'));
  }

  /** Send ``values``, show the outcome and reload the settings. */
  private async run(values: AuditSyslogUpdate, success: Message): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.message.set(null);
    try {
      await firstValueFrom(this.api.setAuditSyslog(values));
      this.message.set(success);
      this.syslog.reload();
    } catch (error: unknown) {
      this.error.set(describeError(error));
    } finally {
      this.busy.set(false);
    }
  }
}
