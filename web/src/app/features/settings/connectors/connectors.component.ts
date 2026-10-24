import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { Message, msg } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ConnectorTarget, ConnectorInfo } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { describeError } from '../settings-page';
import { ConnectorConnectionComponent } from './connector-connection.component';
import { ConnectorTargetsComponent } from './connector-targets.component';

/** Tab of the settings dialog of a connector. */
type ConnectorTab = 'connection' | 'projects';

/** State shown on the card of a connector. */
type ConnectorState = 'on' | 'off' | 'unconfigured' | 'locked';

const STATE_BADGES: Record<ConnectorState, { label: MessageKey; css: string; icon: string }> = {
  on: { label: 'connectors.state.on', css: 'text-bg-success', icon: 'bi-check-circle' },
  off: { label: 'connectors.state.off', css: 'text-bg-secondary', icon: 'bi-pause-circle' },
  unconfigured: {
    label: 'connectors.state.unconfigured',
    css: 'text-bg-warning',
    icon: 'bi-exclamation-circle',
  },
  locked: { label: 'connectors.state.locked', css: 'text-bg-danger', icon: 'bi-lock' },
};

/** Look of the built-in connectors; a third-party one gets the puzzle piece. */
const BUILTIN_LOOK: Record<string, { icon: string; about: MessageKey }> = {
  jira: { icon: 'bi-kanban', about: 'connectors.about.jira' },
  servicenow: { icon: 'bi-headset', about: 'connectors.about.servicenow' },
};
const PLUGIN_LOOK = { icon: 'bi-puzzle', about: 'connectors.about.plugin' as MessageKey };

/**
 * Administrator page: the available connectors (built-in or third-party) as cards, each with
 * its switch and a gear opening its settings: connection and destinations of the projects.
 */
@Component({
  selector: 'app-connectors',
  imports: [
    ConnectorConnectionComponent,
    ConnectorTargetsComponent,
    RefreshButtonComponent,
    TranslatePipe,
  ],
  templateUrl: './connectors.component.html',
  styleUrls: ['../settings.css', './connectors.component.css'],
})
export class ConnectorsComponent {
  private readonly api = inject(ApiService);

  readonly settings = rxResource({ stream: () => this.api.connectors() });
  readonly targets = rxResource({ stream: () => this.api.connectorTargets() });
  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly connectors = computed(() => this.settings.value()?.connectors ?? []);
  /** SECREVIEW_CONNECTORS_ENABLED=false: every switch is locked off. */
  readonly locked = computed(() => this.settings.value()?.enabled === false);
  readonly projectNames = computed(() =>
    (this.projects.value() ?? []).map((p) => p.project).sort((a, b) => a.localeCompare(b)),
  );
  /** Destinations by connector kind. */
  readonly targetsByKind = computed(() => {
    const found = new Map<string, ConnectorTarget[]>();
    for (const target of this.targets.value() ?? []) {
      found.set(target.kind, [...(found.get(target.kind) ?? []), target]);
    }
    return found;
  });

  readonly loading = computed(() => this.settings.isLoading() || this.targets.isLoading());
  /** Kind of the connector being switched. */
  readonly switching = signal<string | null>(null);
  readonly message = signal<Message | null>(null);
  readonly error = signal<Message | null>(null);

  /** Connector whose settings dialog is open (kept up to date when the settings reload). */
  private readonly openKind = signal<string | null>(null);
  readonly opened = computed(
    () => this.connectors().find((c) => c.kind === this.openKind()) ?? null,
  );
  readonly tab = signal<ConnectorTab>('connection');
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('connectorDialog');

  reload(): void {
    this.settings.reload();
    this.targets.reload();
    this.projects.reload();
  }

  state(connector: ConnectorInfo): ConnectorState {
    if (this.locked()) {
      return 'locked';
    }
    if (connector.enabled) {
      return 'on';
    }
    return connector.configured ? 'off' : 'unconfigured';
  }

  badge(connector: ConnectorInfo) {
    return STATE_BADGES[this.state(connector)];
  }

  look(connector: ConnectorInfo) {
    return (connector.builtin && BUILTIN_LOOK[connector.kind]) || PLUGIN_LOOK;
  }

  targetsOf(connector: ConnectorInfo): readonly ConnectorTarget[] {
    return this.targetsByKind().get(connector.kind) ?? [];
  }

  /** The switch can be turned on once configured, and always turned off (unless locked). */
  switchable(connector: ConnectorInfo): boolean {
    return !this.locked() && (connector.enabled || connector.configured);
  }

  async toggle(connector: ConnectorInfo, event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const on = input.checked;
    this.switching.set(connector.kind);
    this.message.set(null);
    this.error.set(null);
    try {
      const updated = await firstValueFrom(this.api.switchConnector(connector.kind, on));
      this.settings.set(updated);
      const key = on ? 'connectors.switchedOn' : 'connectors.switchedOff';
      this.message.set(msg(key, { name: connector.name }));
    } catch (error: unknown) {
      input.checked = connector.enabled;
      this.error.set(describeError(error));
    } finally {
      this.switching.set(null);
    }
  }

  /** Open the settings of a connector, on its connection tab. */
  open(connector: ConnectorInfo): void {
    this.openKind.set(connector.kind);
    this.tab.set('connection');
    const dialog = this.dialog().nativeElement;
    if (!dialog.open) {
      dialog.showModal();
    }
  }

  close(): void {
    this.dialog().nativeElement.close();
  }

  /** The dialog closed (button or Escape key). */
  onClosed(): void {
    this.openKind.set(null);
  }
}
