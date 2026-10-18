import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { firstValueFrom } from 'rxjs';
import { msg } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { AdvisoryEcosystemResult, AdvisoryUpdate } from '../../../core/models/api.models';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { compareTableText, filterAndSortRows } from '../../../shared/utils/table-utils';
import { SettingsPage } from '../settings-page';

/** Delay between two refreshes of the OSV history while an update runs. */
const POLL_MS = 5000;

export const UPDATE_STATUS_META: Record<
  AdvisoryUpdate['status'],
  { label: MessageKey; css: string }
> = {
  running: { label: 'settings.statusRunning', css: 'text-bg-info' },
  success: { label: 'settings.statusSuccess', css: 'text-bg-success' },
  partial: { label: 'settings.statusPartial', css: 'text-bg-warning' },
  failed: { label: 'settings.statusFailed', css: 'text-bg-danger' },
  interrupted: { label: 'settings.statusInterrupted', css: 'text-bg-secondary' },
};

export const TRIGGER_LABELS: Record<AdvisoryUpdate['trigger'], MessageKey> = {
  schedule: 'settings.triggerSchedule',
  cli: 'settings.triggerCli',
  web: 'sso.webInterface',
};

/**
 * Administrator page: state of the OSV advisory database, its download configuration, history
 * of its updates and manual update.
 */
@Component({
  selector: 'app-advisory-settings',
  imports: [DatePipe, DecimalPipe, RefreshButtonComponent, TableControlsComponent, TranslatePipe],
  templateUrl: './advisory-settings.component.html',
  styleUrl: '../settings.css',
})
export class AdvisorySettingsComponent extends SettingsPage {
  readonly advisories = rxResource({ stream: () => this.api.advisories() });

  readonly statusMeta = UPDATE_STATUS_META;
  readonly triggerLabels = TRIGGER_LABELS;
  readonly historySearch = signal('');
  readonly historySort = signal<'started' | 'trigger' | 'status' | 'duration'>('started');
  readonly historyDirection = signal<'asc' | 'desc'>('desc');
  readonly historyStatusFilter = signal<AdvisoryUpdate['status'] | ''>('');
  readonly historyTriggerFilter = signal<AdvisoryUpdate['trigger'] | ''>('');
  readonly historySortOptions = computed(() => [
    { value: 'started', label: this.i18n.translate('settings.start') },
    { value: 'trigger', label: this.i18n.translate('settings.trigger') },
    { value: 'status', label: this.i18n.translate('settings.status') },
    { value: 'duration', label: this.i18n.translate('settings.duration') },
  ]);
  readonly historyFilters = computed<TableControlFilter[]>(() => [
    {
      key: 'status',
      label: this.i18n.translate('settings.status'),
      value: this.historyStatusFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...Object.entries(this.statusMeta).map(([value, meta]) => ({
          value,
          label: this.i18n.translate(meta.label),
        })),
      ],
    },
    {
      key: 'trigger',
      label: this.i18n.translate('settings.trigger'),
      value: this.historyTriggerFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...Object.entries(this.triggerLabels).map(([value, label]) => ({
          value,
          label: this.i18n.translate(label),
        })),
      ],
    },
  ]);
  readonly visibleUpdates = computed(() => {
    const status = this.historyStatusFilter();
    const trigger = this.historyTriggerFilter();
    const updates = (this.advisories.value()?.updates ?? []).filter(
      (update) => (!status || update.status === status) && (!trigger || update.trigger === trigger),
    );
    const sort = this.historySort();
    return filterAndSortRows(
      updates,
      this.historySearch(),
      this.historyDirection(),
      (update) =>
        [
          update.started_at,
          update.triggered_by ?? '',
          this.i18n.translate(this.statusMeta[update.status].label),
          this.i18n.translate(this.triggerLabels[update.trigger]),
          JSON.stringify(update.results),
        ].join(' '),
      (left, right) => {
        if (sort === 'trigger') {
          return compareTableText(
            this.i18n.translate(this.triggerLabels[left.trigger]),
            this.i18n.translate(this.triggerLabels[right.trigger]),
          );
        }
        if (sort === 'status') {
          return compareTableText(
            this.i18n.translate(this.statusMeta[left.status].label),
            this.i18n.translate(this.statusMeta[right.status].label),
          );
        }
        if (sort === 'duration') {
          const elapsed = (update: AdvisoryUpdate) =>
            update.finished_at
              ? Date.parse(update.finished_at) - Date.parse(update.started_at)
              : -1;
          return elapsed(left) - elapsed(right);
        }
        return left.started_at.localeCompare(right.started_at);
      },
    );
  });

  readonly ecosystems = computed(() =>
    Object.entries(this.advisories.value()?.database.by_ecosystem ?? {}).sort(([a], [b]) =>
      a.localeCompare(b),
    ),
  );

  private pollTimer: ReturnType<typeof setTimeout> | undefined;

  onHistorySort(value: string): void {
    if (value === 'started' || value === 'trigger' || value === 'status' || value === 'duration') {
      this.historySort.set(value);
    }
  }

  onHistoryFilter(change: TableControlFilterChange): void {
    if (change.key === 'status') {
      this.historyStatusFilter.set(
        change.value in this.statusMeta ? (change.value as AdvisoryUpdate['status']) : '',
      );
    } else if (change.key === 'trigger') {
      this.historyTriggerFilter.set(
        change.value in this.triggerLabels ? (change.value as AdvisoryUpdate['trigger']) : '',
      );
    }
  }

  constructor() {
    super();
    // Follow an update in progress until it finishes
    effect(() => {
      clearTimeout(this.pollTimer);
      if (this.advisories.value()?.running) {
        this.pollTimer = setTimeout(() => this.advisories.reload(), POLL_MS);
      }
    });
    inject(DestroyRef).onDestroy(() => clearTimeout(this.pollTimer));
  }

  override reload(): void {
    super.reload();
    this.advisories.reload();
  }

  async startUpdate(): Promise<void> {
    if (this.busy() || !window.confirm(this.i18n.translate('settings.confirmUpdate'))) {
      return;
    }
    await this.run(
      () => firstValueFrom(this.api.startAdvisoryUpdate()),
      msg('settings.updateStarted'),
    );
  }

  /** Imported advisories, or the error, of each ecosystem of an update. */
  outcome(update: AdvisoryUpdate): { name: string; text: string; failed: boolean }[] {
    return Object.entries(update.results).map(([name, result]) => {
      if (typeof result === 'string') {
        return { name: this.i18n.translate('settings.error'), text: result, failed: true };
      }
      const stats = result as AdvisoryEcosystemResult;
      return stats.error
        ? { name, text: stats.error, failed: true }
        : {
            name,
            text: this.i18n.translate('settings.imported', { count: stats.imported ?? 0 }),
            failed: false,
          };
    });
  }

  /** Duration of a finished update, in a short human form. */
  duration(update: AdvisoryUpdate): string {
    if (!update.finished_at) {
      return '—';
    }
    const seconds = Math.round(
      (Date.parse(update.finished_at) - Date.parse(update.started_at)) / 1000,
    );
    return seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
  }
}
