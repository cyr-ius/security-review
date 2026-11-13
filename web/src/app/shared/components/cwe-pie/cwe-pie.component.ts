import {
  Component,
  DestroyRef,
  ElementRef,
  afterNextRender,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';

/** Horizontal room kept on each side of the pie for the labels (leader line and text). */
const LABEL_ROOM = 84;
const MIN_RADIUS = 36;
const MAX_RADIUS = 110;
/** Vertical room above and below the pie, for the labels of the top and bottom slices. */
const VERTICAL_ROOM = 30;
/** Vertical room of a two-line label: closer labels are pushed apart. */
const LABEL_GAP = 28;
/** Tall enough for five labels on one side (the sixth slice is the large one opposite). */
const MIN_HEIGHT = 5 * LABEL_GAP + 8;

/**
 * Categorical hues by number of colored slices, validated as a ring (the last slice touches the
 * first): violet sits next to blue only when yellow closes the ring.
 */
const HUES: Record<number, readonly string[]> = {
  1: ['--series-1'],
  2: ['--series-1', '--series-2'],
  3: ['--series-1', '--series-2', '--series-3'],
  4: ['--series-1', '--series-2', '--series-3', '--series-4'],
  5: ['--series-1', '--series-2', '--series-3', '--series-7', '--series-4'],
};

export interface CweCount {
  cwe: string;
  count: number;
}

interface Point {
  x: number;
  y: number;
}

interface Slice {
  key: string;
  /** CWE identifier, or null for the open findings outside the most frequent CWEs. */
  cwe: string | null;
  count: number;
  percent: number;
  path: string;
  color: string;
  /** Start of the leader line, on the edge of the pie. */
  edge: Point;
  label: Point & { anchor: 'start' | 'end' };
}

/**
 * Most frequent CWEs of the open findings as a pie, each slice labeled with its CWE, its count
 * and its share of every open finding; the rest of the open findings form a neutral slice.
 * The pie fills the measured box of its host (which a card stretches to the height of its row),
 * so that text is never scaled.
 */
@Component({
  selector: 'app-cwe-pie',
  imports: [TranslatePipe],
  templateUrl: './cwe-pie.component.html',
  styleUrl: './cwe-pie.component.css',
})
export class CwePieComponent {
  /** Most frequent CWEs, most frequent first (at most five). */
  readonly cwes = input.required<CweCount[]>();
  /** Every open finding, to show the share of the other CWEs. */
  readonly total = input.required<number>();

  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly destroyRef = inject(DestroyRef);

  /** Box of the host, measured. */
  readonly width = signal(300);
  readonly height = signal(MIN_HEIGHT);

  /** The pie grows with its box; the labels keep their room on each side, above and below. */
  readonly radius = computed(() => {
    const fit = Math.min(this.width() / 2 - LABEL_ROOM, this.height() / 2 - VERTICAL_ROOM);
    return Math.round(Math.min(MAX_RADIUS, Math.max(MIN_RADIUS, fit)));
  });

  /** Slice under the pointer, highlighted with its label (null when not hovering). */
  readonly active = signal<string | null>(null);

  readonly slices = computed<Slice[]>(() => {
    const top = this.cwes()
      .filter((row) => row.count > 0)
      .slice(0, 5);
    const listed = top.reduce((sum, row) => sum + row.count, 0);
    const total = Math.max(this.total(), listed);
    if (total === 0) {
      return [];
    }
    const hues = HUES[top.length] ?? [];
    const parts = top.map((row, index) => ({
      key: row.cwe,
      cwe: row.cwe as string | null,
      count: row.count,
      color: `var(${hues[index]})`,
    }));
    if (total > listed) {
      parts.push({ key: '', cwe: null, count: total - listed, color: 'var(--cwe-other)' });
    }

    const radius = this.radius();
    const cx = this.width() / 2;
    // Clockwise from 12 o'clock.
    let start = -Math.PI / 2;
    const slices = parts.map((part) => {
      const sweep = (part.count / total) * 2 * Math.PI;
      const end = start + sweep;
      const middle = start + sweep / 2;
      const right = Math.cos(middle) >= 0;
      const slice: Slice = {
        ...part,
        percent: Math.round((part.count / total) * 100),
        path: this.arc(start, end, sweep),
        edge: this.point(middle, radius + 3),
        label: {
          x: right ? cx + radius + 18 : cx - radius - 18,
          y: this.point(middle, radius + 12).y,
          anchor: right ? 'start' : 'end',
        },
      };
      start = end;
      return slice;
    });
    this.spread(slices.filter((s) => s.label.anchor === 'start'));
    this.spread(slices.filter((s) => s.label.anchor === 'end'));
    return slices;
  });

  constructor() {
    afterNextRender(() => {
      const observer = new ResizeObserver((entries) => {
        const { width, height } = entries[0].contentRect;
        if (width > 0) {
          this.width.set(Math.round(width));
          this.height.set(Math.max(MIN_HEIGHT, Math.round(height)));
        }
      });
      observer.observe(this.host.nativeElement);
      this.destroyRef.onDestroy(() => observer.disconnect());
    });
  }

  /** Leader line: from the edge of the slice to its label, with a short horizontal end. */
  leader(slice: Slice): string {
    const side = slice.label.anchor === 'start' ? -1 : 1;
    const elbow = slice.label.x + side * 8;
    const end = slice.label.x + side * 3;
    return `M${slice.edge.x.toFixed(1)},${slice.edge.y.toFixed(1)} L${elbow.toFixed(1)},${slice.label.y.toFixed(1)} L${end.toFixed(1)},${slice.label.y.toFixed(1)}`;
  }

  private point(angle: number, radius: number): Point {
    return {
      x: this.width() / 2 + radius * Math.cos(angle),
      y: this.height() / 2 + radius * Math.sin(angle),
    };
  }

  private arc(start: number, end: number, sweep: number): string {
    const radius = this.radius();
    if (sweep >= 2 * Math.PI - 1e-9) {
      // A single slice: a full circle cannot be drawn as one arc.
      const top = this.point(-Math.PI / 2, radius);
      const bottom = this.point(Math.PI / 2, radius);
      return `M${top.x},${top.y} A${radius},${radius} 0 1 1 ${bottom.x},${bottom.y} A${radius},${radius} 0 1 1 ${top.x},${top.y} Z`;
    }
    const center = this.point(0, 0);
    const from = this.point(start, radius);
    const to = this.point(end, radius);
    const large = sweep > Math.PI ? 1 : 0;
    return `M${center.x},${center.y} L${from.x.toFixed(2)},${from.y.toFixed(2)} A${radius},${radius} 0 ${large} 1 ${to.x.toFixed(2)},${to.y.toFixed(2)} Z`;
  }

  /** Push the labels of one side apart, top to bottom, then back inside the chart. */
  private spread(side: Slice[]): void {
    const sorted = [...side].sort((a, b) => a.label.y - b.label.y);
    const top = LABEL_GAP / 2;
    const bottom = this.height() - LABEL_GAP / 2;
    sorted.forEach((slice, index) => {
      const previous = sorted[index - 1];
      const min = previous ? previous.label.y + LABEL_GAP : top;
      slice.label.y = Math.max(slice.label.y, min);
    });
    for (let index = sorted.length - 1; index >= 0; index--) {
      const next = sorted[index + 1];
      const max = next ? next.label.y - LABEL_GAP : bottom;
      sorted[index].label.y = Math.min(sorted[index].label.y, max);
    }
  }
}
