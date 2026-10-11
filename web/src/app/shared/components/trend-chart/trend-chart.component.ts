import {
  Component,
  DestroyRef,
  ElementRef,
  afterNextRender,
  computed,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { TrendPeriod } from '../../../core/models/api.models';

const HEIGHT = 220;
const MARGIN = { top: 12, right: 16, bottom: 28, left: 40 };
const TICKS = 4;

interface Point {
  x: number;
  y: number;
  period: TrendPeriod;
}

/**
 * Open findings at the end of each period: a single-series line chart with a crosshair
 * tooltip (pointer and keyboard) and a table view of the same numbers.
 */
@Component({
  selector: 'app-trend-chart',
  templateUrl: './trend-chart.component.html',
  styleUrl: './trend-chart.component.css',
})
export class TrendChartComponent {
  readonly periods = input.required<TrendPeriod[]>();

  readonly height = HEIGHT;
  readonly margin = MARGIN;

  private readonly container = viewChild.required<ElementRef<HTMLElement>>('container');
  private readonly destroyRef = inject(DestroyRef);

  /** Width of the plot container, measured so that text is never scaled. */
  readonly width = signal(640);

  /** Index of the period under the crosshair (null when not hovering). */
  readonly active = signal<number | null>(null);

  readonly showTable = signal(false);

  /** Upper bound of the y axis, rounded to a multiple of the tick count. */
  readonly yMax = computed(() => {
    const max = Math.max(0, ...this.periods().map((p) => p.open_total));
    return Math.max(TICKS, Math.ceil(max / TICKS) * TICKS);
  });

  readonly points = computed<Point[]>(() => {
    const periods = this.periods();
    const innerWidth = this.width() - MARGIN.left - MARGIN.right;
    const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
    const step = periods.length > 1 ? innerWidth / (periods.length - 1) : 0;
    return periods.map((period, index) => ({
      x: MARGIN.left + (periods.length > 1 ? index * step : innerWidth / 2),
      y: MARGIN.top + innerHeight * (1 - period.open_total / this.yMax()),
      period,
    }));
  });

  readonly linePath = computed(() =>
    this.points()
      .map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`)
      .join(' '),
  );

  readonly yTicks = computed(() => {
    const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
    return Array.from({ length: TICKS + 1 }, (_, i) => ({
      value: (this.yMax() / TICKS) * i,
      y: MARGIN.top + innerHeight * (1 - i / TICKS),
    }));
  });

  /** First, middle and last labels: enough to read the time axis without collisions. */
  readonly xLabels = computed(() => {
    const points = this.points();
    if (points.length === 0) {
      return [];
    }
    const indexes = [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])];
    return indexes.map((i) => ({
      x: points[i].x,
      label: points[i].period.period,
      anchor: i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle',
    }));
  });

  readonly activePoint = computed(() => {
    const index = this.active();
    return index === null ? null : (this.points()[index] ?? null);
  });

  /** Keep the tooltip inside the chart: flip it to the left of the crosshair near the edge. */
  readonly tooltipLeft = computed(() => {
    const point = this.activePoint();
    if (!point) {
      return 0;
    }
    return point.x > this.width() * 0.6 ? point.x - 12 : point.x + 12;
  });

  readonly tooltipFlipped = computed(() => {
    const point = this.activePoint();
    return point !== null && point.x > this.width() * 0.6;
  });

  constructor() {
    afterNextRender(() => {
      const element = this.container().nativeElement;
      const observer = new ResizeObserver((entries) => {
        const width = Math.round(entries[0].contentRect.width);
        if (width > 0) {
          this.width.set(width);
        }
      });
      observer.observe(element);
      this.destroyRef.onDestroy(() => observer.disconnect());
    });
  }

  /** Snap the crosshair to the closest period. */
  onPointerMove(event: PointerEvent): void {
    const svg = event.currentTarget as SVGSVGElement;
    const x = event.clientX - svg.getBoundingClientRect().left;
    let closest = 0;
    this.points().forEach((point, index) => {
      if (Math.abs(point.x - x) < Math.abs(this.points()[closest].x - x)) {
        closest = index;
      }
    });
    this.active.set(closest);
  }

  /** Arrow keys move the crosshair, Escape hides it. */
  onKeydown(event: KeyboardEvent): void {
    const last = this.points().length - 1;
    const current = this.active() ?? last;
    if (event.key === 'ArrowLeft') {
      this.active.set(Math.max(0, current - 1));
    } else if (event.key === 'ArrowRight') {
      this.active.set(Math.min(last, current + 1));
    } else if (event.key === 'Escape') {
      this.active.set(null);
    } else {
      return;
    }
    event.preventDefault();
  }
}
