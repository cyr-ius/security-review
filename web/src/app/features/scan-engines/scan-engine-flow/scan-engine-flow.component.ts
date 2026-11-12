import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ScanEngine, ScanEngineList } from '../../../core/models/api.models';

/** Geometry of the diagram, in the units of its viewBox (it scales with the card). */
const HEIGHT = 430;
const SOURCE = { x: 72, r: 46, ys: [110, 320] };
const CONTROLLER = { x: 262, y: 215, r: 66 };
const ENGINE = { r: 52, x0: 440, dx: 145, rows: [100, 330] };
const MIN_WIDTH = 620;
/** Gap between two arcs of a ring, and the thinnest and thickest link. */
const ARC_GAP = 3;
const LINK = { min: 1.5, max: 6 };
const RING = 6;

/** One arc of a ring: a dash of a circle, starting at 12 o'clock. */
interface Arc {
  kind: 'codebase' | 'fragment';
  dash: string;
  offset: number;
}

interface Point {
  x: number;
  y: number;
}

/** An engine as drawn: its place, its ring and the link from the Controller server. */
interface EngineNode {
  engine: ScanEngine;
  label: string;
  x: number;
  y: number;
  /** Name above the top row, below the others. */
  labelY: number;
  arcs: Arc[];
  used: number;
  capacity: number;
  scans: number;
  path: string;
  width: number;
  busyCodebase: boolean;
  busyFragment: boolean;
}

interface SourceNode {
  kind: 'codebase' | 'fragment';
  x: number;
  y: number;
  r: number;
  scans: number;
  path: string;
  width: number;
  busy: boolean;
}

/** Used slots of each pool (0 when the engine reports no capacity or is not active). */
function usedSlots(engine: ScanEngine): { codebase: number; fragment: number } {
  if (!engine.active) {
    return { codebase: 0, fragment: 0 };
  }
  return {
    codebase: Math.max(0, engine.codebase_slots - engine.free_codebase_slots),
    fragment: Math.max(0, engine.fragment_slots - engine.free_fragment_slots),
  };
}

/** The used slots as arcs of a ring of radius ``r``, codebase first, with a gap between. */
function ringArcs(r: number, codebase: number, fragment: number, capacity: number): Arc[] {
  if (capacity <= 0) {
    return [];
  }
  const circumference = 2 * Math.PI * r;
  const arcs: Arc[] = [];
  let start = 0;
  for (const [kind, used] of [
    ['codebase', codebase],
    ['fragment', fragment],
  ] as const) {
    const length = (Math.min(used, capacity) / capacity) * circumference;
    if (length > 0) {
      const drawn = Math.max(1, length - (capacity > used ? ARC_GAP : 0));
      arcs.push({ kind, dash: `${drawn} ${circumference - drawn}`, offset: -start });
      start += length;
    }
  }
  return arcs;
}

/** Width of a link carrying ``share`` of the busiest link. */
function linkWidth(share: number): number {
  return LINK.min + (LINK.max - LINK.min) * Math.min(1, Math.max(0, share));
}

/** Point of the circle of the Controller server towards ``target``. */
function controllerEdge(target: Point): Point {
  const angle = Math.atan2(target.y - CONTROLLER.y, target.x - CONTROLLER.x);
  return {
    x: CONTROLLER.x + CONTROLLER.r * Math.cos(angle),
    y: CONTROLLER.y + CONTROLLER.r * Math.sin(angle),
  };
}

const f = (value: number) => value.toFixed(1);

/** Name of an engine cut to fit under its circle. */
function shortName(name: string): string {
  return name.length > 20 ? `${name.slice(0, 19)}…` : name;
}

/**
 * Flow of the code scans on the Scan engines page: the pipelines and the agents on the left,
 * the Controller server in the middle, each enrolled engine on the right. A ring shows the
 * OpenGrep slots in use, a link is as thick as the share of the scans, and a moving dot marks
 * a scan running now. The table of the page gives the same numbers.
 */
@Component({
  selector: 'app-scan-engine-flow',
  imports: [TranslatePipe],
  templateUrl: './scan-engine-flow.component.html',
  styleUrl: './scan-engine-flow.component.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ScanEngineFlowComponent {
  readonly data = input.required<ScanEngineList>();

  readonly height = HEIGHT;
  readonly controller = CONTROLLER;
  readonly engineRadius = ENGINE.r;
  readonly ring = RING;
  readonly controllerRing = CONTROLLER.r - RING;
  readonly engineRing = ENGINE.r - RING;
  readonly sourceRing = SOURCE.r - RING;

  /** The active engines first, in the order of the API (the most recently seen first). */
  private readonly engines = computed(() => {
    const engines = this.data().engines;
    return [...engines.filter((e) => e.active), ...engines.filter((e) => !e.active)];
  });

  private readonly columns = computed(() => Math.ceil(this.engines().length / 2));

  readonly width = computed(() =>
    Math.max(MIN_WIDTH, ENGINE.x0 + (this.columns() - 1) * ENGINE.dx + ENGINE.r + 40),
  );

  readonly totals = computed(() => {
    const totals = {
      codebase: 0,
      fragment: 0,
      files: 0,
      failed: 0,
      active: 0,
      used: 0,
      capacity: 0,
    };
    let usedCodebase = 0;
    let usedFragment = 0;
    for (const engine of this.engines()) {
      totals.codebase += engine.codebase_scans;
      totals.fragment += engine.fragment_scans;
      totals.files += engine.scanned_files;
      totals.failed += engine.failed_scans;
      if (engine.active) {
        const used = usedSlots(engine);
        totals.active += 1;
        totals.capacity += engine.codebase_slots + engine.fragment_slots;
        usedCodebase += used.codebase;
        usedFragment += used.fragment;
      }
    }
    totals.used = usedCodebase + usedFragment;
    return {
      ...totals,
      busyCodebase: usedCodebase > 0,
      busyFragment: usedFragment > 0,
      arcs: ringArcs(this.controllerRing, usedCodebase, usedFragment, totals.capacity),
    };
  });

  readonly nodes = computed<EngineNode[]>(() => {
    const engines = this.engines();
    const busiest = Math.max(1, ...engines.map((e) => e.codebase_scans + e.fragment_scans));
    return engines.map((engine, index) => {
      const single = engines.length === 1;
      const row = index % 2;
      const x = ENGINE.x0 + Math.floor(index / 2) * ENGINE.dx;
      const y = single ? CONTROLLER.y : ENGINE.rows[row];
      // Enter the engine from below (top row), from above (bottom row) or from the left
      const end: Point = single
        ? { x: x - ENGINE.r, y }
        : { x, y: row === 0 ? y + ENGINE.r : y - ENGINE.r };
      const start = controllerEdge(end);
      const pull = single
        ? { x: end.x - 70, y: end.y }
        : { x, y: row === 0 ? end.y + 70 : end.y - 70 };
      const used = usedSlots(engine);
      const capacity = engine.codebase_slots + engine.fragment_slots;
      const scans = engine.codebase_scans + engine.fragment_scans;
      return {
        engine,
        label: shortName(engine.name),
        x,
        y,
        labelY: !single && row === 0 ? y - ENGINE.r - 12 : y + ENGINE.r + 22,
        arcs: ringArcs(this.engineRing, used.codebase, used.fragment, capacity),
        used: used.codebase + used.fragment,
        capacity,
        scans,
        path: `M${f(start.x)},${f(start.y)} C${f(start.x + 60)},${f(start.y)} ${f(pull.x)},${f(pull.y)} ${f(end.x)},${f(end.y)}`,
        width: linkWidth(scans / busiest),
        busyCodebase: used.codebase > 0,
        busyFragment: used.fragment > 0,
      };
    });
  });

  readonly sources = computed<SourceNode[]>(() => {
    const totals = this.totals();
    const busiest = Math.max(1, totals.codebase, totals.fragment);
    return (['codebase', 'fragment'] as const).map((kind, index) => {
      const y = SOURCE.ys[index];
      const start: Point = { x: SOURCE.x + SOURCE.r, y };
      const end = controllerEdge({ x: SOURCE.x, y });
      const scans = kind === 'codebase' ? totals.codebase : totals.fragment;
      return {
        kind,
        x: SOURCE.x,
        y,
        r: SOURCE.r,
        scans,
        path: `M${f(start.x)},${f(start.y)} C${f(start.x + 70)},${f(y)} ${f(end.x - 50)},${f(end.y)} ${f(end.x)},${f(end.y)}`,
        width: linkWidth(scans / busiest),
        busy: kind === 'codebase' ? totals.busyCodebase : totals.busyFragment,
      };
    });
  });
}
