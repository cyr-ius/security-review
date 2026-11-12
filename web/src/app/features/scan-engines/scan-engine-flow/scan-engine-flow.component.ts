import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { ControllerInstance, ScanEngine, ScanEngineList } from '../../../core/models/api.models';

/** Geometry of the diagram, in the units of its viewBox (it shrinks with the card, at most 1 unit = 1px). */
const HEIGHT = 430;
const SOURCE = { x: 72, r: 46, ys: [110, 320] };
const CONTROLLER = { x: 262, y: 215, r: 66 };
const CONTROLLER_ROW_GAP = CONTROLLER.r * 2 + 52;
const ENGINE = { r: 52, x0: 440, dx: 145, rows: SOURCE.ys };
const MIN_WIDTH = 620;
/** Gap between two arcs of a ring. */
const ARC_GAP = 3;
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

interface ControllerNode extends Point {
  instance: ControllerInstance;
  number: number;
  r: number;
  labelY: number;
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
  path: string;
  busyCodebase: boolean;
  busyFragment: boolean;
  idle: boolean;
}

interface SourceNode {
  kind: 'codebase' | 'fragment';
  x: number;
  y: number;
  r: number;
  active: number;
  capacity: number;
  arcs: Arc[];
  path: string;
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

/** Point of the circle of the Controller server towards ``target``. */
function controllerEdge(target: Point, center = CONTROLLER): Point {
  const angle = Math.atan2(target.y - center.y, target.x - center.x);
  return {
    x: center.x + center.r * Math.cos(angle),
    y: center.y + center.r * Math.sin(angle),
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
 * OpenGrep slots in use, thin links carry moving dots for scans running now, and a pulse travels
 * from an engine to the Controller server at each of its
 * heartbeats (a new heartbeat_at recreates the pulse, which restarts its CSS animation). The table of the page gives the same numbers.
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

  readonly height = computed(() => this.controllerLayout().height);
  readonly controllerRadius = CONTROLLER.r;
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

  private readonly controllerLayout = computed(() => {
    const instances = this.data().controllers?.length
      ? this.data().controllers
      : [{ id: 'current', started_at: '', heartbeat_at: '' }];
    const span = (instances.length - 1) * CONTROLLER_ROW_GAP;
    const height = Math.max(HEIGHT, CONTROLLER.r * 2 + 84 + span);
    const firstY = (height - span) / 2;
    return {
      height,
      nodes: instances.map((instance, index): ControllerNode => {
        const y = firstY + index * CONTROLLER_ROW_GAP;
        return {
          instance,
          number: index + 1,
          x: CONTROLLER.x,
          y,
          r: CONTROLLER.r,
          labelY: y + CONTROLLER.r + 20,
        };
      }),
    };
  });

  readonly controllerNodes = computed(() => this.controllerLayout().nodes);

  readonly width = computed(() =>
    Math.max(MIN_WIDTH, ENGINE.x0 + (this.columns() - 1) * ENGINE.dx + ENGINE.r + 40),
  );

  private closestController(y: number): ControllerNode {
    return this.controllerNodes().reduce((closest, node) =>
      Math.abs(node.y - y) < Math.abs(closest.y - y) ? node : closest,
    );
  }

  readonly totals = computed(() => {
    const totals = {
      files: 0,
      active: 0,
      activeCodebase: 0,
      activeFragment: 0,
      capacityCodebase: 0,
      capacityFragment: 0,
    };
    for (const engine of this.engines()) {
      totals.files += engine.processing_files;
      if (engine.active) {
        totals.active += 1;
        totals.activeCodebase += engine.processing_codebase_scans;
        totals.activeFragment += engine.processing_fragment_scans;
        totals.capacityCodebase += engine.codebase_slots;
        totals.capacityFragment += engine.fragment_slots;
      }
    }
    return {
      ...totals,
      busyCodebase: totals.activeCodebase > 0,
      busyFragment: totals.activeFragment > 0,
      arcs: ringArcs(
        this.controllerRing,
        totals.activeCodebase,
        totals.activeFragment,
        Math.max(
          totals.capacityCodebase + totals.capacityFragment,
          totals.activeCodebase + totals.activeFragment,
        ),
      ),
    };
  });

  readonly nodes = computed<EngineNode[]>(() => {
    const engines = this.engines();
    return engines.map((engine, index) => {
      const single = engines.length === 1;
      const row = index % 2;
      const x = ENGINE.x0 + Math.floor(index / 2) * ENGINE.dx;
      const y = single ? CONTROLLER.y : ENGINE.rows[row];
      // Enter the engine from below (top row), from above (bottom row) or from the left
      const end: Point = single
        ? { x: x - ENGINE.r, y }
        : { x, y: row === 0 ? y + ENGINE.r : y - ENGINE.r };
      const start = controllerEdge(end, this.closestController(y));
      const pull = single
        ? { x: end.x - 70, y: end.y }
        : { x, y: row === 0 ? end.y + 70 : end.y - 70 };
      const used = usedSlots(engine);
      const capacity = engine.codebase_slots + engine.fragment_slots;
      const busyCodebase = engine.processing_codebase_scans > 0;
      const busyFragment = engine.processing_fragment_scans > 0;
      return {
        engine,
        label: shortName(engine.name),
        x,
        y,
        labelY: !single && row === 0 ? y - ENGINE.r - 12 : y + ENGINE.r + 22,
        arcs: ringArcs(this.engineRing, used.codebase, used.fragment, capacity),
        used: used.codebase + used.fragment,
        capacity,
        path: `M${f(start.x)},${f(start.y)} C${f(start.x + 60)},${f(start.y)} ${f(pull.x)},${f(pull.y)} ${f(end.x)},${f(end.y)}`,
        busyCodebase,
        busyFragment,
        idle:
          engine.active && !busyCodebase && !busyFragment && used.codebase + used.fragment === 0,
      };
    });
  });

  readonly sources = computed<SourceNode[]>(() => {
    const totals = this.totals();
    return (['codebase', 'fragment'] as const).map((kind, index) => {
      const y = SOURCE.ys[index];
      const start: Point = { x: SOURCE.x + SOURCE.r, y };
      const end = controllerEdge({ x: SOURCE.x, y }, this.closestController(y));
      return {
        kind,
        x: SOURCE.x,
        y,
        r: SOURCE.r,
        active: kind === 'codebase' ? totals.activeCodebase : totals.activeFragment,
        capacity: kind === 'codebase' ? totals.capacityCodebase : totals.capacityFragment,
        arcs: ringArcs(
          this.sourceRing,
          kind === 'codebase' ? totals.activeCodebase : 0,
          kind === 'fragment' ? totals.activeFragment : 0,
          Math.max(
            kind === 'codebase' ? totals.capacityCodebase : totals.capacityFragment,
            kind === 'codebase' ? totals.activeCodebase : totals.activeFragment,
          ),
        ),
        path: `M${f(start.x)},${f(start.y)} C${f(start.x + 70)},${f(y)} ${f(end.x - 50)},${f(end.y)} ${f(end.x)},${f(end.y)}`,
        busy: kind === 'codebase' ? totals.busyCodebase : totals.busyFragment,
      };
    });
  });
}
