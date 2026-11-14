import {
  ChangeDetectionStrategy,
  Component,
  computed,
  ElementRef,
  inject,
  input,
  signal,
} from '@angular/core';
import { I18nService } from '../../../core/i18n/i18n.service';
import { MessageKey } from '../../../core/i18n/messages';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  AgentActivity,
  ControllerScans,
  Processing,
  ScanEngine,
  ScanEngineList,
  ServerInstance,
} from '../../../core/models/api.models';

/** Geometry of the diagram, in the units of its viewBox (it shrinks with the card, at most 1 unit = 1px). */
const HEIGHT = 430;
const SOURCE = { x: 72, r: 46, ys: [110, 320] };
/** The agents: smaller than the MCP servers they call, stacked under the pipelines. */
const AGENT = { r: 36, minY: 205 };
const AGENT_ROW_GAP = AGENT.r * 2 + 36;
/** Agents drawn one by one; the others share a "+N" circle. */
const MAX_AGENT_NODES = 6;
/** Column of the MCP servers, between the agents and the Controller server (when any is running). */
const MCP = { x: 232, r: 46, minY: 205 };
const MCP_ROW_GAP = MCP.r * 2 + 40;
/** Width taken by the column of the MCP servers: the next columns move right by this much. */
const MCP_COLUMN = 160;
const CONTROLLER = { x: 262, y: 215, r: 66 };
const CONTROLLER_ROW_GAP = CONTROLLER.r * 2 + 52;
/**
 * The engines: in columns right of the Controller server, PER_COLUMN at most, each entered from
 * the left; an odd column moves down by half a row, so that its links pass between the circles
 * of the column before.
 */
const ENGINE = { r: SOURCE.r, x0: 470, dx: 145, rowGap: SOURCE.r * 2 + 52, perColumn: 4 };
const MIN_WIDTH = 620;
/** Gap between two arcs of a ring. */
const ARC_GAP = 3;
/** Width of the rings, and from the edge of a circle to the middle of its ring (3 units inside). */
const RING = 3;
const RING_INSET = 3 + RING / 2;

/** Families of the requests of the agents, in the order of the parts of a ring. */
/** Requests by family, every family given (0 when an earlier server gives none). */
type Counts = Required<Processing>;
type Family = keyof Counts;
/** The scans of security-review-ci (pipeline) only reach the Controller server. */
const FAMILIES: readonly Family[] = ['code', 'deps', 'reports', 'reads', 'pipeline'];
/** Delay between the dots of two families on the same path, in seconds. */
const DOT_STAGGER = 0.6;

/** One arc of a ring: a dash of a circle, starting at 12 o'clock. */
interface Arc {
  kind: 'codebase' | 'fragment' | Family;
  dash: string;
  offset: number;
}

/** A request running: a dot of the color of its family along ``path``, from ``begin`` seconds. */
interface Dot {
  kind: Family;
  path: string;
  begin: string;
}

interface Point {
  x: number;
  y: number;
}

interface ControllerNode extends Point {
  instance: ServerInstance;
  number: number;
  r: number;
  labelY: number;
  /** Scans received by this process (from the MCP servers and security-review-ci), by family:
   * the inner ring. */
  processing: Counts;
  requestArcs: Arc[];
  /** The code scans it runs itself (zeros from an earlier version). */
  scans: ControllerScans;
  /** Its ring: the slots of the engines, or its own slots when there is no engine. */
  arcs: Arc[];
}

/** An MCP server as drawn: the link from the agents, and its link to the Controller server. */
interface McpNode extends Point {
  instance: ServerInstance;
  number: number;
  r: number;
  labelY: number;
  inPath: string;
  outPath: string;
  /** Requests running by family, as the parts of its ring. */
  processing: Counts;
  total: number;
  arcs: Arc[];
  /** Requests from the "Agents" circle (none when the agents are drawn one by one). */
  dots: Dot[];
  busy: boolean;
  /** Code scans going on to the Controller server now. */
  outBusy: boolean;
  /** Agents linked to it (seen in the last 5 minutes). */
  agentCount: number;
}

/** An agent seen by an MCP server (or the "+N" circle of the others), linked to its server(s). */
interface AgentNode extends Point {
  id: string;
  /** null for the "+N" circle. */
  agent: AgentActivity | null;
  /** MCP server of the agent, by its number in the diagram. */
  mcpNumber: number;
  /** "+N" circle: how many agents it stands for. */
  more: number;
  label: string;
  /** Tooltip: its MCP client, its server and its last request (its requests are added). */
  titleKey: MessageKey;
  titleParams: Record<string, string | number>;
  /** Requests running by family, as the parts of its ring. */
  processing: Counts;
  total: number;
  arcs: Arc[];
  paths: string[];
  dots: Dot[];
  busy: boolean;
}

/** An engine as drawn: its place, its ring and the link from the Controller server. */
interface EngineNode {
  engine: ScanEngine;
  label: string;
  x: number;
  y: number;
  /** Name under the circle. */
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
  /** Above the circle on the top row, like the engines there; below it otherwise. */
  labelY: number;
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

/** The code scans a Controller process runs itself; zeros from an earlier version. */
function scansOf(instance: ServerInstance): ControllerScans {
  return {
    codebase: instance.scans?.codebase ?? 0,
    fragment: instance.scans?.fragment ?? 0,
    files: instance.scans?.files ?? 0,
    codebase_slots: instance.scans?.codebase_slots ?? 0,
    fragment_slots: instance.scans?.fragment_slots ?? 0,
  };
}

/** Requests by family; an MCP server of an earlier version gives its code scans only. */
function processingOf(item: { processing?: Processing; processing_fragments: number }): Counts {
  return {
    code: item.processing?.code ?? item.processing_fragments,
    deps: item.processing?.deps ?? 0,
    reports: item.processing?.reports ?? 0,
    reads: item.processing?.reads ?? 0,
    pipeline: item.processing?.pipeline ?? 0,
  };
}

function totalOf(processing: Counts): number {
  return FAMILIES.reduce((sum, family) => sum + processing[family], 0);
}

function sumOf(items: Counts[]): Counts {
  const sum: Counts = { code: 0, deps: 0, reports: 0, reads: 0, pipeline: 0 };
  for (const item of items) {
    for (const family of FAMILIES) {
      sum[family] += item[family] ?? 0;
    }
  }
  return sum;
}

/**
 * The requests running as the parts of a whole ring of radius ``r``, each in proportion to its
 * count, with a gap between two parts (none while nothing runs).
 */
function shareArcs(r: number, processing: Counts): Arc[] {
  const total = totalOf(processing);
  if (total <= 0) {
    return [];
  }
  const circumference = 2 * Math.PI * r;
  const parts = FAMILIES.filter((family) => processing[family] > 0);
  const arcs: Arc[] = [];
  let start = 0;
  for (const kind of parts) {
    const length = (processing[kind] / total) * circumference;
    const drawn = parts.length > 1 ? Math.max(1, length - ARC_GAP) : length;
    arcs.push({ kind, dash: `${drawn} ${circumference - drawn}`, offset: -start });
    start += length;
  }
  return arcs;
}

/** Point of the circle ``center`` (the Controller server by default) towards ``target``. */
function controllerEdge(target: Point, center: Point & { r: number } = CONTROLLER): Point {
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
 * Flow of the code scans on the Scan engines page: the pipelines and the agents on the left, the
 * MCP servers that relay the scan_code fragments of the agents, the Controller server in the
 * middle, each enrolled engine on the right. A ring shows the
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
  private readonly i18n = inject(I18nService);
  private readonly host: ElementRef<HTMLElement> = inject(ElementRef);

  readonly data = input.required<ScanEngineList>();

  /**
   * Node under the pointer ("engine:<id>", "mcp:<id>"...) and the pointer, in the frame of the
   * diagram. The tooltip is drawn in HTML from them: a native SVG <title> closes, or never opens,
   * when the page reloads the data under the pointer (every 2 s).
   */
  readonly hovered = signal<string | null>(null);
  readonly pointer = signal<{ x: number; y: number; flipped: boolean } | null>(null);

  /** Text of the tooltip of the hovered node, from the current data (null once it is gone). */
  readonly tooltip = computed(() => {
    const key = this.hovered();
    if (!key) {
      return null;
    }
    const t = this.i18n.translate.bind(this.i18n);
    const split = key.indexOf(':');
    const kind = key.slice(0, split);
    const id = key.slice(split + 1);
    const total = this.totals();
    switch (kind) {
      case 'source': {
        const source = this.sources().find((s) => s.kind === id);
        return source
          ? t(
              source.kind === 'codebase'
                ? 'scanEngines.flowPipelinesTitle'
                : 'scanEngines.flowAgentsTitle',
              { count: source.active, total: source.capacity },
            )
          : null;
      }
      case 'agent': {
        const agent = this.agentNodes().find((a) => a.id === id);
        return agent
          ? t(agent.titleKey, { ...agent.titleParams, requests: this.requests(agent.processing) })
          : null;
      }
      case 'mcp': {
        const node = this.mcpNodes().find((n) => n.instance.id === id);
        if (!node) {
          return null;
        }
        const detail = t(
          node.instance.delegated
            ? 'scanEngines.flowMcpTitleDelegated'
            : 'scanEngines.flowMcpTitleLocal',
          {
            name: node.instance.name,
            version: node.instance.version,
            requests: this.requests(node.processing),
          },
        );
        return `${t('scanEngines.flowMcpInstance', { number: node.number })}. ${detail}`;
      }
      case 'controller': {
        const node = this.controllerNodes().find((n) => n.instance.id === id);
        if (!node) {
          return null;
        }
        const scans = node.scans;
        const capacity = scans.codebase_slots + scans.fragment_slots;
        const detail = this.data().engines.length
          ? t('scanEngines.flowControllerTitle', {
              active: total.active,
              total: this.data().engines.length,
              pipelines: total.activeCodebase,
              fragments: total.activeFragment,
              files: total.files,
            })
          : t(
              capacity
                ? 'scanEngines.flowControllerLocalTitle'
                : 'scanEngines.flowControllerLocalUnlimitedTitle',
              {
                pipelines: scans.codebase,
                fragments: scans.fragment,
                files: scans.files,
                used: scans.codebase + scans.fragment,
                capacity,
              },
            );
        const received = t('scanEngines.flowControllerRequests', {
          pipeline: node.processing.pipeline,
          code: node.processing.code,
          deps: node.processing.deps,
        });
        return `${t('scanEngines.flowControllerInstance', { number: node.number })}. ${detail}\n${received}`;
      }
      case 'engine': {
        const node = this.nodes().find((n) => n.engine.id === id);
        if (!node) {
          return null;
        }
        const now = t('scanEngines.flowEngineNow', {
          codebase: node.engine.processing_codebase_scans,
          fragments: node.engine.processing_fragment_scans,
        });
        return `${t('scanEngines.flowEngineTitle', {
          name: node.engine.name,
          version: node.engine.version,
          codebase: node.engine.codebase_scans,
          fragments: node.engine.fragment_scans,
          files: node.engine.scanned_files,
          failed: node.engine.failed_scans,
          busy: node.engine.busy_refusals,
          used: node.used,
          capacity: node.capacity,
        })}\n${now}`;
      }
    }
    return null;
  });

  /** The requests of a tooltip, by family (in the language of the page). */
  private requests(processing: Counts): string {
    return this.i18n.translate('scanEngines.flowRequests', { ...processing });
  }

  /** Follow the pointer; the tooltip goes left of it on the right half of the diagram. */
  onPointerMove(event: PointerEvent): void {
    const rect = this.host.nativeElement.getBoundingClientRect();
    const x = event.clientX - rect.left;
    this.pointer.set({ x, y: event.clientY - rect.top, flipped: x > rect.width / 2 });
  }

  readonly height = computed(() => this.controllerLayout().height);
  readonly controllerRadius = CONTROLLER.r;
  readonly engineRadius = ENGINE.r;
  readonly ring = RING;
  readonly ringInset = RING_INSET;
  readonly controllerRing = CONTROLLER.r - RING_INSET;
  /** Inner ring of the Controller server: the scans it receives, inside its ring of the slots. */
  readonly controllerRequestRing = CONTROLLER.r - RING_INSET - RING - 3;
  readonly engineRing = ENGINE.r - RING_INSET;
  readonly mcpRadius = MCP.r;
  readonly mcpRing = MCP.r - RING_INSET;
  readonly agentRadius = AGENT.r;
  readonly agentRing = AGENT.r - RING_INSET;

  /** The active engines first, in the order of the API (the most recently seen first). */
  private readonly engines = computed(() => {
    const engines = this.data().engines;
    return [...engines.filter((e) => e.active), ...engines.filter((e) => !e.active)];
  });

  private readonly columns = computed(() => Math.ceil(this.engines().length / ENGINE.perColumn));

  /** Height of the column of the engines, from the top of its first circle to its last label. */
  private readonly engineSpan = computed(() => {
    const rows = Math.min(this.engines().length, ENGINE.perColumn);
    if (!rows) {
      return 0;
    }
    const stagger = this.columns() > 1 ? ENGINE.rowGap / 2 : 0;
    return (rows - 1) * ENGINE.rowGap + stagger + ENGINE.r * 2 + 84;
  });

  private readonly mcpServers = computed(() => this.data().mcp_servers ?? []);

  /** How far the Controller server and the engines move right to make room for the MCP servers. */
  private readonly offset = computed(() => (this.mcpServers().length ? MCP_COLUMN : 0));

  /** Centre of the MCP servers, stacked around the agents and below the pipelines. */
  private readonly mcpYs = computed(() => {
    const count = this.mcpServers().length;
    const firstY = Math.max(MCP.minY, SOURCE.ys[1] - ((count - 1) * MCP_ROW_GAP) / 2);
    return this.mcpServers().map((_, index) => firstY + index * MCP_ROW_GAP);
  });

  /** Every agent of every MCP server, with the number of its server, the most recent first. */
  private readonly agents = computed(() =>
    this.mcpServers()
      .flatMap((instance, index) =>
        (instance.agents ?? []).map((agent) => ({ agent, mcpNumber: index + 1 })),
      )
      .sort((left, right) => right.agent.last_seen.localeCompare(left.agent.last_seen)),
  );

  /** Centre of the agent circles (at most MAX_AGENT_NODES, then a "+N" circle). */
  private readonly agentYs = computed(() => {
    const total = this.agents().length;
    const count = total > MAX_AGENT_NODES ? MAX_AGENT_NODES + 1 : total;
    const firstY = Math.max(AGENT.minY, SOURCE.ys[1] - ((count - 1) * AGENT_ROW_GAP) / 2);
    return Array.from({ length: count }, (_, index) => firstY + index * AGENT_ROW_GAP);
  });

  private readonly controllerLayout = computed(() => {
    const instances: ServerInstance[] = this.data().controllers?.length
      ? this.data().controllers
      : [
          {
            id: 'current',
            name: '',
            version: '',
            started_at: '',
            heartbeat_at: '',
            delegated: false,
            processing_fragments: 0,
            agents: [],
          },
        ];
    // Without engines, each process draws its own slots; with them, the slots of the engines
    const engineArcs = this.engines().length ? this.totals().arcs : null;
    const span = (instances.length - 1) * CONTROLLER_ROW_GAP;
    const lastMcp = this.mcpYs().at(-1);
    const lastAgent = this.agentYs().at(-1);
    const height = Math.max(
      HEIGHT,
      CONTROLLER.r * 2 + 84 + span,
      lastMcp === undefined ? 0 : lastMcp + MCP.r + 56,
      lastAgent === undefined ? 0 : lastAgent + AGENT.r + 40,
      this.engineSpan(),
    );
    const firstY = (height - span) / 2;
    return {
      height,
      nodes: instances.map((instance, index): ControllerNode => {
        const y = firstY + index * CONTROLLER_ROW_GAP;
        const processing = processingOf(instance);
        const scans = scansOf(instance);
        return {
          instance,
          number: index + 1,
          x: CONTROLLER.x + this.offset(),
          y,
          r: CONTROLLER.r,
          labelY: y + CONTROLLER.r + 20,
          processing,
          requestArcs: shareArcs(this.controllerRequestRing, processing),
          scans,
          arcs:
            engineArcs ??
            ringArcs(
              this.controllerRing,
              scans.codebase,
              scans.fragment,
              Math.max(
                scans.codebase_slots + scans.fragment_slots,
                scans.codebase + scans.fragment,
              ),
            ),
        };
      }),
    };
  });

  readonly controllerNodes = computed(() => this.controllerLayout().nodes);

  /** Scans sent by security-review-ci that the Controller server processes receive now. */
  readonly pipelineSent = computed(() =>
    this.controllerNodes().reduce((sum, node) => sum + node.processing.pipeline, 0),
  );

  /** Up to the last engine, or up to the Controller server when there is no engine. */
  readonly width = computed(() =>
    this.engines().length
      ? Math.max(
          MIN_WIDTH,
          ENGINE.x0 + this.offset() + (this.columns() - 1) * ENGINE.dx + ENGINE.r + 40,
        )
      : CONTROLLER.x + this.offset() + CONTROLLER.r + 60,
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
    // Without engines, the Controller server processes scan themselves, in their own slots
    if (!this.engines().length) {
      for (const instance of this.data().controllers ?? []) {
        const scans = scansOf(instance);
        totals.files += scans.files;
        totals.activeCodebase += scans.codebase;
        totals.activeFragment += scans.fragment;
        totals.capacityCodebase += scans.codebase_slots;
        totals.capacityFragment += scans.fragment_slots;
      }
    }
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
      const column = Math.floor(index / ENGINE.perColumn);
      const rows = Math.min(engines.length, ENGINE.perColumn);
      const stagger = this.columns() > 1 ? ENGINE.rowGap / 2 : 0;
      const firstY = (this.height() - ((rows - 1) * ENGINE.rowGap + stagger)) / 2;
      const x = ENGINE.x0 + this.offset() + column * ENGINE.dx;
      const y =
        firstY + (index % ENGINE.perColumn) * ENGINE.rowGap + (column % 2 ? ENGINE.rowGap / 2 : 0);
      // Enter the engine from the left, from the closest Controller server
      const end: Point = { x: x - ENGINE.r, y };
      const start = controllerEdge(end, this.closestController(y));
      const pull = { x: end.x - 70, y: end.y };
      const used = usedSlots(engine);
      const capacity = engine.codebase_slots + engine.fragment_slots;
      const busyCodebase = engine.processing_codebase_scans > 0;
      const busyFragment = engine.processing_fragment_scans > 0;
      return {
        engine,
        label: shortName(engine.name),
        x,
        y,
        labelY: y + ENGINE.r + 22,
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

  /** Link of each MCP server to the closest Controller server, in the order of the servers. */
  private readonly mcpOutPaths = computed(() =>
    this.mcpServers().map((_, index) => {
      const y = this.mcpYs()[index];
      const outStart: Point = { x: MCP.x + MCP.r, y };
      const outEnd = controllerEdge(outStart, this.closestController(y));
      return `M${f(outStart.x)},${f(y)} C${f(outStart.x + 60)},${f(y)} ${f(outEnd.x - 50)},${f(outEnd.y)} ${f(outEnd.x)},${f(outEnd.y)}`;
    }),
  );

  /**
   * The dots of the requests running along ``path`` to the MCP server ``mcpNumber``, one per
   * family: a code scan goes on through the server (under its circle) to the Controller server
   * when it delegates scan_code, so that one dot goes from the agent to the MCP server, then to
   * the Controller server; the other requests end at the MCP server.
   */
  private requestDots(path: string, mcpNumber: number, processing: Counts): Dot[] {
    const instance = this.mcpServers()[mcpNumber - 1];
    const out = this.mcpOutPaths()[mcpNumber - 1];
    return FAMILIES.filter((family) => processing[family] > 0).map((kind, index) => ({
      kind,
      path: kind === 'code' && instance?.delegated && out ? `${path} L${out.slice(1)}` : path,
      begin: `${index * DOT_STAGGER}s`,
    }));
  }

  /** The agents seen lately, each linked to its MCP server; the others in a "+N" circle. */
  readonly agentNodes = computed<AgentNode[]>(() => {
    const agents = this.agents();
    const ys = this.agentYs();
    const link = (y: number, mcpNumber: number): string => {
      const start: Point = { x: SOURCE.x + AGENT.r, y };
      const endY = this.mcpYs()[mcpNumber - 1];
      const end: Point = { x: MCP.x - MCP.r, y: endY };
      return `M${f(start.x)},${f(y)} C${f(start.x + 40)},${f(y)} ${f(end.x - 40)},${f(endY)} ${f(end.x)},${f(endY)}`;
    };
    // The most recent agents, stacked in the order of their MCP servers so that no two links
    // cross, then by client: a circle keeps its place from one reload to the next
    const shown = (
      agents.length > MAX_AGENT_NODES ? agents.slice(0, MAX_AGENT_NODES) : [...agents]
    ).sort(
      (left, right) =>
        left.mcpNumber - right.mcpNumber ||
        left.agent.client.localeCompare(right.agent.client) ||
        left.agent.id.localeCompare(right.agent.id),
    );
    const nodes: AgentNode[] = shown.map(({ agent, mcpNumber }, index) => {
      const processing = processingOf(agent);
      const total = totalOf(processing);
      const path = link(ys[index], mcpNumber);
      return {
        id: `${mcpNumber}:${agent.id}`,
        agent,
        mcpNumber,
        more: 0,
        label: shortName(agent.client),
        titleKey: 'scanEngines.flowAgentTitle',
        titleParams: {
          client: agent.client,
          version: agent.client_version,
          number: mcpNumber,
          time: new Date(agent.last_seen).toLocaleTimeString(),
        },
        processing,
        total,
        arcs: shareArcs(this.agentRing, processing),
        x: SOURCE.x,
        y: ys[index],
        paths: [path],
        dots: this.requestDots(path, mcpNumber, processing),
        busy: total > 0,
      };
    });
    const rest = agents.slice(MAX_AGENT_NODES);
    if (rest.length) {
      const y = ys[shown.length];
      const processing = sumOf(rest.map((item) => processingOf(item.agent)));
      const total = totalOf(processing);
      // One dot per server and family, with the requests of the agents of that server
      const servers = [...new Set(rest.map((item) => item.mcpNumber))];
      nodes.push({
        id: 'more',
        agent: null,
        mcpNumber: 0,
        more: rest.length,
        label: '',
        titleKey: 'scanEngines.flowMoreAgentsTitle',
        titleParams: { count: rest.length },
        processing,
        total,
        arcs: shareArcs(this.agentRing, processing),
        x: SOURCE.x,
        y,
        paths: servers.map((n) => link(y, n)),
        dots: servers.flatMap((n) =>
          this.requestDots(
            link(y, n),
            n,
            sumOf(
              rest.filter((item) => item.mcpNumber === n).map((item) => processingOf(item.agent)),
            ),
          ),
        ),
        busy: total > 0,
      });
    }
    return nodes;
  });

  /** The MCP servers, the agents linked to each, each linked to the closest Controller server. */
  readonly mcpNodes = computed<McpNode[]>(() =>
    this.mcpServers().map((instance, index) => {
      const y = this.mcpYs()[index];
      const agents: Point = { x: SOURCE.x + AGENT.r, y: SOURCE.ys[1] };
      const inEnd: Point = { x: MCP.x - MCP.r, y };
      // From the "Agents" circle, when the MCP servers name no agent (the agents link otherwise)
      const inPath = this.agentNodes().length
        ? ''
        : `M${f(agents.x)},${f(agents.y)} C${f(agents.x + 40)},${f(agents.y)} ${f(inEnd.x - 40)},${f(y)} ${f(inEnd.x)},${f(y)}`;
      const processing = processingOf(instance);
      const total = totalOf(processing);
      return {
        instance,
        number: index + 1,
        x: MCP.x,
        y,
        r: MCP.r,
        labelY: y + MCP.r + 20,
        inPath,
        outPath: this.mcpOutPaths()[index],
        processing,
        total,
        arcs: shareArcs(this.mcpRing, processing),
        dots: inPath ? this.requestDots(inPath, index + 1, processing) : [],
        busy: total > 0,
        outBusy: instance.delegated && processing.code > 0,
        agentCount: instance.agents?.length ?? 0,
      };
    }),
  );

  readonly sources = computed<SourceNode[]>(() => {
    const totals = this.totals();
    const relayed = this.mcpServers().length > 0;
    // One circle per agent replaces the "Agents" circle when the MCP servers name them
    const kinds = this.agentNodes().length
      ? (['codebase'] as const)
      : (['codebase', 'fragment'] as const);
    return kinds.map((kind, index) => {
      const y = SOURCE.ys[index];
      const r = kind === 'codebase' ? SOURCE.r : AGENT.r;
      const start: Point = { x: SOURCE.x + r, y };
      const end = controllerEdge({ x: SOURCE.x, y }, this.closestController(y));
      return {
        kind,
        x: SOURCE.x,
        y,
        r,
        labelY: index === 0 ? y - r - 12 : y + r + 20,
        active: kind === 'codebase' ? totals.activeCodebase : totals.activeFragment,
        capacity: kind === 'codebase' ? totals.capacityCodebase : totals.capacityFragment,
        arcs: ringArcs(
          r - RING_INSET,
          kind === 'codebase' ? totals.activeCodebase : 0,
          kind === 'fragment' ? totals.activeFragment : 0,
          Math.max(
            kind === 'codebase' ? totals.capacityCodebase : totals.capacityFragment,
            kind === 'codebase' ? totals.activeCodebase : totals.activeFragment,
          ),
        ),
        // The fragments reach the Controller server through the MCP servers, when any is running
        path:
          kind === 'fragment' && relayed
            ? ''
            : `M${f(start.x)},${f(start.y)} C${f(start.x + 70)},${f(y)} ${f(end.x - 50)},${f(end.y)} ${f(end.x)},${f(end.y)}`,
        // The pipelines send their files to the Controller server, with or without engines
        busy:
          kind === 'codebase'
            ? totals.busyCodebase || this.pipelineSent() > 0
            : totals.busyFragment,
      };
    });
  });
}
