import { Finding, SEVERITY_RANK, Severity } from '../../core/models/api.models';

/** CWE of the vulnerable component findings of a dependency scan (deps/depscan.py). */
const VULNERABLE_COMPONENT_CWE = 'CWE-1395';
/** Evidence of such a finding: ``name==version (ecosystem)``. */
const EVIDENCE_RE = /^(.+)==(\S+) \((.+)\)$/;

/** Advisories of one vulnerable component (same project, package, version and manifest). */
export interface PackageGroup<T extends Finding> {
  key: string;
  /** ``name version``, as in the titles of its findings. */
  component: string;
  filePath: string | null;
  /** Worst severity of its findings. */
  severity: Severity;
  findings: T[];
  /** Open findings, and findings with a status proposed by an agent. */
  open: number;
  proposals: number;
}

/** A finding on its own, or the advisories of one package, at the place of the first one. */
export type FindingEntry<T extends Finding> =
  | { kind: 'finding'; key: string; finding: T }
  | { kind: 'package'; key: string; group: PackageGroup<T> };

function packageKey(finding: Finding): { key: string; component: string } | null {
  if (finding.category !== 'dependency' || finding.cwe !== VULNERABLE_COMPONENT_CWE) {
    return null;
  }
  const match = EVIDENCE_RE.exec(finding.evidence ?? '');
  if (!match) {
    return null;
  }
  const [, name, version, ecosystem] = match;
  // The findings of every project are listed together at /findings: one group per project
  const project = 'project' in finding ? String(finding.project) : '';
  return {
    key: `${project}|${ecosystem}|${name}|${version}|${finding.file_path ?? ''}`,
    component: `${name} ${version}`,
  };
}

/**
 * Gather the findings of the advisories of one vulnerable package: a release often fixes
 * many advisories at once, each one its own finding. The order of the list is kept (a group
 * takes the place of its first finding); a package with a single advisory stays a finding.
 */
export function groupByPackage<T extends Finding>(findings: readonly T[]): FindingEntry<T>[] {
  const groups = new Map<string, PackageGroup<T>>();
  for (const finding of findings) {
    const pkg = packageKey(finding);
    if (!pkg) {
      continue;
    }
    const group = groups.get(pkg.key);
    if (group) {
      group.findings.push(finding);
      if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[group.severity]) {
        group.severity = finding.severity;
      }
      group.open += finding.status === 'open' ? 1 : 0;
      group.proposals += finding.proposed_status ? 1 : 0;
    } else {
      groups.set(pkg.key, {
        key: pkg.key,
        component: pkg.component,
        filePath: finding.file_path,
        severity: finding.severity,
        findings: [finding],
        open: finding.status === 'open' ? 1 : 0,
        proposals: finding.proposed_status ? 1 : 0,
      });
    }
  }

  const entries: FindingEntry<T>[] = [];
  const placed = new Set<string>();
  for (const finding of findings) {
    const pkg = packageKey(finding);
    const group = pkg ? groups.get(pkg.key) : undefined;
    if (!group || group.findings.length < 2) {
      entries.push({ kind: 'finding', key: `finding-${finding.id}`, finding });
    } else if (!placed.has(group.key)) {
      placed.add(group.key);
      entries.push({ kind: 'package', key: `package-${group.key}`, group });
    }
  }
  return entries;
}
