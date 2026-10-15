import { FindingStatus, Role, Severity } from '../models/api.models';

/** Display name and icon of each severity (color is never the only cue). */
export const SEVERITY_META: Record<Severity, { label: string; icon: string }> = {
  critical: { label: 'Critique', icon: 'bi-x-octagon-fill' },
  high: { label: 'Haute', icon: 'bi-exclamation-triangle-fill' },
  medium: { label: 'Moyenne', icon: 'bi-exclamation-circle-fill' },
  low: { label: 'Basse', icon: 'bi-info-circle-fill' },
  info: { label: 'Info', icon: 'bi-circle' },
};

/** Display name and icon of each finding status. */
export const STATUS_META: Record<FindingStatus, { label: string; icon: string }> = {
  open: { label: 'Ouvert', icon: 'bi-circle' },
  fixed: { label: 'Corrigé', icon: 'bi-check-circle-fill' },
  accepted: { label: 'Risque accepté', icon: 'bi-shield-check' },
  false_positive: { label: 'Faux positif', icon: 'bi-slash-circle' },
};

/** Trend direction returned by the API. */
export const DIRECTION_META: Record<string, { label: string; icon: string }> = {
  improving: { label: 'En amélioration', icon: 'bi-arrow-down-right' },
  worsening: { label: 'En dégradation', icon: 'bi-arrow-up-right' },
  stable: { label: 'Stable', icon: 'bi-arrow-right' },
  insufficient_data: { label: 'Pas assez de données', icon: 'bi-dash' },
};

/** Display name of each token role. */
export const ROLE_META: Record<Role, { label: string; icon: string }> = {
  admin: { label: 'Administrateur', icon: 'bi-shield-fill-check' },
  triager: { label: 'Triage', icon: 'bi-funnel-fill' },
  reader: { label: 'Lecture', icon: 'bi-eye-fill' },
  mcp: { label: 'MCP', icon: 'bi-plug-fill' },
};

/** What a token is used for, by role: the MCP server or the REST API (and its rights). */
export const TOKEN_ROLE_LABELS: Record<Role, string> = {
  mcp: 'MCP',
  reader: 'API REST — lecture seule',
  triager: 'API REST — lecture et triage',
  admin: 'MCP et API REST — administrateur',
};
