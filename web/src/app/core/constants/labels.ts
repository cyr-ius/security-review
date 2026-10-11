import { FindingStatus, Severity } from '../models/api.models';

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
