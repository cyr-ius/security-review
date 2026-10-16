import { MessageKey } from '../i18n/messages';
import { FindingStatus, ReviewType, Role, Severity } from '../models/api.models';

/** Message key and icon of each severity (color is never the only cue). */
export const SEVERITY_META: Record<Severity, { label: MessageKey; icon: string }> = {
  critical: { label: 'severity.critical', icon: 'bi-x-octagon-fill' },
  high: { label: 'severity.high', icon: 'bi-exclamation-triangle-fill' },
  medium: { label: 'severity.medium', icon: 'bi-exclamation-circle-fill' },
  low: { label: 'severity.low', icon: 'bi-info-circle-fill' },
  info: { label: 'severity.info', icon: 'bi-circle' },
};

/** Message key and icon of each finding status. */
export const STATUS_META: Record<FindingStatus, { label: MessageKey; icon: string }> = {
  open: { label: 'status.open', icon: 'bi-circle' },
  fixed: { label: 'status.fixed', icon: 'bi-check-circle-fill' },
  accepted: { label: 'status.accepted', icon: 'bi-shield-check' },
  false_positive: { label: 'status.false_positive', icon: 'bi-slash-circle' },
};

/** Message key and icon of each review type. */
export const REVIEW_TYPE_META: Record<ReviewType, { label: MessageKey; icon: string }> = {
  'security-review': { label: 'reviewType.security-review', icon: 'bi-shield-lock' },
  'api-security-review': { label: 'reviewType.api-security-review', icon: 'bi-hdd-network' },
  'configuration-review': { label: 'reviewType.configuration-review', icon: 'bi-gear' },
  'dependency-review': { label: 'reviewType.dependency-review', icon: 'bi-box-seam' },
  'codebase-review': { label: 'reviewType.codebase-review', icon: 'bi-folder2-open' },
  'code-scan': { label: 'reviewType.code-scan', icon: 'bi-terminal' },
  'dependency-scan': { label: 'reviewType.dependency-scan', icon: 'bi-terminal' },
  other: { label: 'reviewType.other', icon: 'bi-question-circle' },
};

/** Trend direction returned by the API. */
export const DIRECTION_META: Record<string, { label: MessageKey; icon: string }> = {
  improving: { label: 'direction.improving', icon: 'bi-arrow-down-right' },
  worsening: { label: 'direction.worsening', icon: 'bi-arrow-up-right' },
  stable: { label: 'direction.stable', icon: 'bi-arrow-right' },
  insufficient_data: { label: 'direction.insufficient_data', icon: 'bi-dash' },
};

/** Message key and icon of each role. */
export const ROLE_META: Record<Role, { label: MessageKey; icon: string }> = {
  admin: { label: 'role.admin', icon: 'bi-shield-fill-check' },
  triager: { label: 'role.triager', icon: 'bi-funnel-fill' },
  reader: { label: 'role.reader', icon: 'bi-eye-fill' },
  mcp: { label: 'role.mcp', icon: 'bi-plug-fill' },
};

/** What a token is used for, by role: the MCP server or the REST API (and its rights). */
export const TOKEN_ROLE_LABELS: Record<Role, MessageKey> = {
  mcp: 'tokenRole.mcp',
  reader: 'tokenRole.reader',
  triager: 'tokenRole.triager',
  admin: 'tokenRole.admin',
};
