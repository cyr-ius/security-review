import { MessageKey } from '../i18n/messages';
import {
  FindingStatus,
  Permission,
  ReviewType,
  Role,
  Severity,
  TokenRole,
} from '../models/api.models';

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
  user: { label: 'role.user', icon: 'bi-person-fill' },
  mcp: { label: 'role.mcp', icon: 'bi-plug-fill' },
  api: { label: 'role.api', icon: 'bi-key-fill' },
  ci: { label: 'role.ci', icon: 'bi-gear-wide-connected' },
};

/** What a token is used for, by role: the MCP server, a CI/CD pipeline or the administration. */
export const TOKEN_ROLE_LABELS: Record<TokenRole, MessageKey> = {
  mcp: 'tokenRole.mcp',
  api: 'tokenRole.api',
  admin: 'tokenRole.admin',
  ci: 'tokenRole.ci',
};

/** Message keys of the name and of the description of each permission, in display order. */
export const PERMISSION_META: Record<Permission, { label: MessageKey; help: MessageKey }> = {
  'reports.read': { label: 'permission.reportsRead', help: 'permission.reportsReadHelp' },
  'findings.triage': { label: 'permission.findingsTriage', help: 'permission.findingsTriageHelp' },
  'rules.manage': { label: 'permission.rulesManage', help: 'permission.rulesManageHelp' },
  'standards.manage': {
    label: 'permission.standardsManage',
    help: 'permission.standardsManageHelp',
  },
  'tokens.manage': { label: 'permission.tokensManage', help: 'permission.tokensManageHelp' },
  'settings.manage': { label: 'permission.settingsManage', help: 'permission.settingsManageHelp' },
  'users.manage': { label: 'permission.usersManage', help: 'permission.usersManageHelp' },
  'audit.read': { label: 'permission.auditRead', help: 'permission.auditReadHelp' },
  'projects.create': {
    label: 'permission.projectsCreate',
    help: 'permission.projectsCreateHelp',
  },
  'mcp_tokens.create': {
    label: 'permission.mcpTokensCreate',
    help: 'permission.mcpTokensCreateHelp',
  },
};

/** Permissions limited to projects (the others concern the whole controller). */
export const SCOPED_PERMISSIONS: ReadonlySet<Permission> = new Set([
  'reports.read',
  'findings.triage',
]);
