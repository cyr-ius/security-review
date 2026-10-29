import { Routes } from '@angular/router';

// Each title is a message key, translated by I18nTitleStrategy
import { authGuard } from './core/guards/auth.guard';
import { backendGuard } from './core/guards/backend.guard';
import { passwordChangeGuard } from './core/guards/password-change.guard';
import { permissionGuard } from './core/guards/permission.guard';

export const routes: Routes = [
  {
    path: 'unavailable',
    title: 'unavailable.title',
    loadComponent: () =>
      import('./features/unavailable/backend-unavailable.component').then(
        (m) => m.BackendUnavailableComponent,
      ),
  },
  {
    path: 'login',
    title: 'login.title',
    canActivate: [backendGuard],
    loadComponent: () => import('./features/login/login.component').then((m) => m.LoginComponent),
  },
  {
    // Consent screen of the OAuth login of the MCP clients, outside the layout
    path: 'oauth/authorize',
    title: 'oauth.title',
    canActivate: [backendGuard, authGuard],
    loadComponent: () =>
      import('./features/oauth/oauth-consent.component').then((m) => m.OAuthConsentComponent),
  },
  {
    path: '',
    canActivate: [backendGuard, authGuard],
    canActivateChild: [passwordChangeGuard],
    loadComponent: () => import('./layout/layout.component').then((m) => m.LayoutComponent),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'projects' },
      {
        path: 'projects',
        title: 'layout.projects',
        loadComponent: () =>
          import('./features/projects/project-list/project-list.component').then(
            (m) => m.ProjectListComponent,
          ),
      },
      {
        path: 'projects/:project',
        title: 'reportTable.project',
        loadComponent: () =>
          import('./features/projects/project-detail/project-detail.component').then(
            (m) => m.ProjectDetailComponent,
          ),
      },
      {
        path: 'findings',
        canActivate: [permissionGuard('reports.read')],
        title: 'projectFindings.title',
        loadComponent: () =>
          import('./features/projects/project-findings/project-findings.component').then(
            (m) => m.ProjectFindingsComponent,
          ),
      },
      {
        path: 'projects/:project/findings',
        title: 'projectFindings.title',
        loadComponent: () =>
          import('./features/projects/project-findings/project-findings.component').then(
            (m) => m.ProjectFindingsComponent,
          ),
      },
      {
        path: 'risk-acceptances',
        canActivate: [permissionGuard('reports.read')],
        title: 'acceptances.title',
        loadComponent: () =>
          import('./features/acceptances/risk-acceptance-list/risk-acceptance-list.component').then(
            (m) => m.RiskAcceptanceListComponent,
          ),
      },
      {
        path: 'projects/:project/risk-acceptances',
        title: 'acceptances.title',
        loadComponent: () =>
          import('./features/acceptances/risk-acceptance-list/risk-acceptance-list.component').then(
            (m) => m.RiskAcceptanceListComponent,
          ),
      },
      {
        path: 'reports',
        title: 'layout.reports',
        loadComponent: () =>
          import('./features/reports/report-list/report-list.component').then(
            (m) => m.ReportListComponent,
          ),
      },
      {
        path: 'rules',
        title: 'layout.rules',
        canActivate: [permissionGuard('rules.manage')],
        loadComponent: () =>
          import('./features/rules/rule-list/rule-list.component').then((m) => m.RuleListComponent),
      },
      {
        path: 'checklists',
        title: 'layout.checklists',
        canActivate: [permissionGuard('rules.manage')],
        loadComponent: () =>
          import('./features/checklists/checklist-list/checklist-list.component').then(
            (m) => m.ChecklistListComponent,
          ),
      },
      {
        path: 'standards',
        canActivate: [permissionGuard('standards.manage')],
        title: 'layout.standards',
        loadComponent: () =>
          import('./features/standards/standard-list/standard-list.component').then(
            (m) => m.StandardListComponent,
          ),
      },
      {
        path: 'about',
        title: 'about.title',
        loadComponent: () =>
          import('./features/about/about.component').then((m) => m.AboutComponent),
      },
      {
        path: 'account',
        title: 'layout.account',
        loadComponent: () =>
          import('./features/account/account-page/account.component').then(
            (m) => m.AccountComponent,
          ),
      },
      {
        path: 'users',
        title: 'layout.users',
        canActivate: [permissionGuard('users.manage')],
        loadComponent: () =>
          import('./features/users/user-list.component').then((m) => m.UserListComponent),
      },
      {
        path: 'tokens',
        title: 'layout.tokens',
        canActivate: [permissionGuard('tokens.manage')],
        loadComponent: () =>
          import('./features/tokens/project-token-list.component').then(
            (m) => m.ProjectTokenListComponent,
          ),
      },
      {
        path: 'audit',
        title: 'layout.audit',
        canActivate: [permissionGuard('audit.read')],
        loadComponent: () =>
          import('./features/audit/audit-log/audit-log.component').then((m) => m.AuditLogComponent),
      },
      {
        path: 'groups',
        title: 'layout.groups',
        canActivate: [permissionGuard('users.manage')],
        loadComponent: () =>
          import('./features/access/group-list/group-list.component').then(
            (m) => m.GroupListComponent,
          ),
      },
      // Former single settings page, split into the three pages below
      { path: 'settings', pathMatch: 'full', redirectTo: 'settings/general' },
      {
        path: 'roles',
        title: 'layout.roles',
        canActivate: [permissionGuard('users.manage')],
        loadComponent: () =>
          import('./features/access/role-list/role-list.component').then(
            (m) => m.RoleListComponent,
          ),
      },
      {
        path: 'sso',
        title: 'layout.sso',
        canActivate: [permissionGuard('users.manage')],
        loadComponent: () =>
          import('./features/sso/sso-page/sso-page.component').then((m) => m.SsoPageComponent),
      },
      // Former address of the OIDC page
      { path: 'role-mappings', pathMatch: 'full', redirectTo: 'sso' },
      {
        path: 'settings/general',
        title: 'settings.generalTitle',
        canActivate: [permissionGuard('settings.manage')],
        loadComponent: () =>
          import('./features/settings/general-settings/general-settings.component').then(
            (m) => m.GeneralSettingsComponent,
          ),
      },
      // Former address of the report language, now on the General page
      { path: 'settings/language', pathMatch: 'full', redirectTo: 'settings/general' },
      // Former address of the outgoing proxy, now on the General page
      { path: 'settings/proxy', pathMatch: 'full', redirectTo: 'settings/general' },
      {
        path: 'settings/connectors',
        title: 'connectors.title',
        canActivate: [permissionGuard('settings.manage')],
        loadComponent: () =>
          import('./features/settings/connectors/connectors.component').then(
            (m) => m.ConnectorsComponent,
          ),
      },
      // Former address of the Connectors screen
      {
        path: 'settings/advisories',
        title: 'settings.osvTitle',
        canActivate: [permissionGuard('settings.manage')],
        loadComponent: () =>
          import('./features/settings/advisory-settings/advisory-settings.component').then(
            (m) => m.AdvisorySettingsComponent,
          ),
      },
      {
        path: 'reports/:id',
        title: 'common.reportPage',
        loadComponent: () =>
          import('./features/reports/report-detail/report-detail.component').then(
            (m) => m.ReportDetailComponent,
          ),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
