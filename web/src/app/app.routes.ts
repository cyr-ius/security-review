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
        path: 'projects/:project/findings',
        title: 'projectFindings.title',
        loadComponent: () =>
          import('./features/projects/project-findings/project-findings.component').then(
            (m) => m.ProjectFindingsComponent,
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
          import('./features/account/account.component').then((m) => m.AccountComponent),
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
          import('./features/audit/audit-log.component').then((m) => m.AuditLogComponent),
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
      { path: 'settings', pathMatch: 'full', redirectTo: 'settings/language' },
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
        path: 'settings/language',
        title: 'settings.languageTitle',
        canActivate: [permissionGuard('settings.manage')],
        loadComponent: () =>
          import('./features/settings/language-settings/language-settings.component').then(
            (m) => m.LanguageSettingsComponent,
          ),
      },
      {
        path: 'settings/proxy',
        title: 'settings.proxyTitle',
        canActivate: [permissionGuard('settings.manage')],
        loadComponent: () =>
          import('./features/settings/proxy-settings/proxy-settings.component').then(
            (m) => m.ProxySettingsComponent,
          ),
      },
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
