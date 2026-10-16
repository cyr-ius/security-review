import { Routes } from '@angular/router';

// Each title is a message key, translated by I18nTitleStrategy
import { authGuard } from './core/guards/auth.guard';
import { adminGuard } from './core/guards/admin.guard';

export const routes: Routes = [
  {
    path: 'login',
    title: 'login.title',
    loadComponent: () => import('./features/login/login.component').then((m) => m.LoginComponent),
  },
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./shared/components/layout/layout.component').then((m) => m.LayoutComponent),
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
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/rules/rule-list/rule-list.component').then((m) => m.RuleListComponent),
      },
      {
        path: 'checklists',
        title: 'layout.checklists',
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/checklists/checklist-list/checklist-list.component').then(
            (m) => m.ChecklistListComponent,
          ),
      },
      {
        path: 'standards',
        canActivate: [adminGuard],
        title: 'layout.standards',
        loadComponent: () =>
          import('./features/standards/standard-list/standard-list.component').then(
            (m) => m.StandardListComponent,
          ),
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
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/users/user-list.component').then((m) => m.UserListComponent),
      },
      {
        path: 'tokens',
        title: 'layout.tokens',
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/tokens/project-token-list.component').then(
            (m) => m.ProjectTokenListComponent,
          ),
      },
      {
        path: 'role-mappings',
        title: 'layout.sso',
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/role-mappings/role-mapping-list.component').then(
            (m) => m.RoleMappingListComponent,
          ),
      },
      {
        path: 'settings',
        title: 'layout.settings',
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/settings/settings.component').then((m) => m.SettingsComponent),
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
