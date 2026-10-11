import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';
import { adminGuard } from './core/guards/admin.guard';

export const routes: Routes = [
  {
    path: 'login',
    title: 'Connexion · Security Review',
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
        title: 'Projets · Security Review',
        loadComponent: () =>
          import('./features/projects/project-list/project-list.component').then(
            (m) => m.ProjectListComponent,
          ),
      },
      {
        path: 'projects/:project',
        title: 'Projet · Security Review',
        loadComponent: () =>
          import('./features/projects/project-detail/project-detail.component').then(
            (m) => m.ProjectDetailComponent,
          ),
      },
      {
        path: 'reports',
        title: 'Rapports · Security Review',
        loadComponent: () =>
          import('./features/reports/report-list/report-list.component').then(
            (m) => m.ReportListComponent,
          ),
      },
      {
        path: 'rules',
        title: 'Règles · Security Review',
        canActivate: [adminGuard],
        loadComponent: () =>
          import('./features/rules/rule-list/rule-list.component').then(
            (m) => m.RuleListComponent,
          ),
      },
      {
        path: 'reports/:id',
        title: 'Rapport · Security Review',
        loadComponent: () =>
          import('./features/reports/report-detail/report-detail.component').then(
            (m) => m.ReportDetailComponent,
          ),
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
