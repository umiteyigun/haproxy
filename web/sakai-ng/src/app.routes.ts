import { Routes } from '@angular/router';
import { AppLayout } from './app/layout/component/app.layout';
import { authGuard } from './app/core/guards/auth.guard';

export const appRoutes: Routes = [
    { path: 'auth', loadChildren: () => import('./app/pages/auth/auth.routes') },
    {
        path: '',
        component: AppLayout,
        canActivate: [authGuard],
        children: [
            { path: '', loadComponent: () => import('./app/pages/dashboard/dashboard').then(m => m.Dashboard) },
            { path: 'ingress', loadComponent: () => import('./app/pages/ingress/ingress').then(m => m.IngressPage) },
            { path: 'port-forwarding', loadComponent: () => import('./app/pages/port-forward/port-forward').then(m => m.PortForwardPage) },
            { path: 'ssl', loadComponent: () => import('./app/pages/ssl/ssl').then(m => m.SslPage) },
            { path: 'guard', loadComponent: () => import('./app/pages/guard/guard').then(m => m.GuardPage) },
            { path: 'waf', loadComponent: () => import('./app/pages/waf/waf').then(m => m.WafPage) },
            { path: 'members', loadComponent: () => import('./app/pages/members/members').then(m => m.MembersPage) },
            { path: 'connections', loadComponent: () => import('./app/pages/connections/connections').then(m => m.ConnectionsPage) },
            { path: 'logs', loadComponent: () => import('./app/pages/logs/logs').then(m => m.LogsPage) },
            { path: 'terminal', loadComponent: () => import('./app/pages/terminal/terminal').then(m => m.TerminalPage) }
        ]
    },
    { path: 'notfound', loadComponent: () => import('./app/pages/notfound/notfound').then(m => m.Notfound) },
    { path: '**', redirectTo: '/notfound' }
];
