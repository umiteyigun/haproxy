import { Component, computed, effect, inject, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AppTopbar } from './app.topbar';
import { AppSidebar } from './app.sidebar';
import { AppFooter } from './app.footer';
import { LayoutService } from '@/app/layout/service/layout.service';
import { AuthService } from '@/app/core/services/auth.service';

@Component({
    selector: 'app-layout',
    standalone: true,
    imports: [CommonModule, AppTopbar, AppSidebar, RouterModule, AppFooter],
    templateUrl: './app.layout.html'
})
export class AppLayout implements OnInit, OnDestroy {
    layoutService = inject(LayoutService);
    private authService = inject(AuthService);
    private tokenCheckInterval: any;

    constructor() {
        effect(() => {
            const state = this.layoutService.layoutState();
            if (state.mobileMenuActive) {
                document.body.classList.add('blocked-scroll');
            } else {
                document.body.classList.remove('blocked-scroll');
            }
        });
    }

    ngOnInit() {
        // Token geçerlilik kontrolü: her 60 saniyede bir kontrol et
        this.tokenCheckInterval = setInterval(() => {
            if (!this.authService.isAuthenticated()) {
                this.authService.logout();
            }
        }, 60_000);
    }

    ngOnDestroy() {
        clearInterval(this.tokenCheckInterval);
    }

    containerClass = computed(() => {
        const config = this.layoutService.layoutConfig();
        const state = this.layoutService.layoutState();
        return {
            'layout-overlay': config.menuMode === 'overlay',
            'layout-static': config.menuMode === 'static',
            'layout-static-inactive': state.staticMenuDesktopInactive && config.menuMode === 'static',
            'layout-overlay-active': state.overlayMenuActive,
            'layout-mobile-active': state.mobileMenuActive
        };
    })
}
