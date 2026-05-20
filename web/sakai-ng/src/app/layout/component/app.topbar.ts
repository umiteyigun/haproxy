import { Component, inject } from '@angular/core';
import { MenuItem, ConfirmationService } from 'primeng/api';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { StyleClassModule } from 'primeng/styleclass';
import { AppConfigurator } from './app.configurator';
import { LayoutService } from '@/app/layout/service/layout.service';
import { AuthService } from '@/app/core/services/auth.service';
import { ButtonModule } from 'primeng/button';
import { ConfirmDialogModule } from 'primeng/confirmdialog';

@Component({
    selector: 'app-topbar',
    standalone: true,
    imports: [RouterModule, CommonModule, StyleClassModule, AppConfigurator, ButtonModule, ConfirmDialogModule],
    templateUrl: './app.topbar.html'
})
export class AppTopbar {
    items!: MenuItem[];

    layoutService = inject(LayoutService);
    authService = inject(AuthService);
    private confirmationService = inject(ConfirmationService);

    toggleDarkMode() {
        this.layoutService.layoutConfig.update((state) => ({
            ...state,
            darkTheme: !state.darkTheme
        }));
    }

    logout() {
        this.confirmationService.confirm({
            key: 'logout-confirm',
            message: 'Oturumu sonlandırmak istediğinize emin misiniz?',
            header: 'Çıkış Onayı',
            icon: 'pi pi-sign-out',
            acceptLabel: 'Evet, Çıkış Yap',
            rejectLabel: 'İptal',
            acceptButtonStyleClass: 'p-button-danger',
            accept: () => {
                this.authService.logout();
            }
        });
    }
}
