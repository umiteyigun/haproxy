import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MenuItem } from 'primeng/api';
import { AppMenuitem } from './app.menuitem';

@Component({
    selector: 'app-menu',
    standalone: true,
    imports: [CommonModule, AppMenuitem, RouterModule],
    templateUrl: './app.menu.html',
})
export class AppMenu {
    model: MenuItem[] = [];

    ngOnInit() {
        this.model = [
            {
                label: 'Genel',
                items: [{ label: 'Dashboard', icon: 'pi pi-fw pi-home', routerLink: ['/'] }]
            },
            {
                label: 'Yük Dengeleme',
                items: [
                    { label: 'Ingress Kuralları', icon: 'pi pi-fw pi-sitemap', routerLink: ['/ingress'] },
                    { label: 'Port Yönlendirme', icon: 'pi pi-fw pi-arrows-h', routerLink: ['/port-forwarding'] }
                ]
            },
            {
                label: 'SSL / TLS',
                items: [
                    { label: 'Sertifikalar', icon: 'pi pi-fw pi-shield', routerLink: ['/ssl'] }
                ]
            },
            {
                label: 'Güvenlik',
                items: [
                    { label: 'Guard (IP Ban / Whitelist)', icon: 'pi pi-fw pi-ban', routerLink: ['/guard'] },
                    { label: 'WAF Kuralları', icon: 'pi pi-fw pi-lock', routerLink: ['/waf'] }
                ]
            },
            {
                label: 'İzleme',
                items: [
                    { label: 'Aktif Bağlantılar', icon: 'pi pi-fw pi-wifi', routerLink: ['/connections'] },
                    { label: 'Trafik Logları', icon: 'pi pi-fw pi-list', routerLink: ['/logs'] }
                ]
            },
            {
                label: 'Yönetim',
                items: [
                    { label: 'Kullanıcılar', icon: 'pi pi-fw pi-users', routerLink: ['/members'] },
                    { label: 'Terminal', icon: 'pi pi-fw pi-desktop', routerLink: ['/terminal'] }
                ]
            }
        ];
    }
}
