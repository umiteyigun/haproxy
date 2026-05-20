import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from 'primeng/button';
import { TableModule } from 'primeng/table';
import { DialogModule } from 'primeng/dialog';
import { InputTextModule } from 'primeng/inputtext';
import { TagModule } from 'primeng/tag';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ToolbarModule } from 'primeng/toolbar';
import { TabsModule } from 'primeng/tabs';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { TooltipModule } from 'primeng/tooltip';
import { MessageService, ConfirmationService } from 'primeng/api';
import { SecurityService } from '@/app/core/services/security.service';
import { Ban } from '@/app/core/models';

@Component({
    selector: 'app-guard',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, DialogModule, InputTextModule, IconFieldModule, InputIconModule, TagModule, ToastModule, ConfirmDialogModule, ToolbarModule, TabsModule, TooltipModule],
    templateUrl: './guard.html'
})
export class GuardPage implements OnInit {
    private service = inject(SecurityService);
    private msg = inject(MessageService);
    private confirm = inject(ConfirmationService);

    bans = signal<Ban[]>([]);
    whitelist = signal<any[]>([]);
    guardOnline = signal<boolean | null>(null);
    loadingBans = signal(true);
    loadingWhitelist = signal(true);
    banLoading = signal(false);
    whitelistLoading = signal(false);

    manualBanIp = '';
    newWhitelistIp = '';

    filterTextBans = '';
    globalFilterFieldsBans = ['ip', 'reason'];
    filterTextWhitelist = '';
    globalFilterFieldsWhitelist = ['ip'];

    async ngOnInit() {
        await Promise.all([this.loadBans(), this.loadWhitelist()]);
    }

    async loadBans() {
        try {
            this.loadingBans.set(true);
            const data = await this.service.getBans();
            this.bans.set(data);
            this.guardOnline.set(true);
        } catch {
            this.guardOnline.set(false);
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Banlar y�klenemedi' });
        } finally {
            this.loadingBans.set(false);
        }
    }

    async loadWhitelist() {
        try {
            this.loadingWhitelist.set(true);
            const data = await this.service.getWhitelist();
            this.whitelist.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Whitelist y�klenemedi' });
        } finally {
            this.loadingWhitelist.set(false);
        }
    }

    async addBan() {
        if (!this.manualBanIp) return;
        this.banLoading.set(true);
        try {
            await this.service.manualBan(this.manualBanIp);
            this.msg.add({ severity: 'success', summary: 'Banl�', detail: `${this.manualBanIp} banland�` });
            this.manualBanIp = '';
            await this.loadBans();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Ban i�lemi ba�ar�s�z' });
        } finally {
            this.banLoading.set(false);
        }
    }

    unban(ban: Ban) {
        this.confirm.confirm({
            message: `${ban.ip} adresinin ban�n� kald�rmak istedi�inize emin misiniz?`,
            header: 'Unban Onay�',
            accept: async () => {
                try {
                    await this.service.unban(ban.ip);
                    this.msg.add({ severity: 'success', summary: 'Unban', detail: `${ban.ip} unban edildi` });
                    await this.loadBans();
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Unban ba�ar�s�z' });
                }
            }
        });
    }

    async addWhitelist() {
        if (!this.newWhitelistIp) return;
        this.whitelistLoading.set(true);
        try {
            await this.service.addToWhitelist(this.newWhitelistIp);
            this.msg.add({ severity: 'success', summary: 'Eklendi', detail: `${this.newWhitelistIp} whitelist'e eklendi` });
            this.newWhitelistIp = '';
            await this.loadWhitelist();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Ekleme ba�ar�s�z' });
        } finally {
            this.whitelistLoading.set(false);
        }
    }

    async removeWhitelist(item: any) {
        const ip = item.ip || item;
        try {
            await this.service.removeFromWhitelist(ip);
            this.msg.add({ severity: 'success', summary: 'Kald�r�ld�' });
            await this.loadWhitelist();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kald�rma ba�ar�s�z' });
        }
    }
}
