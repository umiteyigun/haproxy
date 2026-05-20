import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from 'primeng/button';
import { TableModule } from 'primeng/table';
import { DialogModule } from 'primeng/dialog';
import { InputTextModule } from 'primeng/inputtext';
import { SelectModule } from 'primeng/select';
import { TagModule } from 'primeng/tag';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ToolbarModule } from 'primeng/toolbar';
import { TabsModule } from 'primeng/tabs';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { TooltipModule } from 'primeng/tooltip';
import { MessageService, ConfirmationService } from 'primeng/api';
import { PortForwardService } from '@/app/core/services/port-forward.service';
import { WafService } from '@/app/core/services/waf.service';
import { PortForwarding } from '@/app/core/models';

@Component({
    selector: 'app-port-forward',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, DialogModule, InputTextModule, IconFieldModule, InputIconModule, SelectModule, TagModule, ToastModule, ConfirmDialogModule, ToolbarModule, TabsModule, ProgressSpinnerModule, TooltipModule],
    templateUrl: './port-forward.html'
})
export class PortForwardPage implements OnInit {
    private service = inject(PortForwardService);
    private wafService = inject(WafService);
    private msg = inject(MessageService);
    private confirm = inject(ConfirmationService);

    protocolOptions = [
        { label: 'TCP', value: 'tcp' },
        { label: 'HTTP', value: 'http' }
    ];

    filterText = '';
    globalFilterFields = ['name', 'backend_host', 'protocol'];

    rules = signal<PortForwarding[]>([]);
    loading = signal(true);
    saving = signal(false);
    editMode = signal(false);
    dialogVisible = false;
    editId: number | null = null;

    // Global WAF signals
    blacklist = signal<string[]>([]);
    loadingBlacklist = signal(false);
    savingBlacklist = signal(false);
    newBlacklistEntry = '';
    filterBlacklist = '';

    badUserAgents = signal<string[]>([]);
    loadingUserAgents = signal(false);
    savingUserAgents = signal(false);
    newUserAgent = '';
    filterUserAgents = '';

    form = this.emptyForm();

    emptyForm() {
        return { name: '', frontend_port: 0, backend_host: '', backend_port: 0, protocol: 'tcp' as 'tcp' | 'udp' };
    }

    async ngOnInit() {
        await this.load();
        await this.loadGlobalWaf();
    }

    async load() {
        try {
            this.loading.set(true);
            const data = await this.service.getRules();
            this.rules.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kurallar yuklenemedi' });
        } finally {
            this.loading.set(false);
        }
    }

    async loadGlobalWaf() {
        await Promise.all([this.loadBlacklist(), this.loadUserAgents()]);
    }

    async loadBlacklist() {
        this.loadingBlacklist.set(true);
        try {
            const res = await this.wafService.getGlobalList('ip_blacklist');
            this.blacklist.set(res.entries);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'IP kara listesi yuklenemedi' });
        } finally {
            this.loadingBlacklist.set(false);
        }
    }

    async addBlacklistEntry() {
        const entry = this.newBlacklistEntry.trim();
        if (!entry) return;
        this.savingBlacklist.set(true);
        try {
            const res = await this.wafService.addGlobalEntry('ip_blacklist', entry);
            this.blacklist.set(res.entries);
            this.newBlacklistEntry = '';
            this.msg.add({ severity: 'success', summary: 'Eklendi', detail: entry + ' kara listeye eklendi' });
        } catch (err: any) {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: err?.error?.error || 'Eklenemedi' });
        } finally {
            this.savingBlacklist.set(false);
        }
    }

    deleteBlacklistEntry(entry: string) {
        this.confirm.confirm({
            message: '"' + entry + '" adresini kara listeden kaldirmak istediginize emin misiniz?',
            header: 'Kaldirma Onayi',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    const res = await this.wafService.deleteGlobalEntry('ip_blacklist', entry);
                    this.blacklist.set(res.entries);
                    this.msg.add({ severity: 'success', summary: 'Kaldirildi', detail: entry + ' kara listeden kaldirildi' });
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kaldirma basarisiz' });
                }
            }
        });
    }

    async loadUserAgents() {
        this.loadingUserAgents.set(true);
        try {
            const res = await this.wafService.getGlobalList('bad_useragents');
            this.badUserAgents.set(res.entries);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'User-Agent listesi yuklenemedi' });
        } finally {
            this.loadingUserAgents.set(false);
        }
    }

    async addUserAgent() {
        const entry = this.newUserAgent.trim();
        if (!entry) return;
        this.savingUserAgents.set(true);
        try {
            const res = await this.wafService.addGlobalEntry('bad_useragents', entry);
            this.badUserAgents.set(res.entries);
            this.newUserAgent = '';
            this.msg.add({ severity: 'success', summary: 'Eklendi', detail: 'User-Agent eklendi' });
        } catch (err: any) {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: err?.error?.error || 'Eklenemedi' });
        } finally {
            this.savingUserAgents.set(false);
        }
    }

    deleteUserAgent(entry: string) {
        this.confirm.confirm({
            message: '"' + entry + '" user-agenti engellenmis listeden kaldirmak istediginize emin misiniz?',
            header: 'Kaldirma Onayi',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    const res = await this.wafService.deleteGlobalEntry('bad_useragents', entry);
                    this.badUserAgents.set(res.entries);
                    this.msg.add({ severity: 'success', summary: 'Kaldirildi', detail: 'User-Agent listeden kaldirildi' });
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kaldirma basarisiz' });
                }
            }
        });
    }

    filteredBlacklist() {
        const q = this.filterBlacklist.toLowerCase();
        return q ? this.blacklist().filter(e => e.toLowerCase().includes(q)) : this.blacklist();
    }

    filteredUserAgents() {
        const q = this.filterUserAgents.toLowerCase();
        return q ? this.badUserAgents().filter(e => e.toLowerCase().includes(q)) : this.badUserAgents();
    }

    openNew() {
        this.form = this.emptyForm();
        this.editMode.set(false);
        this.editId = null;
        this.dialogVisible = true;
    }

    editRule(rule: PortForwarding) {
        this.form = { name: rule.name, frontend_port: rule.frontend_port, backend_host: rule.backend_host, backend_port: rule.backend_port, protocol: rule.protocol || 'tcp' };
        this.editMode.set(true);
        this.editId = rule.id ?? null;
        this.dialogVisible = true;
    }

    async save() {
        if (!this.form.name || !this.form.backend_host) {
            this.msg.add({ severity: 'warn', summary: 'Uyari', detail: 'Isim ve hedef host zorunludur' });
            return;
        }
        this.saving.set(true);
        try {
            if (this.editMode() && this.editId !== null) {
                await this.service.updateRule(this.editId, this.form);
                this.msg.add({ severity: 'success', summary: 'Basarili', detail: 'Guncellendi' });
            } else {
                await this.service.createRule(this.form);
                this.msg.add({ severity: 'success', summary: 'Basarili', detail: 'Olusturuldu' });
            }
            this.dialogVisible = false;
            await this.load();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kayit basarisiz' });
        } finally {
            this.saving.set(false);
        }
    }

    deleteRule(rule: PortForwarding) {
        this.confirm.confirm({
            message: '"' + rule.name + '" kurali silmek istediginize emin misiniz?',
            header: 'Silme Onayi',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    await this.service.deleteRule(rule.id!);
                    this.msg.add({ severity: 'success', summary: 'Silindi' });
                    await this.load();
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Silme basarisiz' });
                }
            }
        });
    }
}