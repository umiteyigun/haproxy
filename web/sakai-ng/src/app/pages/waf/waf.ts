import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from 'primeng/button';
import { TableModule } from 'primeng/table';
import { DialogModule } from 'primeng/dialog';
import { InputTextModule } from 'primeng/inputtext';
import { TextareaModule } from 'primeng/textarea';
import { TagModule } from 'primeng/tag';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ToolbarModule } from 'primeng/toolbar';
import { TabsModule } from 'primeng/tabs';
import { ToggleSwitchModule } from 'primeng/toggleswitch';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { MessageModule } from 'primeng/message';
import { TooltipModule } from 'primeng/tooltip';
import { SelectModule } from 'primeng/select';
import { MessageService, ConfirmationService } from 'primeng/api';
import { WafService } from '@/app/core/services/waf.service';
import { WafRule, WafEvent } from '@/app/core/models';

@Component({
    selector: 'app-waf',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, DialogModule, InputTextModule, IconFieldModule, InputIconModule, TextareaModule, TagModule, ToastModule, ConfirmDialogModule, ToolbarModule, TabsModule, ToggleSwitchModule, ProgressSpinnerModule, MessageModule, TooltipModule, SelectModule],
    templateUrl: './waf.html'
})
export class WafPage implements OnInit {
    private service = inject(WafService);
    private msg = inject(MessageService);
    private confirm = inject(ConfirmationService);

    filterTextRules = '';
    globalFilterFieldsRules = ['filename'];
    filterTextCrs = '';
    globalFilterFieldsCrs = ['filename'];

    rules = signal<WafRule[]>([]);
    crsRules = signal<any[]>([]);
    wafEvents = signal<WafEvent[]>([]);
    loadingRules = signal(true);
    loadingCrs = signal(true);
    loadingEvents = signal(false);
    saving = signal(false);
    savingCrs = signal(false);
    reloading = signal(false);
    editMode = signal(false);
    loadingCrsContent = signal(false);
    eventsLimit = 100;
    eventsMessage = '';
    dialogVisible = false;
    crsDialogVisible = false;
    editFilename: string | null = null;
    crsEditFilename = '';
    crsEditContent = '';

    form = this.emptyForm();

    emptyForm() {
        return { filename: '', content: '' };
    }

    async ngOnInit() {
        await Promise.all([this.loadRules(), this.loadCrs()]);
        this.loadEvents();
    }

    async loadRules() {
        try {
            this.loadingRules.set(true);
            const data = await this.service.getRules();
            this.rules.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kurallar y�klenemedi' });
        } finally {
            this.loadingRules.set(false);
        }
    }

    async loadCrs() {
        try {
            this.loadingCrs.set(true);
            const data = await this.service.getCrsRules();
            this.crsRules.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'CRS kurallar� y�klenemedi' });
        } finally {
            this.loadingCrs.set(false);
        }
    }

    openNew() {
        this.form = this.emptyForm();
        this.editMode.set(false);
        this.editFilename = null;
        this.dialogVisible = true;
    }

    editRule(rule: WafRule) {
        this.form = { filename: rule.filename, content: rule.content || '' };
        this.editMode.set(true);
        this.editFilename = rule.filename;
        this.dialogVisible = true;
    }

    async save() {
        if (!this.form.filename || !this.form.content) {
            this.msg.add({ severity: 'warn', summary: 'Uyar�', detail: 'Dosya ad� ve i�erik zorunludur' });
            return;
        }
        this.saving.set(true);
        try {
            if (this.editMode() && this.editFilename !== null) {
                await this.service.updateRule(this.editFilename, this.form.content);
                this.msg.add({ severity: 'success', summary: 'G�ncellendi' });
            } else {
                await this.service.createRule(this.form.filename, this.form.content);
                this.msg.add({ severity: 'success', summary: 'Olu�turuldu' });
            }
            this.dialogVisible = false;
            await this.loadRules();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kay�t ba�ar�s�z' });
        } finally {
            this.saving.set(false);
        }
    }

    deleteRule(rule: WafRule) {
        this.confirm.confirm({
            message: `"${rule.filename}" kural�n� silmek istedi�inize emin misiniz?`,
            header: 'Silme Onay�',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    await this.service.deleteRule(rule.filename);
                    this.msg.add({ severity: 'success', summary: 'Silindi' });
                    await this.loadRules();
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Silme ba�ar�s�z' });
                }
            }
        });
    }

    async toggleCrs(rule: any) {
        try {
            await this.service.toggleCrsRule(rule.filename, rule.enabled);
        } catch {
            rule.enabled = !rule.enabled;
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'CRS kural durumu değiştirilemedi' });
        }
    }

    async openEditCrs(rule: any) {
        this.crsEditFilename = rule.filename;
        this.crsEditContent = '';
        this.crsDialogVisible = true;
        this.loadingCrsContent.set(true);
        try {
            this.crsEditContent = await this.service.getCrsRuleContent(rule.filename);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'CRS kural içeriği yüklenemedi' });
            this.crsDialogVisible = false;
        } finally {
            this.loadingCrsContent.set(false);
        }
    }

    async saveCrs() {
        if (!this.crsEditContent) {
            this.msg.add({ severity: 'warn', summary: 'Uyarı', detail: 'İçerik boş olamaz' });
            return;
        }
        this.savingCrs.set(true);
        try {
            await this.service.updateCrsRule(this.crsEditFilename, this.crsEditContent);
            this.msg.add({ severity: 'success', summary: 'Kaydedildi', detail: "Değişikliklerin etkili olması için SPOA'yı yeniden başlatın" });
            this.crsDialogVisible = false;
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'CRS kuralı kaydedilemedi' });
        } finally {
            this.savingCrs.set(false);
        }
    }

    async reloadSpoa() {
        this.reloading.set(true);
        try {
            await this.service.reloadSpoa();
            this.msg.add({ severity: 'success', summary: 'SPOA Yenilendi' });
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'SPOA yenileme basarisiz' });
        } finally {
            this.reloading.set(false);
        }
    }

    async loadEvents() {
        this.loadingEvents.set(true);
        this.eventsMessage = '';
        try {
            const res = await this.service.getWafEvents(this.eventsLimit);
            this.wafEvents.set(res.events ?? []);
            if (res.message) this.eventsMessage = res.message;
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'WAF olayları yüklenemedi' });
        } finally {
            this.loadingEvents.set(false);
        }
    }

    eventSeverityTag(severity: string | undefined): 'danger' | 'warn' | 'info' | 'secondary' {
        if (!severity) return 'secondary';
        const s = severity.toUpperCase();
        if (s === 'CRITICAL' || s === 'ERROR' || s === 'ALERT') return 'danger';
        if (s === 'WARNING') return 'warn';
        if (s === 'NOTICE' || s === 'INFO') return 'info';
        return 'secondary';
    }
}
