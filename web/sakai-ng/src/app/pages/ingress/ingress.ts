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
import { ToggleSwitchModule } from 'primeng/toggleswitch';
import { RadioButtonModule } from 'primeng/radiobutton';
import { TextareaModule } from 'primeng/textarea';
import { DividerModule } from 'primeng/divider';
import { MessageModule } from 'primeng/message';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { MessageService, ConfirmationService } from 'primeng/api';
import { IngressRuleService } from '@/app/core/services/ingress-rule.service';
import { SslService } from '@/app/core/services/ssl.service';
import { Rule, Certificate } from '@/app/core/models';

@Component({
    selector: 'app-ingress',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, DialogModule, InputTextModule, IconFieldModule, InputIconModule, SelectModule, TagModule, ToastModule, ConfirmDialogModule, ToolbarModule, ToggleSwitchModule, RadioButtonModule, TextareaModule, DividerModule, MessageModule, ProgressSpinnerModule],
    templateUrl: './ingress.html'
})
export class IngressPage implements OnInit {
    private service = inject(IngressRuleService);
    private sslService = inject(SslService);
    private msg = inject(MessageService);
    private confirm = inject(ConfirmationService);

    filterText = '';
    globalFilterFields = ['name', 'domain', 'backend_host', 'backend_protocol', 'lb_mode'];

    rules = signal<Rule[]>([]);
    certificates = signal<Certificate[]>([]);
    loading = signal(true);
    saving = signal(false);
    editMode = signal(false);
    dialogVisible = false;
    editId: number | null = null;

    form = this.emptyForm();

    lbModes = [
        { label: 'Yük Dengeleme (Round Robin)', value: 'roundrobin' },
        { label: 'Failover (Ana + Yedek)', value: 'failover' }
    ];

    backendProtocols = [
        { label: 'HTTP (Standart)', value: 'http' },
        { label: 'HTTPS (SSL - Re-encryption)', value: 'https' }
    ];

    dnsProviders = [
        { label: 'GoDaddy', value: 'godaddy' },
        { label: 'Hurricane Electric (dns.he.net)', value: 'he-net' }
    ];

    certOptions() {
        return this.certificates().map(c => ({ label: c.cert_domain || c.domain, value: String(c.id ?? c.cert_domain) }));
    }

    emptyForm() {
        return {
            name: '',
            domain: '',
            path: '',
            backend_host: '',
            backend_port: 80,
            backend_protocol: 'http',
            lb_mode: 'roundrobin',
            extra_backends: '',
            ssl_type: 'none' as 'none' | 'new' | 'select',
            ssl_cert_id: '',
            new_ssl_type: 'normal' as 'normal' | 'wildcard',
            dns_provider: '',
            he_username: '',
            he_password: '',
            redirect_to_https: false,
            ssl_enabled: false
        };
    }

    async ngOnInit() {
        await this.load();
    }

    async load() {
        try {
            this.loading.set(true);
            const data = await this.service.getRules();
            this.rules.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kurallar yüklenemedi' });
        } finally {
            this.loading.set(false);
        }
    }

    async loadCertificates() {
        try {
            const certs = await this.sslService.getCertificates();
            this.certificates.set(certs ?? []);
        } catch { /* sertifikalar yüklenemezse sessizce devam et */ }
    }

    async openNew() {
        this.form = this.emptyForm();
        this.editMode.set(false);
        this.editId = null;
        this.dialogVisible = true;
        await this.loadCertificates();
    }

    async editRule(rule: Rule) {
        const sslType = rule.ssl_type === 'select' || rule.ssl_type === 'none' || rule.ssl_type === 'new'
            ? (rule.ssl_type as 'none' | 'new' | 'select')
            : (rule.ssl_enabled ? 'select' : 'none');
        this.form = {
            name: rule.name,
            domain: rule.domain,
            path: rule.path ?? '',
            backend_host: rule.backend_host,
            backend_port: rule.backend_port,
            backend_protocol: rule.backend_protocol || 'http',
            lb_mode: rule.lb_mode || 'roundrobin',
            extra_backends: rule.backends?.map(b => `${b.host}:${b.port}`).join('\n') ?? '',
            ssl_type: sslType,
            ssl_cert_id: rule.ssl_cert ?? '',
            new_ssl_type: 'normal',
            dns_provider: rule.dns_provider ?? '',
            he_username: '',
            he_password: '',
            redirect_to_https: rule.redirect_to_https || false,
            ssl_enabled: rule.ssl_enabled
        };
        this.editMode.set(true);
        this.editId = rule.id ?? null;
        this.dialogVisible = true;
        await this.loadCertificates();
    }

    onSslTypeChange() {
        if (this.form.ssl_type === 'none') {
            this.form.redirect_to_https = false;
            this.form.ssl_enabled = false;
        } else {
            this.form.ssl_enabled = true;
        }
    }

    async save() {
        if (!this.form.domain || !this.form.backend_host) {
            this.msg.add({ severity: 'warn', summary: 'Uyarı', detail: 'Domain ve backend host zorunludur' });
            return;
        }
        this.saving.set(true);
        const payload = {
            name: this.form.name,
            domain: this.form.domain,
            path: this.form.path || null,
            backend_host: this.form.backend_host,
            backend_port: this.form.backend_port,
            backend_protocol: this.form.backend_protocol,
            lb_mode: this.form.lb_mode,
            extra_backends: this.form.extra_backends || null,
            ssl_type: this.form.ssl_type === 'new' && this.form.new_ssl_type === 'wildcard' ? 'wildcard' : this.form.ssl_type,
            ssl_cert_id: this.form.ssl_type === 'select' ? this.form.ssl_cert_id : null,
            dns_provider: this.form.dns_provider || null,
            he_username: this.form.he_username || null,
            he_password: this.form.he_password || null,
            redirect_to_https: this.form.redirect_to_https,
            ssl_enabled: this.form.ssl_enabled
        };
        try {
            if (this.editMode() && this.editId !== null) {
                await this.service.updateRule(this.editId, payload);
                this.msg.add({ severity: 'success', summary: 'Başarılı', detail: 'Kural güncellendi' });
            } else {
                await this.service.createRule(payload);
                this.msg.add({ severity: 'success', summary: 'Başarılı', detail: 'Kural oluşturuldu' });
            }
            this.dialogVisible = false;
            await this.load();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kayıt başarısız' });
        } finally {
            this.saving.set(false);
        }
    }

    deleteRule(rule: Rule) {
        this.confirm.confirm({
            message: `"${rule.domain}" kuralını silmek istediğinize emin misiniz?`,
            header: 'Silme Onayı',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    await this.service.deleteRule(rule.id!);
                    this.msg.add({ severity: 'success', summary: 'Silindi', detail: 'Kural silindi' });
                    await this.load();
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Silme başarısız' });
                }
            }
        });
    }
}
