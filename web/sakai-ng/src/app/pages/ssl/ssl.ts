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
import { StepperModule } from 'primeng/stepper';
import { MessageModule } from 'primeng/message';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { MessageService, ConfirmationService } from 'primeng/api';
import { SslService } from '@/app/core/services/ssl.service';
import { Certificate } from '@/app/core/models';

@Component({
    selector: 'app-ssl',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, DialogModule, InputTextModule, IconFieldModule, InputIconModule, SelectModule, TagModule, ToastModule, ConfirmDialogModule, ToolbarModule, StepperModule, MessageModule, ProgressSpinnerModule],
    templateUrl: './ssl.html'
})
export class SslPage implements OnInit {
    private service = inject(SslService);
    private msg = inject(MessageService);
    private confirm = inject(ConfirmationService);

    filterText = '';
    globalFilterFields = ['domain', 'status', 'expires_at'];

    certs = signal<Certificate[]>([]);
    loading = signal(true);
    requesting = signal(false);
    renewingAll = signal(false);
    requestDialogVisible = false;
    dnsChallenge = signal<any>(null);
    verifyToken = '';

    reqForm = this.emptyReqForm();
    dnsProviders = [
        { label: 'Cloudflare', value: 'cloudflare' },
        { label: 'HE.net (Hurricane Electric)', value: 'he' },
        { label: 'Manuel DNS', value: 'manual' }
    ];
    sslTypes = [
        { label: 'Standart', value: 'normal' },
        { label: 'Wildcard (*.domain.com)', value: 'wildcard' }
    ];

    emptyReqForm() {
        return { domain: '', email: '', ssl_type: 'normal' as 'normal' | 'wildcard', dns_provider: 'cloudflare', cloudflare_api_key: '', he_username: '', he_password: '' };
    }

    async ngOnInit() {
        await this.load();
    }

    async load() {
        try {
            this.loading.set(true);
            const data = await this.service.getCertificates();
            this.certs.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Sertifikalar yüklenemedi' });
        } finally {
            this.loading.set(false);
        }
    }

    openRequest() {
        this.reqForm = this.emptyReqForm();
        this.dnsChallenge.set(null);
        this.requestDialogVisible = true;
    }

    async requestCert() {
        if (!this.reqForm.domain) {
            this.msg.add({ severity: 'warn', summary: 'Uyarı', detail: 'Domain zorunludur' });
            return;
        }
        this.requesting.set(true);
        try {
            const result: any = await this.service.requestCertificate(this.reqForm);
            if (result?.challenge) {
                this.dnsChallenge.set(result.challenge);
                this.msg.add({ severity: 'info', summary: 'DNS Kaydı Gerekli', detail: 'DNS TXT kaydını ekleyin' });
            } else {
                this.msg.add({ severity: 'success', summary: 'Başarılı', detail: 'Sertifika oluşturuldu' });
                this.requestDialogVisible = false;
                await this.load();
            }
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Sertifika isteği başarısız' });
        } finally {
            this.requesting.set(false);
        }
    }

    async verifyCert() {
        this.requesting.set(true);
        try {
            await this.service.verifyCertificate({ domain: this.reqForm.domain, token: this.verifyToken });
            this.msg.add({ severity: 'success', summary: 'Başarılı', detail: 'Sertifika doğrulandı ve oluşturuldu' });
            this.requestDialogVisible = false;
            this.dnsChallenge.set(null);
            await this.load();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Doğrulama başarısız' });
        } finally {
            this.requesting.set(false);
        }
    }

    async renewCert(cert: Certificate) {
        try {
            await this.service.renewCertificate(cert.domain);
            this.msg.add({ severity: 'success', summary: 'Yenilendi', detail: `${cert.domain} sertifikası yenilendi` });
            await this.load();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Yenileme başarısız' });
        }
    }

    async renewAll() {
        this.renewingAll.set(true);
        try {
            await this.service.renewAll();
            this.msg.add({ severity: 'success', summary: 'Başarılı', detail: 'Tüm sertifikalar yenilendi' });
            await this.load();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Toplu yenileme başarısız' });
        } finally {
            this.renewingAll.set(false);
        }
    }

    deleteCert(cert: Certificate) {
        this.confirm.confirm({
            message: `"${cert.domain}" sertifikasını silmek istediğinize emin misiniz?`,
            header: 'Silme Onayı',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    await this.service.deleteCertificate(cert.domain);
                    this.msg.add({ severity: 'success', summary: 'Silindi' });
                    await this.load();
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Silme başarısız' });
                }
            }
        });
    }
}
