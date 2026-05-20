import { Component, OnInit, OnDestroy, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from 'primeng/button';
import { TableModule } from 'primeng/table';
import { ToolbarModule } from 'primeng/toolbar';
import { TagModule } from 'primeng/tag';
import { InputTextModule } from 'primeng/inputtext';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { ToastModule } from 'primeng/toast';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { MessageService } from 'primeng/api';
import { LogsService } from '@/app/core/services/logs.service';
import { TrafficLog } from '@/app/core/models';

@Component({
    selector: 'app-logs',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, ToolbarModule, TagModule, InputTextModule, IconFieldModule, InputIconModule, ToastModule, ProgressSpinnerModule],
    templateUrl: './logs.html'
})
export class LogsPage implements OnInit, OnDestroy {
    private logsService = inject(LogsService);
    private msg = inject(MessageService);
    private refreshInterval: any;

    logs = signal<TrafficLog[]>([]);
    loading = signal(true);
    autoRefresh = signal(false);
    filterText = '';
    globalFilterFields = ['timestamp', 'time', 'client_ip', 'client', 'method', 'path', 'url', 'status_code', 'status'];

    async ngOnInit() {
        await this.load();
    }

    ngOnDestroy() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);
    }

    async load() {
        try {
            this.loading.set(true);
            const res = await this.logsService.getLogs();
            this.logs.set(res?.logs ?? []);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Loglar y�klenemedi' });
        } finally {
            this.loading.set(false);
        }
    }

    toggleAutoRefresh() {
        const current = this.autoRefresh();
        if (current) {
            clearInterval(this.refreshInterval);
            this.autoRefresh.set(false);
        } else {
            this.autoRefresh.set(true);
            this.refreshInterval = setInterval(() => this.load(), 5000);
        }
    }

    getMethodSeverity(method: string): 'success' | 'info' | 'warn' | 'danger' | 'secondary' {
        const map: Record<string, 'success' | 'info' | 'warn' | 'danger' | 'secondary'> = {
            GET: 'info', POST: 'success', PUT: 'warn', DELETE: 'danger', PATCH: 'warn'
        };
        return map[method] || 'secondary';
    }

    getStatusSeverity(status: number | string): 'success' | 'warn' | 'danger' | 'secondary' {
        const code = Number(status);
        if (code >= 500) return 'danger';
        if (code >= 400) return 'warn';
        if (code >= 200 && code < 300) return 'success';
        return 'secondary';
    }
}
