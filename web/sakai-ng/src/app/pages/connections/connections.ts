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

@Component({
    selector: 'app-connections',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, ToolbarModule, TagModule, InputTextModule, IconFieldModule, InputIconModule, ToastModule, ProgressSpinnerModule],
    templateUrl: './connections.html'
})
export class ConnectionsPage implements OnInit, OnDestroy {
    private logsService = inject(LogsService);
    private msg = inject(MessageService);
    private refreshInterval: any;

    connections = signal<any[]>([]);
    loading = signal(true);
    paused = signal(false);
    filterText = '';
    globalFilterFields = ['src', 'cliaddr', 'frontend', 'pxname', 'backend', 'svname', 'state', 'status'];

    async ngOnInit() {
        await this.load();
        this.refreshInterval = setInterval(() => {
            if (!this.paused()) this.load();
        }, 2000);
    }

    ngOnDestroy() {
        clearInterval(this.refreshInterval);
    }

    async load() {
        try {
            this.loading.set(true);
            const data = await this.logsService.getConnections();
            this.connections.set(Array.isArray(data) ? data : []);
        } catch {
            // silently ignore
        } finally {
            this.loading.set(false);
        }
    }

    togglePause() {
        this.paused.set(!this.paused());
    }
}
