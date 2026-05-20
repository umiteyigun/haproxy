import { Component, OnInit, OnDestroy, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { CardModule } from 'primeng/card';
import { TagModule } from 'primeng/tag';
import { ButtonModule } from 'primeng/button';
import { TableModule } from 'primeng/table';
import { ChartModule } from 'primeng/chart';
import { ToolbarModule } from 'primeng/toolbar';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { StatsService } from '@/app/core/services/stats.service';
import { HaStats } from '@/app/core/models';

@Component({
    selector: 'app-dashboard',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, TagModule, ButtonModule, TableModule, ChartModule, ToolbarModule, IconFieldModule, InputIconModule, ProgressSpinnerModule],
    templateUrl: './dashboard.html'
})
export class Dashboard implements OnInit, OnDestroy {
    private statsService = inject(StatsService);
    private refreshInterval: any;

    filterText = '';
    globalFilterFields = ['pxname', 'svname', 'status'];

    stats = signal<HaStats[]>([]);
    loading = signal(true);
    totalBackends = signal(0);
    activeBackends = signal(0);
    downBackends = signal(0);
    totalSessions = signal(0);

    chartData = signal<any>({});
    chartOptions = {
        plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
    };

    trafficChartData = signal<any>({ labels: [], datasets: [] });
    trafficChartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        plugins: {
            legend: { labels: { color: '#94a3b8' } }
        },
        scales: {
            x: {
                ticks: { color: '#94a3b8', maxTicksLimit: 8 },
                grid: { color: 'rgba(51,65,85,0.5)' }
            },
            y: {
                ticks: { color: '#94a3b8' },
                grid: { color: 'rgba(51,65,85,0.5)' },
                beginAtZero: true
            }
        }
    };

    private trafficHistory = {
        labels: [] as string[],
        reqRate: [] as number[],
        connRate: [] as number[]
    };

    async ngOnInit() {
        await this.loadStats();
        this.refreshInterval = setInterval(() => this.loadStats(), 5000);
    }

    ngOnDestroy() {
        clearInterval(this.refreshInterval);
    }

    async loadStats() {
        try {
            this.loading.set(true);
            const csv = await this.statsService.getStats();
            const rows = this.statsService.parseStatsCSV(csv);
            this.stats.set(rows);

            const up = rows.filter(r => r.status === 'UP').length;
            const down = rows.filter(r => r.status === 'DOWN').length;
            const other = rows.length - up - down;
            this.totalBackends.set(rows.length);
            this.activeBackends.set(up);
            this.downBackends.set(down);
            this.totalSessions.set(rows.reduce((a, r) => a + (r.scur || 0), 0));

            this.chartData.set({
                labels: ['UP', 'DOWN', 'Diğer'],
                datasets: [{
                    data: [up, down, other],
                    backgroundColor: ['#22c55e', '#ef4444', '#f59e0b']
                }]
            });

            // Trafik geçmişini güncelle (maks 50 örnek)
            let reqRate = 0;
            let connRate = 0;
            rows.forEach(r => {
                if (r.svname === 'FRONTEND') {
                    reqRate += Number(r.req_rate || 0);
                    connRate += Number((r as any)['rate'] || r.conn_rate || 0);
                }
            });

            const h = this.trafficHistory;
            if (h.labels.length >= 50) {
                h.labels.shift();
                h.reqRate.shift();
                h.connRate.shift();
            }
            h.labels.push(new Date().toLocaleTimeString('tr-TR'));
            h.reqRate.push(reqRate);
            h.connRate.push(connRate);

            this.trafficChartData.set({
                labels: [...h.labels],
                datasets: [
                    {
                        label: 'İstek/sn',
                        data: [...h.reqRate],
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16,185,129,0.1)',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 2
                    },
                    {
                        label: 'Bağlantı/sn',
                        data: [...h.connRate],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59,130,246,0.1)',
                        tension: 0.4,
                        fill: true,
                        pointRadius: 2
                    }
                ]
            });
        } catch {
            // ignore
        } finally {
            this.loading.set(false);
        }
    }
}
