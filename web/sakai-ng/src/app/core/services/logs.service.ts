import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { TrafficLog } from '../models';

@Injectable({ providedIn: 'root' })
export class LogsService {
    private readonly http = inject(HttpClient);

    async getLogs(): Promise<{ logs: TrafficLog[]; raw?: string }> {
        return firstValueFrom(this.http.get<{ logs: TrafficLog[]; raw?: string }>('/api/logs/access'));
    }

    async getConnections(): Promise<unknown[]> {
        return firstValueFrom(this.http.get<unknown[]>('/api/ha_sessions'));
    }
}
