import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { HaStats } from '../models';

@Injectable({ providedIn: 'root' })
export class StatsService {
    private readonly http = inject(HttpClient);

    async getStats(): Promise<string> {
        return firstValueFrom(this.http.get('/api/ha_stats', { responseType: 'text' }));
    }

    async getSessions(): Promise<unknown[]> {
        return firstValueFrom(this.http.get<unknown[]>('/api/ha_sessions'));
    }

    parseStatsCSV(csv: string): HaStats[] {
        const lines = csv.trim().split('\n');
        if (lines[0].startsWith('# ')) lines[0] = lines[0].slice(2);
        const headers = lines[0].split(',');
        const data: HaStats[] = [];
        for (let i = 1; i < lines.length; i++) {
            const cols = lines[i].split(',');
            if (cols.length < headers.length) continue;
            const row: HaStats = { pxname: '', svname: '' };
            headers.forEach((h, idx) => {
                const val = cols[idx];
                row[h.trim()] = isNaN(Number(val)) || val === '' ? val : Number(val);
            });
            data.push(row);
        }
        return data;
    }
}
