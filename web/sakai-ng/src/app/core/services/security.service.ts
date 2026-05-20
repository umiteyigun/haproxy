import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Ban } from '../models';

@Injectable({ providedIn: 'root' })
export class SecurityService {
    private readonly http = inject(HttpClient);

    async getBans(): Promise<Ban[]> {
        const res = await firstValueFrom(this.http.get<any>('/api/security/bans'));
        return Array.isArray(res) ? res : (res?.bans ?? []);
    }

    async unban(ip: string): Promise<void> {
        return firstValueFrom(this.http.post<void>('/api/security/unban', { ip }));
    }

    async manualBan(ip: string): Promise<void> {
        return firstValueFrom(this.http.post<void>('/api/security/ban', { ip }));
    }

    async getWhitelist(): Promise<string[]> {
        const res = await firstValueFrom(this.http.get<any>('/api/security/whitelist'));
        return Array.isArray(res) ? res : (res?.whitelist ?? []);
    }

    async addToWhitelist(ip: string): Promise<void> {
        return firstValueFrom(this.http.post<void>('/api/security/whitelist', { ip }));
    }

    async removeFromWhitelist(ip: string): Promise<void> {
        return firstValueFrom(this.http.post<void>('/api/security/unwhitelist', { ip }));
    }
}
