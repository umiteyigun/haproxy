import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { PortForwarding } from '../models';

@Injectable({ providedIn: 'root' })
export class PortForwardService {
    private readonly http = inject(HttpClient);

    async getRules(): Promise<PortForwarding[]> {
        return firstValueFrom(this.http.get<PortForwarding[]>('/api/port-forwarding'));
    }

    async getRule(id: number): Promise<PortForwarding> {
        return firstValueFrom(this.http.get<PortForwarding>(`/api/port-forwarding/${id}`));
    }

    async createRule(rule: Partial<PortForwarding>): Promise<PortForwarding> {
        return firstValueFrom(this.http.post<PortForwarding>('/api/port-forwarding', rule));
    }

    async updateRule(id: number, rule: Partial<PortForwarding>): Promise<PortForwarding> {
        return firstValueFrom(this.http.put<PortForwarding>(`/api/port-forwarding/${id}`, rule));
    }

    async deleteRule(id: number): Promise<void> {
        return firstValueFrom(this.http.delete<void>(`/api/port-forwarding/${id}`));
    }
}
