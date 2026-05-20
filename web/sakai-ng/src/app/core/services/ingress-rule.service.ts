import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Rule } from '../models';

@Injectable({ providedIn: 'root' })
export class IngressRuleService {
    private readonly http = inject(HttpClient);

    async getRules(): Promise<Rule[]> {
        return firstValueFrom(this.http.get<Rule[]>('/api/rules'));
    }

    async getRule(id: number): Promise<Rule> {
        return firstValueFrom(this.http.get<Rule>(`/api/rules/${id}`));
    }

    async createRule(rule: Partial<Rule>): Promise<Rule> {
        return firstValueFrom(this.http.post<Rule>('/api/rules', rule));
    }

    async updateRule(id: number, rule: Partial<Rule>): Promise<Rule> {
        return firstValueFrom(this.http.put<Rule>(`/api/rules/${id}`, rule));
    }

    async deleteRule(id: number): Promise<void> {
        return firstValueFrom(this.http.delete<void>(`/api/rules/${id}`));
    }
}
