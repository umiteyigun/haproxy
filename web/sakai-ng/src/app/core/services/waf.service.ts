import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { WafRule, WafEvent, GlobalWafList } from '../models';

@Injectable({ providedIn: 'root' })
export class WafService {
    private readonly http = inject(HttpClient);

    // Custom rules
    async getRules(): Promise<WafRule[]> {
        const res = await firstValueFrom(this.http.get<any>('/api/waf/rules'));
        const list: any[] = Array.isArray(res) ? res : (res?.rules ?? []);
        // API returns `name` field; model uses `filename`
        return list.map(r => ({ ...r, filename: r.filename ?? r.name }));
    }

    async getRule(filename: string): Promise<WafRule> {
        return firstValueFrom(this.http.get<WafRule>(`/api/waf/rules/${filename}`));
    }

    async createRule(filename: string, content: string): Promise<WafRule> {
        return firstValueFrom(this.http.post<WafRule>('/api/waf/rules', { filename, content }));
    }

    async updateRule(filename: string, content: string): Promise<WafRule> {
        return firstValueFrom(this.http.put<WafRule>(`/api/waf/rules/${filename}`, { content }));
    }

    async deleteRule(filename: string): Promise<void> {
        return firstValueFrom(this.http.delete<void>(`/api/waf/rules/${filename}`));
    }

    // CRS rules
    async getCrsRules(): Promise<WafRule[]> {
        return firstValueFrom(this.http.get<WafRule[]>('/api/waf/crs'));
    }

    async getCrsRuleContent(filename: string): Promise<string> {
        return firstValueFrom(this.http.get(`/api/waf/crs/${filename}`, { responseType: 'text' }));
    }

    async updateCrsRule(filename: string, content: string): Promise<WafRule> {
        return firstValueFrom(this.http.post<WafRule>(`/api/waf/crs/${filename}`, { content }));
    }

    async toggleCrsRule(filename: string, enable: boolean): Promise<void> {
        return firstValueFrom(this.http.post<void>(`/api/waf/crs/${filename}/toggle`, { enable }));
    }

    // SPOA reload
    async reloadSpoa(): Promise<unknown> {
        return firstValueFrom(this.http.post('/api/waf/reload-spoa', {}));
    }

  // WAF Events (ModSecurity audit log)
  getWafEvents(limit = 100): Promise<{ events: WafEvent[]; message?: string }> {
    return firstValueFrom(this.http.get<{ events: WafEvent[]; message?: string }>(`/api/waf/events?limit=${limit}`));
  }

  // Global WAF list management (HAProxy ACL files)
  getGlobalList(type: 'ip_blacklist' | 'bad_useragents'): Promise<GlobalWafList> {
    return firstValueFrom(this.http.get<GlobalWafList>(`/api/waf/global/${type}`));
  }

  addGlobalEntry(type: 'ip_blacklist' | 'bad_useragents', entry: string): Promise<GlobalWafList> {
    return firstValueFrom(this.http.post<GlobalWafList>(`/api/waf/global/${type}`, { entry }));
  }

  deleteGlobalEntry(type: 'ip_blacklist' | 'bad_useragents', entry: string): Promise<GlobalWafList> {
    return firstValueFrom(this.http.delete<GlobalWafList>(`/api/waf/global/${type}`, { body: { entry } }));
  }
}
