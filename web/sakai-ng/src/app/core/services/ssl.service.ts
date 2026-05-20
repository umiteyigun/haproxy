import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Certificate, SslRequestData } from '../models';

@Injectable({ providedIn: 'root' })
export class SslService {
    private readonly http = inject(HttpClient);

    async getCertificates(): Promise<Certificate[]> {
        return firstValueFrom(this.http.get<Certificate[]>('/api/ssl/certificates'));
    }

    async getCertificate(certDomain: string): Promise<unknown> {
        return firstValueFrom(this.http.get(`/api/ssl/certificates/${certDomain}`));
    }

    async getAvailableCerts(domain: string): Promise<string[]> {
        return firstValueFrom(this.http.get<string[]>(`/api/ssl/certificates/available/${domain}`));
    }

    async requestCertificate(data: SslRequestData): Promise<unknown> {
        return firstValueFrom(this.http.post('/api/ssl/request', data));
    }

    async verifyCertificate(data: unknown): Promise<unknown> {
        return firstValueFrom(this.http.post('/api/ssl/verify', data));
    }

    async continueCertificate(data: unknown): Promise<unknown> {
        return firstValueFrom(this.http.post('/api/ssl/continue', data));
    }

    async renewCertificate(domain: string): Promise<unknown> {
        return firstValueFrom(this.http.post(`/api/ssl/renew/${domain}`, {}));
    }

    async renewAll(): Promise<unknown> {
        return firstValueFrom(this.http.post('/api/ssl/renew', {}));
    }

    async deleteCertificate(certDomain: string): Promise<void> {
        return firstValueFrom(this.http.delete<void>(`/api/ssl/certificates/${certDomain}`));
    }

    async updateCertificate(domain: string, data: Partial<Certificate>): Promise<unknown> {
        return firstValueFrom(this.http.put(`/api/ssl/certificates/${domain}`, data));
    }
}
