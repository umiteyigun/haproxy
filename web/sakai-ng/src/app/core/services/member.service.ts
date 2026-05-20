import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { Member } from '../models';

@Injectable({ providedIn: 'root' })
export class MemberService {
    private readonly http = inject(HttpClient);

    async getMembers(): Promise<Member[]> {
        return firstValueFrom(this.http.get<Member[]>('/api/members'));
    }

    async createMember(data: { email: string; password: string }): Promise<Member> {
        return firstValueFrom(this.http.post<Member>('/api/members', data));
    }

    async updateMemberPassword(id: number, password: string): Promise<void> {
        return firstValueFrom(this.http.put<void>(`/api/members/${id}/password`, { password }));
    }

    async deleteMember(id: number): Promise<void> {
        return firstValueFrom(this.http.delete<void>(`/api/members/${id}`));
    }

    async updateSelfPassword(current_password: string, new_password: string): Promise<void> {
        return firstValueFrom(this.http.put<void>('/api/auth/password', { current_password, new_password }));
    }
}
