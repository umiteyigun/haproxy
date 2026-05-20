import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from 'primeng/button';
import { TableModule } from 'primeng/table';
import { DialogModule } from 'primeng/dialog';
import { InputTextModule } from 'primeng/inputtext';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ToolbarModule } from 'primeng/toolbar';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { MessageService, ConfirmationService } from 'primeng/api';
import { MemberService } from '@/app/core/services/member.service';
import { AuthService } from '@/app/core/services/auth.service';
import { Member } from '@/app/core/models';

@Component({
    selector: 'app-members',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, TableModule, DialogModule, InputTextModule, IconFieldModule, InputIconModule, ToastModule, ConfirmDialogModule, ToolbarModule, ProgressSpinnerModule],
    templateUrl: './members.html'
})
export class MembersPage implements OnInit {
    private service = inject(MemberService);
    private authService = inject(AuthService);
    private msg = inject(MessageService);
    private confirm = inject(ConfirmationService);

    filterText = '';
    globalFilterFields = ['email'];

    members = signal<Member[]>([]);
    loading = signal(true);
    saving = signal(false);
    currentEmail = signal('');
    newDialogVisible = false;
    passDialogVisible = false;
    selfPasswordMode = false;
    selectedMemberId: number | null = null;

    newForm = { email: '', password: '' };
    passForm = { current: '', newPass: '' };

    async ngOnInit() {
        this.currentEmail.set(this.authService.getCurrentUserEmail());
        await this.load();
    }

    async load() {
        try {
            this.loading.set(true);
            const data = await this.service.getMembers();
            this.members.set(data);
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kullan�c�lar y�klenemedi' });
        } finally {
            this.loading.set(false);
        }
    }

    openNew() {
        this.newForm = { email: '', password: '' };
        this.newDialogVisible = true;
    }

    async createMember() {
        if (!this.newForm.email || !this.newForm.password) {
            this.msg.add({ severity: 'warn', summary: 'Uyar�', detail: 'E-posta ve �ifre zorunludur' });
            return;
        }
        this.saving.set(true);
        try {
            await this.service.createMember(this.newForm);
            this.msg.add({ severity: 'success', summary: 'Olu�turuldu' });
            this.newDialogVisible = false;
            await this.load();
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Kullan�c� olu�turulamad�' });
        } finally {
            this.saving.set(false);
        }
    }

    openChangePassword(member: Member) {
        this.selfPasswordMode = false;
        this.selectedMemberId = member.id ?? null;
        this.passForm = { current: '', newPass: '' };
        this.passDialogVisible = true;
    }

    openSelfPassword() {
        this.selfPasswordMode = true;
        this.passForm = { current: '', newPass: '' };
        this.passDialogVisible = true;
    }

    async changePassword() {
        if (!this.passForm.newPass) {
            this.msg.add({ severity: 'warn', summary: 'Uyar�', detail: 'Yeni �ifre zorunludur' });
            return;
        }
        this.saving.set(true);
        try {
            if (this.selfPasswordMode) {
                await this.service.updateSelfPassword(this.passForm.current, this.passForm.newPass);
            } else if (this.selectedMemberId !== null) {
                await this.service.updateMemberPassword(this.selectedMemberId, this.passForm.newPass);
            }
            this.msg.add({ severity: 'success', summary: '�ifre g�ncellendi' });
            this.passDialogVisible = false;
        } catch {
            this.msg.add({ severity: 'error', summary: 'Hata', detail: '�ifre g�ncellenemedi' });
        } finally {
            this.saving.set(false);
        }
    }

    deleteMember(member: Member) {
        this.confirm.confirm({
            message: `"${member.email}" kullan�c�s�n� silmek istedi�inize emin misiniz?`,
            header: 'Silme Onay�',
            icon: 'pi pi-exclamation-triangle',
            accept: async () => {
                try {
                    await this.service.deleteMember(member.id!);
                    this.msg.add({ severity: 'success', summary: 'Silindi' });
                    await this.load();
                } catch {
                    this.msg.add({ severity: 'error', summary: 'Hata', detail: 'Silme ba�ar�s�z' });
                }
            }
        });
    }
}
