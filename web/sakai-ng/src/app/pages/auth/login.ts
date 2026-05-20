import { Component, signal, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { MessageModule } from 'primeng/message';
import { AuthService } from '../../core/services/auth.service';
import { AppFloatingConfigurator } from '../../layout/component/app.floatingconfigurator';

@Component({
    selector: 'app-login',
    standalone: true,
    imports: [ButtonModule, InputTextModule, PasswordModule, FormsModule, RouterModule, AppFloatingConfigurator, MessageModule],
    templateUrl: './login.html'
})
export class Login {
    private authService = inject(AuthService);
    private router = inject(Router);
    email = '';
    password = '';
    loading = signal(false);
    errorMsg = signal('');

    async login() {
        if (!this.email || !this.password) {
            this.errorMsg.set('E-posta ve sifre zorunludur.');
            return;
        }
        this.loading.set(true);
        this.errorMsg.set('');
        try {
            await this.authService.login({ email: this.email, password: this.password });
            this.router.navigate(['/']);
        } catch {
            this.errorMsg.set('Gecersiz e-posta veya sifre.');
        } finally {
            this.loading.set(false);
        }
    }
}
