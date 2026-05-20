import { Component, OnInit, OnDestroy, AfterViewInit, ViewChild, ElementRef, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ButtonModule } from 'primeng/button';
import { TagModule } from 'primeng/tag';
import { ToolbarModule } from 'primeng/toolbar';
import { ToastModule } from 'primeng/toast';
import { MessageService } from 'primeng/api';
import { AuthService } from '@/app/core/services/auth.service';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

@Component({
    selector: 'app-terminal',
    standalone: true,
    imports: [CommonModule, ButtonModule, TagModule, ToolbarModule, ToastModule],
    styles: [`
        .terminal-wrapper {
            background: #1e1e1e;
            border-radius: 8px;
            padding: 8px;
            min-height: 500px;
        }
        #terminal-container {
            width: 100%;
            height: 500px;
        }
    `],
    templateUrl: './terminal.html'
})
export class TerminalPage implements OnInit, AfterViewInit, OnDestroy {
    @ViewChild('terminalEl') terminalEl!: ElementRef<HTMLDivElement>;

    private authService = inject(AuthService);
    private msg = inject(MessageService);

    connected = signal(false);
    connecting = signal(false);

    private term!: Terminal;
    private fitAddon!: FitAddon;
    private ws: WebSocket | null = null;
    private resizeObserver: ResizeObserver | null = null;

    ngOnInit() {}

    ngAfterViewInit() {
        this.term = new Terminal({
            theme: {
                background: '#1e1e1e',
                foreground: '#d4d4d4',
                cursor: '#d4d4d4',
            },
            fontFamily: '"Cascadia Code", "Fira Code", monospace',
            fontSize: 14,
            cursorBlink: true,
            convertEol: true,
        });

        this.fitAddon = new FitAddon();
        this.term.loadAddon(this.fitAddon);
        this.term.open(this.terminalEl.nativeElement);
        this.fitAddon.fit();

        this.resizeObserver = new ResizeObserver(() => {
            try { this.fitAddon.fit(); } catch {}
        });
        this.resizeObserver.observe(this.terminalEl.nativeElement);

        this.term.writeln('\x1b[32mHAProxy Terminal\x1b[0m - Baglantı kurmak için "Baglan" butonuna tıklayın.');
    }

    ngOnDestroy() {
        this.disconnect();
        if (this.resizeObserver) this.resizeObserver.disconnect();
        if (this.term) this.term.dispose();
    }

    connect() {
        this.connecting.set(true);
        const token = this.authService.getToken();
        const wsUrl = `ws://${location.host}/ws/terminal?token=${token}`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this.connected.set(true);
            this.connecting.set(false);
            this.term.writeln('\x1b[32m[Bağlandı]\x1b[0m');

            this.term.onData((data) => {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(data);
                }
            });

            this.term.onResize(({ cols, rows }) => {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
                }
            });
        };

        this.ws.onmessage = (event) => {
            this.term.write(event.data);
        };

        this.ws.onerror = () => {
            this.term.writeln('\x1b[31m[Bağlantı hatası]\x1b[0m');
            this.connected.set(false);
            this.connecting.set(false);
        };

        this.ws.onclose = () => {
            this.term.writeln('\x1b[33m[Bağlantı kapatıldı]\x1b[0m');
            this.connected.set(false);
            this.connecting.set(false);
        };
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        this.connected.set(false);
    }

    clearTerminal() {
        this.term.clear();
    }
}