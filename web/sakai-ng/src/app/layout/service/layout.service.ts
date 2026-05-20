import { Injectable, effect, signal, computed } from '@angular/core';

export interface LayoutConfig {
    preset: string;
    primary: string;
    surface: string | undefined | null;
    darkTheme: boolean;
    menuMode: string;
}

interface LayoutState {
    staticMenuDesktopInactive: boolean;
    overlayMenuActive: boolean;
    configSidebarVisible: boolean;
    mobileMenuActive: boolean;
    menuHoverActive: boolean;
    activePath: string | null;
}

interface SavedPrefs {
    preset?: string;
    primary?: string;
    surface?: string | null;
    darkTheme?: boolean;
    menuMode?: string;
    sidebarClosed?: boolean;
}

const STORAGE_KEY = 'haproxy_ui_prefs';

function loadPrefs(): SavedPrefs {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch {
        return {};
    }
}

function savePrefs(prefs: SavedPrefs): void {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch { /* storage quota exceeded */ }
}

@Injectable({
    providedIn: 'root'
})
export class LayoutService {
    private readonly saved: SavedPrefs = loadPrefs();

    layoutConfig = signal<LayoutConfig>({
        preset: this.saved.preset ?? 'Aura',
        primary: this.saved.primary ?? 'emerald',
        surface: this.saved.surface ?? null,
        darkTheme: this.saved.darkTheme ?? false,
        menuMode: this.saved.menuMode ?? 'static'
    });

    layoutState = signal<LayoutState>({
        staticMenuDesktopInactive: this.saved.sidebarClosed ?? false,
        overlayMenuActive: false,
        configSidebarVisible: false,
        mobileMenuActive: false,
        menuHoverActive: false,
        activePath: null
    });

    theme = computed(() => (this.layoutConfig().darkTheme ? 'light' : 'dark'));

    isSidebarActive = computed(() => this.layoutState().overlayMenuActive || this.layoutState().mobileMenuActive);

    isDarkTheme = computed(() => this.layoutConfig().darkTheme);

    getPrimary = computed(() => this.layoutConfig().primary);

    getSurface = computed(() => this.layoutConfig().surface);

    isOverlay = computed(() => this.layoutConfig().menuMode === 'overlay');

    transitionComplete = signal<boolean>(false);

    private initialized = false;

    constructor() {
        // Karanlık modu sayfa yüklenirken hemen uygula (geçiş animasyonu olmadan)
        this.toggleDarkMode();

        // Karanlık mod geçiş efekti (değiştirildiğinde)
        effect(() => {
            const config = this.layoutConfig();

            if (!this.initialized || !config) {
                this.initialized = true;
                return;
            }

            this.handleDarkModeTransition(config);
        });

        // Tercihler değiştiğinde localStorage'a kaydet
        effect(() => {
            const config = this.layoutConfig();
            const state = this.layoutState();
            savePrefs({
                preset: config.preset,
                primary: config.primary,
                surface: config.surface,
                darkTheme: config.darkTheme,
                menuMode: config.menuMode,
                sidebarClosed: state.staticMenuDesktopInactive
            });
        });
    }

    private handleDarkModeTransition(config: LayoutConfig): void {
        const supportsViewTransition = 'startViewTransition' in document;

        if (supportsViewTransition) {
            this.startViewTransition(config);
        } else {
            this.toggleDarkMode(config);
        }
    }

    private startViewTransition(config: LayoutConfig): void {
        document.startViewTransition(() => {
            this.toggleDarkMode(config);
        });
    }

    toggleDarkMode(config?: LayoutConfig): void {
        const _config = config || this.layoutConfig();
        if (_config.darkTheme) {
            document.documentElement.classList.add('app-dark');
        } else {
            document.documentElement.classList.remove('app-dark');
        }
    }

    onMenuToggle() {
        if (this.isOverlay()) {
            this.layoutState.update((prev) => ({ ...prev, overlayMenuActive: !this.layoutState().overlayMenuActive }));
        }

        if (this.isDesktop()) {
            this.layoutState.update((prev) => ({ ...prev, staticMenuDesktopInactive: !this.layoutState().staticMenuDesktopInactive }));
        } else {
            this.layoutState.update((prev) => ({ ...prev, mobileMenuActive: !this.layoutState().mobileMenuActive }));
        }
    }

    showConfigSidebar() {
        this.layoutState.update((prev) => ({ ...prev, configSidebarVisible: true }));
    }

    hideConfigSidebar() {
        this.layoutState.update((prev) => ({ ...prev, configSidebarVisible: false }));
    }

    isDesktop() {
        return window.innerWidth > 991;
    }

    isMobile() {
        return !this.isDesktop();
    }
}
