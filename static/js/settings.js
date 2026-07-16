// static/js/settings.js
import { Dashboard } from './dashboard.js';

export class SettingsManager {
    constructor() {
        this.loadSettings();
        this.setupListeners();
    }
    
    loadSettings() {
        const saved = localStorage.getItem('ids_settings');
        if (saved) {
            try {
                const settings = JSON.parse(saved);
                Object.assign(Dashboard.settings, settings);
            } catch (e) {
                console.warn('Failed to load settings', e);
            }
        }
        
        // Apply theme
        this.applyTheme();
    }
    
    saveSettings() {
        localStorage.setItem('ids_settings', JSON.stringify(Dashboard.settings));
    }
    
    toggleTheme() {
        Dashboard.settings.theme = Dashboard.settings.theme === 'dark' ? 'light' : 'dark';
        this.applyTheme();
        this.saveSettings();
    }
    
    applyTheme() {
        const isDark = Dashboard.settings.theme === 'dark';
        document.body.classList.toggle('dark-mode', isDark);
        
        // Update Chart.js themes
        document.dispatchEvent(new CustomEvent('theme:change', {
            detail: { theme: Dashboard.settings.theme }
        }));
    }
    
    toggleLiveUpdates() {
        Dashboard.settings.liveUpdates = !Dashboard.settings.liveUpdates;
        this.saveSettings();
        
        const btn = document.getElementById('pause-updates');
        if (btn) {
            btn.innerHTML = Dashboard.settings.liveUpdates 
                ? '<i class="fas fa-pause"></i> Пауза'
                : '<i class="fas fa-play"></i> Продолжить';
            btn.classList.toggle('btn-warning', !Dashboard.settings.liveUpdates);
        }
    }
    
    setupListeners() {
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+Shift+D - Toggle dark mode
            if (e.ctrlKey && e.shiftKey && e.key === 'D') {
                e.preventDefault();
                this.toggleTheme();
            }
            
            // Ctrl+Shift+P - Toggle pause
            if (e.ctrlKey && e.shiftKey && e.key === 'P') {
                e.preventDefault();
                this.toggleLiveUpdates();
            }
        });
    }
}