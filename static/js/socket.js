// static/js/socket.js
import { Dashboard } from './dashboard.js';

export class SocketManager {
    constructor() {
        this.socket = io();
        this.pendingFlows = [];
        this.batchTimer = null;
        this.healthInterval = null;
        this.setupListeners();
    }

    setupListeners() {
        this.socket.on('connect', () => {
            this.updateStatus('Connected', 'success');
            const page = document.body.dataset.page || 'dashboard';
            this.socket.emit('request_initial_data', { page });
            this.socket.emit('request_health');
            if (this.healthInterval) {
                clearInterval(this.healthInterval);
            }
            this.healthInterval = setInterval(() => {
                this.socket.emit('request_health');
            }, 5000);
            // hook inspector close button
            const closeBtn = document.getElementById('inspectorClose');
            if (closeBtn) closeBtn.addEventListener('click', () => {
                const panel = document.getElementById('inspectorPanel');
                if (panel) panel.classList.remove('open');
            });
        });

        this.socket.on('disconnect', () => {
            this.updateStatus('Disconnected', 'error');
            if (this.healthInterval) {
                clearInterval(this.healthInterval);
                this.healthInterval = null;
            }
        });

        this.socket.on('flow_update', (data) => {
            // flow_update is only sent on-demand for the flows page
            const flows = data.flows || [];
            if (flows.length === 0) return;
            Dashboard.addFlows(flows);
            if (window.app && typeof window.app.scheduleTableRefresh === 'function') {
                window.app.scheduleTableRefresh();
            }
        });

        this.socket.on('stats_update', (data) => {
            // lightweight, frequent summary updates for dashboard
            Dashboard.health = { ...Dashboard.health, ...data };
            this.updateHealthDisplay(Dashboard.health);
        });

        this.socket.on('alert_update', (data) => {
            const alerts = data.alerts || [];
            if (alerts.length === 0) return;
            // merge alerts: update existing by flow_id or add new
            alerts.forEach(alert => {
                const idx = Dashboard.alerts.findIndex(a => a.flow_id === alert.flow_id);
                if (idx >= 0) {
                    Dashboard.alerts[idx] = { ...Dashboard.alerts[idx], ...alert };
                } else {
                    Dashboard.alerts.unshift(alert);
                }
            });
            // cap alerts length
            if (Dashboard.alerts.length > 200) Dashboard.alerts.length = 200;
            Dashboard.updateStats();
            if (window.app && typeof window.app.scheduleTableRefresh === 'function') {
                window.app.scheduleTableRefresh();
            }
        });

        this.socket.on('status_update', (data) => {
            this.updateStatus(data.status, data.color || 'info');
            this.updateButtons(data);
        });

        this.socket.on('system_health', (data) => {
            Dashboard.health = { ...Dashboard.health, ...data };
            this.updateHealthDisplay(Dashboard.health);
        });
    }

    flushFlowUpdates() {
        this.batchTimer = null;
        if (this.pendingFlows.length === 0) return;
        const flowsToAdd = this.pendingFlows.splice(0, this.pendingFlows.length);
        Dashboard.addFlows(flowsToAdd);
        if (window.app && typeof window.app.scheduleTableRefresh === 'function') {
            window.app.scheduleTableRefresh();
        }
    }

    startIDS() {
        this.socket.emit('start_ids');
        this.updateStatus('Starting IDS...', 'info');
    }

    stopIDS() {
        this.socket.emit('stop_ids');
        this.updateStatus('Stopping IDS...', 'warning');
    }

    updateStatus(message, type) {
        const statusEl = document.getElementById('statusMessage');
        if (!statusEl) return;
        statusEl.textContent = message;
        // keep the class but ensure it matches our CSS naming
        statusEl.className = `status-message status-${type}`;
        const updated = document.getElementById('statusUpdated');
        if (updated) {
            const d = new Date();
            updated.textContent = d.toLocaleTimeString();
        }
    }

    updateButtons(data) {
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        // Prefer the explicit boolean the server now sends. Falls back to
        // substring matching only for safety with any older cached client.
        // The old substring check (`status.includes('started')`) silently
        // broke on 'IDS is already running' -- no 'started' in that string
        // -- which flipped the buttons to the wrong state.
        let running;
        if (typeof data === 'object' && data !== null && 'running' in data) {
            running = !!data.running;
        } else {
            const status = typeof data === 'string' ? data : (data && data.status);
            running = typeof status === 'string' &&
                (status.toLowerCase().includes('started') || status.toLowerCase().includes('already running'));
        }
        if (startBtn) startBtn.disabled = running;
        if (stopBtn) stopBtn.disabled = !running;
    }

    updateHealthDisplay(health) {
        const cpuUsage = document.getElementById('cpuUsage');
        const memoryUsage = document.getElementById('memoryUsage');
        const queueValue = document.getElementById('queueValue');
        const ppsValue = document.getElementById('ppsValue');
        const uptime = document.getElementById('uptime');

        if (cpuUsage) cpuUsage.textContent = `${health.cpu_percent || 0}%`;
        if (memoryUsage) memoryUsage.textContent = `${health.memory_used_mb || 0} MB`;
        if (queueValue) queueValue.textContent = `${health.queue_length || 0}`;
        if (ppsValue) ppsValue.textContent = `${health.packets_per_sec || 0}`;
        if (uptime) uptime.textContent = health.uptime || '00:00:00';

        const memoryBar = document.getElementById('memoryBar');
        if (memoryBar) {
            const pct = Math.min(((health.memory_used_mb || 0) / Math.max((health.memory_total_mb || 1), 1)) * 100, 100);
            memoryBar.style.width = `${pct}%`;
        }

        const cpuBar = document.getElementById('cpuBar');
        if (cpuBar) cpuBar.style.width = `${Math.min(health.cpu_percent || 0, 100)}%`;

        // Dashboard headline stats (index.html's system-banner + chart-summary).
        // None of these were ever wired up before -- they showed whatever
        // static value was in the HTML forever, regardless of real traffic.
        const captureStatus = document.getElementById('captureStatus');
        if (captureStatus) captureStatus.textContent = health.capture_status || 'STOPPED';

        const totalPackets = document.getElementById('totalPackets');
        if (totalPackets) totalPackets.textContent = health.total_packets ?? 0;

        const attackPackets = document.getElementById('attackPackets');
        if (attackPackets) attackPackets.textContent = health.total_attacks ?? 0;

        const packetRate = document.getElementById('packetRate');
        if (packetRate) packetRate.textContent = `${health.packets_per_sec || 0} pkt/s`;

        const packetRateLarge = document.getElementById('packetRateLarge');
        if (packetRateLarge) packetRateLarge.textContent = health.packets_per_sec ?? 0;

        const attacksRateLarge = document.getElementById('attacksRateLarge');
        if (attacksRateLarge) attacksRateLarge.textContent = health.attacks_per_sec ?? 0;

        const alertCountLarge = document.getElementById('alertCountLarge');
        if (alertCountLarge) alertCountLarge.textContent = health.active_alerts ?? 0;

        // Health payload also carries the authoritative running state --
        // keep the buttons in sync here too, not just from status_update,
        // since system_health arrives every 3s regardless of page navigation.
        if ('running' in health) {
            this.updateButtons({ running: health.running });
        }
    }
}