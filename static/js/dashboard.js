// static/js/dashboard.js
export const Dashboard = {
    flows: [],
    alerts: [],
    counters: {
        packets: 0,
        attacks: 0,
        normal: 0,
        alerts: 0
    },
    health: {
        cpu_percent: 0,
        memory_used_mb: 0,
        queue_length: 0,
        capture_status: 'STOPPED',
        packets_per_sec: 0,
        uptime: '00:00:00'
    },
    // Was missing entirely -- settings.js does `Object.assign(Dashboard.settings, ...)`
    // on load, which throws immediately if this isn't an object.
    settings: {
        theme: 'dark',
        liveUpdates: true,
    },
    // Was missing entirely -- table.js reads Dashboard.ui.sortColumn/sortDirection,
    // filters.js writes Dashboard.ui.protocolFilter/attackFilter.
    ui: {
        sortColumn: 'timestamp',
        sortDirection: 'desc',
        protocolFilter: 'all',
        attackFilter: 'all',
    },
    // Was missing entirely -- table.js renders Dashboard.filteredFlows, not
    // Dashboard.flows directly, so filters/sort actually apply to the table.
    get filteredFlows() {
        let result = this.flows;
        if (this.ui.protocolFilter && this.ui.protocolFilter !== 'all') {
            result = result.filter(f => (f.protocol_type || '').toUpperCase() === this.ui.protocolFilter.toUpperCase());
        }
        if (this.ui.attackFilter && this.ui.attackFilter !== 'all') {
            result = result.filter(f => f.outcome === this.ui.attackFilter);
        }
        const col = this.ui.sortColumn;
        const dir = this.ui.sortDirection === 'asc' ? 1 : -1;
        if (col) {
            result = [...result].sort((a, b) => {
                const va = a[col] ?? '';
                const vb = b[col] ?? '';
                if (va === vb) return 0;
                return va > vb ? dir : -dir;
            });
        }
        return result;
    },
    subscribers: [],
    subscribe(callback) {
        this.subscribers.push(callback);
    },
    notify() {
        this.subscribers.forEach(cb => cb(this));
    },
    addFlows(newFlows) {
        if (!newFlows || newFlows.length === 0) return;
        this.flows.unshift(...newFlows);
        if (this.flows.length > 500) {
            this.flows.length = 500;
        }
        this.updateStats();
        this.notify();
    },
    addAlerts(newAlerts) {
        if (!newAlerts || newAlerts.length === 0) return;
        this.alerts.unshift(...newAlerts);
        if (this.alerts.length > 200) {
            this.alerts.length = 200;
        }
        this.updateStats();
        this.notify();
    },
    updateStats() {
        this.counters.packets = this.flows.length;
        this.counters.attacks = this.flows.filter(f => f.outcome !== 'normal').length;
        this.counters.normal = this.flows.filter(f => f.outcome === 'normal').length;
        this.counters.alerts = this.alerts.length;
    }
};