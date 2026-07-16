// static/js/app.js
import { Dashboard } from './dashboard.js';
import { SocketManager } from './socket.js';
import { Utils } from './utils.js';

window.Utils = Utils;

class App {
    constructor() {
        window.app = this;
        this.socket = new SocketManager();
        this.tableRefreshTimer = null;
        this.page = document.body.dataset.page || 'dashboard';
        this.setupUI();

        Dashboard.subscribe(() => {
            this.updateSummaryCards();
            this.scheduleTableRefresh();
        });
    }


    scheduleTableRefresh() {
        if (this.tableRefreshTimer) return;
        this.tableRefreshTimer = setTimeout(() => {
            this.tableRefreshTimer = null;
            this.renderCurrentPage();
        }, 200);
    }

    renderCurrentPage() {
        if (this.page === 'alerts') {
            this.renderAlerts();
        } else if (this.page === 'flows') {
            this.renderFlows();
        } else {
            this.renderDashboardFlows();
        }
    }

    renderDashboardFlows() {
        const flows = Dashboard.flows;
        const tableBody = document.getElementById('mainTableBody');
        if (!tableBody) return;
        this.renderTableRows(tableBody, flows, ['flow_id', 'timestamp', 'src_ip', 'dst_ip', 'protocol_type', 'outcome', 'confidence', 'src_bytes', 'dst_bytes', 'duration'], true);

        const visibleRows = document.getElementById('visibleRows');
        const totalRows = document.getElementById('totalRows');
        if (visibleRows) visibleRows.textContent = Math.min(flows.length, 100);
        if (totalRows) totalRows.textContent = flows.length;
    }

    renderFlows() {
        const flows = Dashboard.flows;
        const tableBody = document.getElementById('flowListBody');
        if (!tableBody) return;
        this.renderTableRows(tableBody, flows, ['flow_id', 'src_ip', 'dst_ip', 'protocol_type', 'outcome', 'confidence'], true);
    }

    renderAlerts() {
        const alerts = Dashboard.alerts;
        const tableBody = document.getElementById('alertsTableBody');
        if (!tableBody) return;
        // fields for display (renderTableRows will add action column for alerts)
        this.renderTableRows(tableBody, alerts, ['timestamp', 'src_ip', 'dst_ip', 'outcome', 'severity', 'confidence'], false, 'alerts');
    }

    // Event delegation for alert actions
    _handleAlertAction(e) {
        const ackBtn = e.target.closest('.ack-btn');
        if (ackBtn) {
            const flowId = ackBtn.getAttribute('data-flowid');
            if (!flowId) return;
            this.socket.socket.emit('ack_alert', { flow_id: flowId });
            // optimistically mark acknowledged in UI
            const alert = Dashboard.alerts.find(a => a.flow_id === flowId);
            if (alert) {
                alert.acknowledged = true;
                this.scheduleTableRefresh();
            }
            return;
        }

        const invBtn = e.target.closest('.investigate-btn');
        if (invBtn) {
            const flowId = invBtn.getAttribute('data-flowid');
            if (!flowId) return;
            // open investigation modal
            this.showInvestigationModal(flowId);
            return;
        }

        const falseBtn = e.target.closest('.false-btn');
        if (falseBtn) {
            const flowId = falseBtn.getAttribute('data-flowid');
            if (!flowId) return;
            if (!confirm('Mark this alert as false positive?')) return;
            this.socket.socket.emit('investigate_alert', { flow_id: flowId, note: 'Marked false positive', false_positive: true });
            const alert = Dashboard.alerts.find(a => a.flow_id === flowId);
            if (alert) {
                alert.acknowledged = true;
                alert.investigated = true;
                alert.investigator_notes = alert.investigator_notes || [];
                alert.investigator_notes.push({ note: 'Marked false positive', timestamp: new Date().toISOString(), false_positive: true });
                this.scheduleTableRefresh();
            }
            return;
        }
    }

    setupUI() {
        // Investigation modal elements and handlers
        this._currentInvestigationFlow = null;
        const modal = document.getElementById('investigateModal');
        if (modal) {
            const saveBtn = document.getElementById('investigateSaveBtn');
            const cancelBtn = document.getElementById('investigateCancelBtn');
            const noteInput = document.getElementById('investigationNoteInput');
            const invInput = document.getElementById('investigatorNameInput');
            saveBtn.addEventListener('click', () => {
                const flowId = this._currentInvestigationFlow;
                const note = noteInput.value.trim();
                const investigator = invInput.value.trim() || null;
                if (!flowId) return;
                this.socket.socket.emit('investigate_alert', { flow_id: flowId, note: note, investigator: investigator });
                // optimistic UI update
                const alert = Dashboard.alerts.find(a => a.flow_id === flowId);
                if (alert) {
                    alert.acknowledged = true;
                    alert.investigated = true;
                    alert.investigator_notes = alert.investigator_notes || [];
                    alert.investigator_notes.push({ note: note || '', timestamp: new Date().toISOString(), false_positive: false, investigator: investigator });
                    if (investigator) alert.investigator = investigator;
                    this.scheduleTableRefresh();
                }
                noteInput.value = '';
                invInput.value = '';
                this.hideInvestigationModal();
            });
            cancelBtn.addEventListener('click', () => {
                noteInput.value = '';
                invInput.value = '';
                this.hideInvestigationModal();
            });
        }
        const startBtn = document.getElementById('startBtn');
        if (startBtn) {
            startBtn.addEventListener('click', () => {
                this.socket.startIDS();
            });
        }

        const stopBtn = document.getElementById('stopBtn');
        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                this.socket.stopIDS();
            });
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === ' ' && e.target === document.body) {
                e.preventDefault();
                if (startBtn && !startBtn.disabled) {
                    this.socket.startIDS();
                } else if (stopBtn && !stopBtn.disabled) {
                    this.socket.stopIDS();
                }
            }
        });

        // Load history button (alerts page)
        const loadHistoryBtn = document.getElementById('loadHistoryBtn');
        if (loadHistoryBtn) {
            loadHistoryBtn.addEventListener('click', async () => {
                try {
                    const resp = await fetch('/alerts/history?limit=200');
                    if (!resp.ok) throw new Error('Failed to fetch');
                    const data = await resp.json();
                    if (data && Array.isArray(data)) {
                        Dashboard.addAlerts(data.map(d => d.alert || d));
                    }
                } catch (e) {
                    console.error('Failed loading history', e);
                    alert('Failed to load history');
                }
            });
        }

        // delegated click for alert acknowledge buttons and row clicks
        document.addEventListener('click', (e) => {
            // prioritize ack button handling
            this._handleAlertAction(e);
            // row click to inspect flow/alert (but not when clicking any
            // action button inside the row -- was only excluding .ack-btn,
            // so Investigate/False-Positive clicks also popped the
            // inspector panel open behind the modal/confirm dialog)
            const tr = e.target.closest('tr[data-flowid]');
            if (tr && !e.target.closest('.ack-btn') && !e.target.closest('.investigate-btn') && !e.target.closest('.false-btn')) {
                const flowId = tr.getAttribute('data-flowid');
                if (flowId) this.openInspector(flowId);
            }
        });
    }

    renderTableRows(tableBody, items, fields, highlightAttacks = false, type = 'flows') {
        if (!items || items.length === 0) {
            const colspan = type === 'alerts' ? (fields.length + 1) : fields.length;
            tableBody.innerHTML = `
                <tr>
                    <td colspan="${colspan}">
                        <div class="empty-state">
                            <h3>${type === 'alerts' ? 'No alerts yet' : 'No data yet'}</h3>
                            <p>${type === 'alerts' ? 'Wait for suspicious activity to be detected.' : 'Start the IDS and wait for packets to appear.'}</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        const rows = items.slice(0, 100).map(item => {
            const cells = fields.map(field => {
                let value = item[field] ?? '-';
                if (field === 'timestamp') {
                    value = Utils.formatTime(value);
                }
                if (field === 'confidence') {
                    const confidence = item.confidence ?? 0;
                    value = `${Math.round(confidence * 100)}%`;
                }
                // add IOC badge for alerts (after outcome field is rendered in its column)
                return `<td>${value}</td>`;
            }).join('');
            const highlight = highlightAttacks && item.outcome !== 'normal';
            const flowIdAttr = item.flow_id ? ` data-flowid="${item.flow_id}"` : '';
            let row = `<tr class="${highlight ? 'attack-row' : ''}"${flowIdAttr}>${cells}`;
            if (type === 'alerts') {
                const acked = item.acknowledged ? true : false;
                const ackBtn = `<button class="btn btn-sm btn-secondary ack-btn" data-flowid="${item.flow_id}" ${acked ? 'disabled' : ''}>${acked ? 'Acknowledged' : 'Acknowledge'}</button>`;
                const invBtn = `<button class="btn btn-sm btn-info investigate-btn" data-flowid="${item.flow_id}">Investigate</button>`;
                const falseBtn = `<button class="btn btn-sm btn-warning false-btn" data-flowid="${item.flow_id}">False Positive</button>`;
                row += `<td style="display:flex;gap:6px;">${ackBtn}${invBtn}${falseBtn}</td>`;
            }
            row += `</tr>`;
            return row;
        }).join('');

        tableBody.innerHTML = rows;

        // append IOC badges for alerts rows (non-blocking DOM ops)
        if (type === 'alerts') {
            try {
                const trs = tableBody.querySelectorAll('tr');
                for (let i = 0; i < trs.length && i < items.length && i < 100; i++) {
                    const it = items[i];
                    if (it && it.ioc_matches && it.ioc_matches.length) {
                        const td = trs[i].children[3]; // outcome column index
                        if (td) td.innerHTML = td.innerHTML + ` <span class="ioc-badge">IOC</span>`;
                    }
                }
            } catch (e) {
                // swallow UI errors
            }
        }
    }

    openInspector(flowId) {
        // find flow or alert by flowId
        const byFlow = (arr) => arr.find(f => f.flow_id === flowId);
        const item = byFlow(Dashboard.flows) || byFlow(Dashboard.alerts);
        const panel = document.getElementById('inspectorPanel');
        const body = document.getElementById('inspectorBody');
        const title = document.getElementById('inspectorTitle');
        const exportBtn = document.getElementById('exportJsonBtn');
        if (!panel || !body) return;
        if (!item) {
            body.innerHTML = '<p class="empty-state">Details not available</p>';
            title.textContent = 'Inspector';
        } else {
            title.textContent = `Inspector — ${item.flow_id || item.src_ip || 'item'}`;
            // render details as dl list
            const entries = [];
            for (const k of Object.keys(item)) {
                const v = item[k];
                let display = v;
                if (k === 'timestamp') display = Utils.formatTime(v);
                if (typeof v === 'object') display = JSON.stringify(v);
                entries.push(`<dt>${k}</dt><dd>${display}</dd>`);
            }
            body.innerHTML = `<dl>${entries.join('\n')}</dl>`;
            exportBtn.onclick = () => this.exportFlowJson(item);
        }
        panel.classList.add('open');
        panel.setAttribute('aria-hidden', 'false');
    }

    closeInspector() {
        const panel = document.getElementById('inspectorPanel');
        if (!panel) return;
        panel.classList.remove('open');
        panel.setAttribute('aria-hidden', 'true');
    }

    exportFlowJson(item) {
        const filename = `${item.flow_id || 'flow'}-${(item.timestamp || '').replace(/[:.]/g,'-')}.json`;
        const dataStr = JSON.stringify(item, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    updateSummaryCards() {
        const totalPackets = document.getElementById('totalPackets');
        const attackPackets = document.getElementById('attackPackets');
        const captureStatus = document.getElementById('captureStatus');
        const packetRate = document.getElementById('packetRate');
        const uptime = document.getElementById('uptime');

        if (totalPackets) totalPackets.textContent = Dashboard.counters.packets;
        if (attackPackets) attackPackets.textContent = Dashboard.counters.attacks;
        if (captureStatus) captureStatus.textContent = Dashboard.health.capture_status || 'STOPPED';
        if (packetRate) packetRate.textContent = `${Dashboard.health.packets_per_sec || 0} pkt/s`;
        if (uptime) uptime.textContent = Dashboard.health.uptime || '00:00:00';

        // large summary numbers on dashboard
        const packetRateLarge = document.getElementById('packetRateLarge');
        const attacksRateLarge = document.getElementById('attacksRateLarge');
        const alertCountLarge = document.getElementById('alertCountLarge');
        if (packetRateLarge) packetRateLarge.textContent = Dashboard.health.packets_per_sec || 0;
        if (attacksRateLarge) attacksRateLarge.textContent = Dashboard.health.attacks_per_sec || 0;
        if (alertCountLarge) alertCountLarge.textContent = Dashboard.counters.alerts || 0;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new App();
});

// Modal helpers
App.prototype.showInvestigationModal = function(flowId) {
    const modal = document.getElementById('investigateModal');
    const noteInput = document.getElementById('investigationNoteInput');
    const invInput = document.getElementById('investigatorNameInput');
    if (!modal) return;
    this._currentInvestigationFlow = flowId;
    noteInput.value = '';
    invInput.value = '';
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
}

App.prototype.hideInvestigationModal = function() {
    const modal = document.getElementById('investigateModal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    this._currentInvestigationFlow = null;
}