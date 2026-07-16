// static/js/utils.js
export const Utils = {
    formatTime(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    formatTimeOnly(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        return date.toLocaleTimeString();
    },

    confidenceColor(confidence) {
        const value = confidence || 0;
        if (value > 0.7) return '#00ff88';
        if (value > 0.4) return '#ffd700';
        return '#ff4444';
    },

    truncate(str, maxLen = 20) {
        if (!str) return '-';
        return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
    },

    getSeverity(outcome) {
        const map = {
            'neptune': 'HIGH',
            'portsweep': 'MEDIUM',
            'ipsweep': 'MEDIUM',
            'smurf': 'HIGH',
            'satan': 'HIGH',
            'normal': 'LOW'
        };
        return map[outcome] || 'MEDIUM';
    },

    getSeverityColor(severity) {
        const map = {
            'HIGH': '#ef4444',
            'MEDIUM': '#f59e0b',
            'LOW': '#10b981'
        };
        return map[severity] || '#888888';
    }
};