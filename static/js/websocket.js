/**
 * DocShield Real-Time WebSocket Client
 * Establishes authenticated WebSocket connection, handles reconnects safely,
 * and updates UI/DOM live without full page reloads.
 */

class DocShieldWebSocket {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectDelay = 10000;
        this.pingInterval = null;
        this.init();
    }

    init() {
        // Connect via ws:// or wss:// based on current protocol
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.updateStatusBadge("connecting");

        try {
            this.socket = new WebSocket(wsUrl);
        } catch (err) {
            console.error("WebSocket init failed:", err);
            this.scheduleReconnect();
            return;
        }

        this.socket.onopen = () => {
            console.log("WebSocket connected to DocShield.");
            this.reconnectAttempts = 0;
            this.updateStatusBadge("connected");

            // Heartbeat ping every 25 seconds
            clearInterval(this.pingInterval);
            this.pingInterval = setInterval(() => {
                if (this.socket && this.socket.readyState === WebSocket.OPEN) {
                    this.socket.send(JSON.stringify({ type: "ping" }));
                }
            }, 25000);
        };

        this.socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleEvent(data);
            } catch (e) {
                console.warn("Failed to parse WebSocket message:", event.data);
            }
        };

        this.socket.onclose = (event) => {
            console.warn("WebSocket disconnected. Code:", event.code);
            clearInterval(this.pingInterval);
            this.updateStatusBadge("disconnected");
            this.scheduleReconnect();
        };

        this.socket.onerror = (err) => {
            console.error("WebSocket error:", err);
            this.socket.close();
        };
    }

    scheduleReconnect() {
        this.reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), this.maxReconnectDelay);
        console.log(`Reconnecting WebSocket in ${Math.round(delay)}ms...`);
        setTimeout(() => this.init(), delay);
    }

    updateStatusBadge(status) {
        const badge = document.getElementById("ws-status");
        const pulse = document.getElementById("ws-pulse");
        if (!badge || !pulse) return;

        if (status === "connected") {
            badge.innerText = "Real-Time Active";
            pulse.classList.remove("disconnected");
        } else if (status === "connecting") {
            badge.innerText = "Connecting...";
            pulse.classList.add("disconnected");
        } else {
            badge.innerText = "Reconnecting...";
            pulse.classList.add("disconnected");
        }
    }

    handleEvent(data) {
        if (!data || !data.type) return;

        switch (data.type) {
            case "DOCUMENT_UPLOADED":
                this.showToast(data.message || "Document uploaded successfully.", "success");
                // Reload dashboard tab smoothly or update counters
                setTimeout(() => window.location.reload(), 1200);
                break;

            case "DOCUMENT_SHARED":
                this.showToast(data.message || "A new document was shared with you.", "info");
                setTimeout(() => window.location.reload(), 1500);
                break;

            case "ACCESS_REVOKED":
                this.showToast(data.message || "Access to document was revoked.", "warning");
                // Remove document row immediately from DOM if currently rendered
                const revokedRow = document.getElementById(`shared-doc-${data.document_id}`);
                if (revokedRow) {
                    revokedRow.style.transition = "opacity 0.4s ease";
                    revokedRow.style.opacity = "0";
                    setTimeout(() => revokedRow.remove(), 400);
                } else {
                    setTimeout(() => window.location.reload(), 1500);
                }
                break;

            case "DOCUMENT_DELETED":
                this.showToast(data.message || "Document was permanently deleted.", "warning");
                const deletedRowOwned = document.getElementById(`owned-doc-${data.document_id}`);
                const deletedRowShared = document.getElementById(`shared-doc-${data.document_id}`);
                if (deletedRowOwned) deletedRowOwned.remove();
                if (deletedRowShared) deletedRowShared.remove();
                break;

            case "SECURITY_ALERT":
                this.showToast(`🚨 ${data.message}`, "danger");
                this.appendActivityRow({
                    action: "UNAUTHORIZED_ACCESS_ATTEMPT",
                    actor: data.actor,
                    decision: "DENIED",
                    reason: data.reason,
                    title: data.title,
                    time: "Just now"
                });
                break;

            case "PERMISSION_UPDATED":
                this.showToast(data.message, "info");
                break;

            case "pong":
                // Heartbeat response
                break;

            default:
                if (data.message) {
                    this.showToast(data.message, "info");
                }
        }
    }

    appendActivityRow(act) {
        const feed = document.getElementById("live-activity-body");
        if (!feed) return;
        const tr = document.createElement("tr");
        tr.className = "filterable-row";
        tr.style.backgroundColor = "rgba(239, 68, 68, 0.1)";
        tr.innerHTML = `
            <td><span class="badge badge-danger">${act.decision}</span></td>
            <td><strong>${act.action}</strong></td>
            <td>${act.actor}</td>
            <td>${act.title || "-"}</td>
            <td><code class="code-badge">${act.reason}</code></td>
            <td style="color:var(--text-dim);font-size:0.8rem;">${act.time}</td>
        `;
        feed.insertBefore(tr, feed.firstChild);
    }

    showToast(message, type = "info") {
        let container = document.getElementById("toast-container");
        if (!container) {
            container = document.createElement("div");
            container.id = "toast-container";
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        
        const icon = type === "success" ? "✓" : (type === "danger" ? "✕" : (type === "warning" ? "!" : "ℹ"));
        
        toast.innerHTML = `
            <div style="font-weight:bold;font-size:1.1rem;">${icon}</div>
            <div style="flex:1;font-size:0.88rem;color:#f1f5f9;">${message}</div>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
            toast.style.opacity = "0";
            toast.style.transform = "translateX(20px)";
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }
}

// Initialize on page load if user is logged in
document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("ws-status")) {
        window.docShieldWS = new DocShieldWebSocket();
    }
});
