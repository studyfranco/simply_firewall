document.addEventListener("DOMContentLoaded", () => {
    // ─── DOM References ────────────────────────────────────
    const apiKeyInput = document.getElementById("api-key-input");
    const ipTableBody = document.getElementById("ip-table-body");
    const statusFilter = document.getElementById("status-filter");
    const refreshBtn = document.getElementById("refresh-btn");
    const toastContainer = document.getElementById("toast-container");

    const TABLE_COLS = 5;
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    // ─── State ─────────────────────────────────────────────
    let currentPage = 0;
    const limit = 10;

    // ─── API Key persistence ───────────────────────────────
    const savedKey = localStorage.getItem("simply_firewall_key");
    if (savedKey) apiKeyInput.value = savedKey;

    apiKeyInput.addEventListener("change", (e) => {
        localStorage.setItem("simply_firewall_key", e.target.value);
        loadData();
    });

    if (savedKey) loadData();

    // ─── Tab Navigation ────────────────────────────────────
    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach((b) => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));

            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");
            const target = document.getElementById(`tab-${btn.dataset.tab}`);
            if (target) target.classList.add("active");

            // Auto-load admin data when switching to that tab
            if (btn.dataset.tab === "admin") {
                loadAdminData();
            }
        });
    });

    // ─── Firewall — Event Listeners ────────────────────────
    refreshBtn.addEventListener("click", () => {
        currentPage = 0;
        loadData();
    });

    statusFilter.addEventListener("change", () => {
        currentPage = 0;
        loadData();
    });

    document.getElementById("btn-prev").addEventListener("click", () => {
        if (currentPage > 0) {
            currentPage--;
            loadData();
        }
    });

    document.getElementById("btn-next").addEventListener("click", () => {
        currentPage++;
        loadData();
    });

    // ─── Firewall — Data Loading ───────────────────────────

    async function loadData() {
        const key = apiKeyInput.value.trim();
        if (!key) return;

        const params = new URLSearchParams({ limit, page: currentPage });
        if (statusFilter.value) params.append("status", statusFilter.value);

        try {
            const res = await fetch(`/api/ips?${params.toString()}`, {
                headers: { "x-api-key": key },
            });

            if (!res.ok) {
                if (res.status === 401 || res.status === 403) {
                    showTableError("Unauthorized or Forbidden: Check API Key and IP bindings.");
                } else {
                    showTableError(`Error fetching data (${res.status})`);
                }
                return;
            }

            const data = await res.json();
            renderTable(data);

            document.getElementById("page-indicator").textContent = `Page ${currentPage + 1}`;
            document.getElementById("btn-prev").disabled = currentPage === 0;
            document.getElementById("btn-next").disabled = data.length < limit;
        } catch (err) {
            showTableError("Network Error or Server Unreachable.");
        }
    }

    // ─── Firewall — Table Rendering ────────────────────────

    function renderTable(data) {
        if (!data || data.length === 0) {
            ipTableBody.innerHTML = `<tr><td colspan="${TABLE_COLS}" class="text-center text-muted">No records found.</td></tr>`;
            return;
        }

        ipTableBody.innerHTML = data
            .map((record) => {
                const statusClass = record.is_whitelist ? "badge-white" : "badge-ban";
                const statusText = record.is_whitelist ? "Whitelist" : "Banned";
                const date = new Date(record.updated_at).toLocaleString();
                const cause = escapeHtml(record.cause || "—");
                const groupId = record.group_id || "—";

                return `
                <tr>
                    <td class="font-mono">${escapeHtml(record.address)}</td>
                    <td><span class="badge ${statusClass}">${statusText}</span></td>
                    <td class="text-sm">${cause}</td>
                    <td class="text-muted text-sm">${escapeHtml(String(groupId))}</td>
                    <td class="text-sm">${date}</td>
                </tr>`;
            })
            .join("");
    }

    function showTableError(msg) {
        ipTableBody.innerHTML = `<tr><td colspan="${TABLE_COLS}" class="text-center text-danger">${escapeHtml(msg)}</td></tr>`;
    }

    // ─── Firewall — Form Submissions ───────────────────────

    document.getElementById("manage-form").addEventListener("submit", (e) => {
        e.preventDefault();
        submitIpAction(false);
    });

    document.getElementById("btn-ban").addEventListener("click", (e) => {
        e.preventDefault();
        submitIpAction(false);
    });

    document.getElementById("btn-white").addEventListener("click", (e) => {
        e.preventDefault();
        submitIpAction(true);
    });

    async function submitIpAction(isWhitelist) {
        const key = apiKeyInput.value.trim();
        if (!key) {
            showMessage("Please enter your API Key first.", "error");
            return;
        }

        const address = document.getElementById("ip-address").value.trim();
        const groupIdRaw = document.getElementById("group-id").value.trim();
        const cause = document.getElementById("cause").value.trim() || null;

        if (!address) return;

        // UUID validation for group_id
        const groupIdInput = document.getElementById("group-id");
        let groupId = null;
        if (groupIdRaw) {
            if (!UUID_REGEX.test(groupIdRaw)) {
                groupIdInput.classList.add("input-error");
                showMessage("Group ID must be a valid UUID (e.g. 550e8400-e29b-41d4-a716-446655440000).", "error");
                return;
            }
            groupId = groupIdRaw;
        }
        groupIdInput.classList.remove("input-error");

        const endpoint = isWhitelist ? "/api/white" : "/api/ban";

        try {
            const res = await fetch(endpoint, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": key,
                },
                body: JSON.stringify({ address, group_id: groupId, cause }),
            });

            if (res.ok) {
                const action = isWhitelist ? "whitelisted" : "banned";
                showMessage(`Successfully ${action} ${address}`, "success");
                showToast(`${address} ${action} successfully`, "success");
                document.getElementById("ip-address").value = "";
                document.getElementById("cause").value = "";
                currentPage = 0;
                loadData();
            } else {
                const text = await res.text().catch(() => "");
                showMessage(`Failed: Server returned ${res.status}. ${text}`, "error");
            }
        } catch (err) {
            showMessage("Network Error.", "error");
        }
    }

    // ─── Inline Form Message ───────────────────────────────

    function showMessage(msg, type) {
        const msgDiv = document.getElementById("form-message");
        msgDiv.textContent = msg;
        msgDiv.className = `message ${type}`;
        msgDiv.classList.remove("hidden");
        setTimeout(() => msgDiv.classList.add("hidden"), 5000);
    }

    // ═══════════════════════════════════════════════════════
    // ADMIN PANEL
    // ═══════════════════════════════════════════════════════

    function getApiKey() {
        return apiKeyInput.value.trim();
    }

    function adminHeaders() {
        return {
            "Content-Type": "application/json",
            "x-api-key": getApiKey(),
        };
    }

    async function loadAdminData() {
        if (!getApiKey()) return;
        await Promise.all([loadApiKeys(), loadIpGroups(), loadWebhooks()]);
    }

    // ─── Admin — API Keys ──────────────────────────────────

    document.getElementById("form-create-apikey").addEventListener("submit", async (e) => {
        e.preventDefault();
        const key = getApiKey();
        if (!key) { showToast("Enter your API key first.", "error"); return; }

        const boundIp = document.getElementById("apikey-bound-ip").value.trim();
        if (!boundIp) return;

        try {
            const res = await fetch("/api/admin/api-keys", {
                method: "POST",
                headers: adminHeaders(),
                body: JSON.stringify({ bound_ip: boundIp }),
            });

            if (!res.ok) {
                showToast(`Failed to create API key (${res.status})`, "error");
                return;
            }

            const data = await res.json();

            // Show the one-time plaintext key
            const revealBox = document.getElementById("apikey-created");
            document.getElementById("apikey-plaintext").textContent = data.plaintext_key;
            revealBox.classList.remove("hidden");

            showToast("API Key created successfully", "success");
            document.getElementById("apikey-bound-ip").value = "";
            loadApiKeys();
        } catch (err) {
            showToast("Network error creating API key.", "error");
        }
    });

    async function loadApiKeys() {
        const tbody = document.getElementById("apikeys-table-body");
        try {
            const res = await fetch("/api/admin/api-keys", {
                headers: { "x-api-key": getApiKey() },
            });
            if (!res.ok) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-center text-danger">Failed to load (${res.status})</td></tr>`;
                return;
            }
            const data = await res.json();
            if (!data.length) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No API keys found.</td></tr>`;
                return;
            }
            tbody.innerHTML = data
                .map(
                    (k) => `
                <tr>
                    <td class="font-mono text-sm">${escapeHtml(k.id)}</td>
                    <td class="font-mono">${escapeHtml(k.bound_ip)}</td>
                    <td><button class="btn-danger-outline" data-delete-apikey="${k.id}">Delete</button></td>
                </tr>`
                )
                .join("");

            // Attach delete handlers
            tbody.querySelectorAll("[data-delete-apikey]").forEach((btn) => {
                btn.addEventListener("click", () => deleteApiKey(btn.dataset.deleteApikey));
            });
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="3" class="text-center text-danger">Network error.</td></tr>`;
        }
    }

    async function deleteApiKey(id) {
        if (!confirm("Delete this API key? This action cannot be undone.")) return;
        try {
            const res = await fetch(`/api/admin/api-keys/${id}`, {
                method: "DELETE",
                headers: { "x-api-key": getApiKey() },
            });
            if (res.ok || res.status === 204) {
                showToast("API Key deleted.", "success");
                loadApiKeys();
            } else {
                showToast(`Delete failed (${res.status})`, "error");
            }
        } catch (err) {
            showToast("Network error.", "error");
        }
    }

    // ─── Admin — IP Groups ─────────────────────────────────

    document.getElementById("form-create-group").addEventListener("submit", async (e) => {
        e.preventDefault();
        const key = getApiKey();
        if (!key) { showToast("Enter your API key first.", "error"); return; }

        const name = document.getElementById("group-name").value.trim();
        if (!name) return;

        try {
            const res = await fetch("/api/admin/ip-groups", {
                method: "POST",
                headers: adminHeaders(),
                body: JSON.stringify({ name }),
            });

            if (!res.ok) {
                showToast(`Failed to create group (${res.status})`, "error");
                return;
            }

            showToast("IP Group created.", "success");
            document.getElementById("group-name").value = "";
            loadIpGroups();
        } catch (err) {
            showToast("Network error creating group.", "error");
        }
    });

    async function loadIpGroups() {
        const tbody = document.getElementById("groups-table-body");
        try {
            const res = await fetch("/api/admin/ip-groups", {
                headers: { "x-api-key": getApiKey() },
            });
            if (!res.ok) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-center text-danger">Failed to load (${res.status})</td></tr>`;
                return;
            }
            const data = await res.json();
            if (!data.length) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No groups found.</td></tr>`;
                return;
            }
            tbody.innerHTML = data
                .map(
                    (g) => `
                <tr>
                    <td class="font-mono text-sm">${escapeHtml(g.id)}</td>
                    <td>${escapeHtml(g.name)}</td>
                    <td><button class="btn-danger-outline" data-delete-group="${g.id}">Delete</button></td>
                </tr>`
                )
                .join("");

            tbody.querySelectorAll("[data-delete-group]").forEach((btn) => {
                btn.addEventListener("click", () => deleteIpGroup(btn.dataset.deleteGroup));
            });
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="3" class="text-center text-danger">Network error.</td></tr>`;
        }
    }

    async function deleteIpGroup(id) {
        if (!confirm("Delete this IP group? Associated records will have their group_id set to NULL.")) return;
        try {
            const res = await fetch(`/api/admin/ip-groups/${id}`, {
                method: "DELETE",
                headers: { "x-api-key": getApiKey() },
            });
            if (res.ok || res.status === 204) {
                showToast("IP Group deleted.", "success");
                loadIpGroups();
            } else {
                showToast(`Delete failed (${res.status})`, "error");
            }
        } catch (err) {
            showToast("Network error.", "error");
        }
    }

    // ─── Admin — Webhooks ──────────────────────────────────

    document.getElementById("form-create-webhook").addEventListener("submit", async (e) => {
        e.preventDefault();
        const key = getApiKey();
        if (!key) { showToast("Enter your API key first.", "error"); return; }

        const targetUrl = document.getElementById("webhook-url").value.trim();
        const groupIdRaw = document.getElementById("webhook-group-id").value.trim();

        if (!targetUrl) return;

        // UUID validation for optional group_id
        const groupInput = document.getElementById("webhook-group-id");
        let groupId = null;
        if (groupIdRaw) {
            if (!UUID_REGEX.test(groupIdRaw)) {
                groupInput.classList.add("input-error");
                showToast("Group ID must be a valid UUID.", "error");
                return;
            }
            groupId = groupIdRaw;
        }
        groupInput.classList.remove("input-error");

        try {
            const res = await fetch("/api/admin/webhooks", {
                method: "POST",
                headers: adminHeaders(),
                body: JSON.stringify({ target_url: targetUrl, group_id: groupId }),
            });

            if (!res.ok) {
                showToast(`Failed to create webhook (${res.status})`, "error");
                return;
            }

            showToast("Webhook created.", "success");
            document.getElementById("webhook-url").value = "";
            document.getElementById("webhook-group-id").value = "";
            loadWebhooks();
        } catch (err) {
            showToast("Network error creating webhook.", "error");
        }
    });

    async function loadWebhooks() {
        const tbody = document.getElementById("webhooks-table-body");
        try {
            const res = await fetch("/api/admin/webhooks", {
                headers: { "x-api-key": getApiKey() },
            });
            if (!res.ok) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">Failed to load (${res.status})</td></tr>`;
                return;
            }
            const data = await res.json();
            if (!data.length) {
                tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No webhook configs found.</td></tr>`;
                return;
            }
            tbody.innerHTML = data
                .map(
                    (w) => `
                <tr>
                    <td class="font-mono text-sm">${escapeHtml(w.id)}</td>
                    <td class="truncate">${escapeHtml(w.target_url)}</td>
                    <td class="text-muted text-sm">${w.group_id ? escapeHtml(w.group_id) : "—"}</td>
                    <td><button class="btn-danger-outline" data-delete-webhook="${w.id}">Delete</button></td>
                </tr>`
                )
                .join("");

            tbody.querySelectorAll("[data-delete-webhook]").forEach((btn) => {
                btn.addEventListener("click", () => deleteWebhook(btn.dataset.deleteWebhook));
            });
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">Network error.</td></tr>`;
        }
    }

    async function deleteWebhook(id) {
        if (!confirm("Delete this webhook configuration?")) return;
        try {
            const res = await fetch(`/api/admin/webhooks/${id}`, {
                method: "DELETE",
                headers: { "x-api-key": getApiKey() },
            });
            if (res.ok || res.status === 204) {
                showToast("Webhook deleted.", "success");
                loadWebhooks();
            } else {
                showToast(`Delete failed (${res.status})`, "error");
            }
        } catch (err) {
            showToast("Network error.", "error");
        }
    }

    // ═══════════════════════════════════════════════════════
    // SHARED UTILITIES
    // ═══════════════════════════════════════════════════════

    function showToast(msg, type = "success") {
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.textContent = msg;
        toastContainer.appendChild(toast);

        requestAnimationFrame(() => toast.classList.add("visible"));

        setTimeout(() => {
            toast.classList.remove("visible");
            toast.addEventListener("transitionend", () => toast.remove());
        }, 3500);
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
});
