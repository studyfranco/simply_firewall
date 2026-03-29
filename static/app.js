document.addEventListener("DOMContentLoaded", () => {
    // ─── DOM References ────────────────────────────────────
    const loginScreen = document.getElementById("login-screen");
    const loginForm = document.getElementById("login-form");
    const loginKeyInput = document.getElementById("login-key");
    const loginError = document.getElementById("login-error");
    const loginSubmit = document.getElementById("login-submit");

    const dashboardContainer = document.getElementById("dashboard-container");
    const logoutBtn = document.getElementById("logout-btn");
    const refreshBtn = document.getElementById("refresh-btn");

    const ipTableBody = document.getElementById("ip-table-body");
    const statusFilter = document.getElementById("status-filter");
    const toastContainer = document.getElementById("toast-container");

    const STORAGE_KEY = "api_key";
    const TABLE_COLS = 5;
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    // ─── State ─────────────────────────────────────────────
    let currentPage = 0;
    const limit = 10;

    // ─── API Wrapper (Centralized Auth Interceptor) ─────────

    /**
     * Centralized fetch wrapper that injects API key and handles 401/403.
     */
    async function apiFetch(url, options = {}) {
        const key = localStorage.getItem(STORAGE_KEY);

        // Merge headers
        const headers = {
            "X-API-Key": key || "",
            "Content-Type": "application/json",
            ...(options.headers || {})
        };

        try {
            const response = await fetch(url, { ...options, headers });

            // Global 401/403 Handling
            if (response.status === 401 || response.status === 403) {
                const wasLoggedIn = !!localStorage.getItem(STORAGE_KEY);
                handleSessionExpired(wasLoggedIn);
                return null;
            }

            return response;
        } catch (error) {
            console.error("Fetch error:", error);
            showToast("Network error. Please check your connection.", "error");
            return null;
        }
    }

    // ─── Auth Logic ────────────────────────────────────────

    /**
     * Validates the API key by making a lightweight request.
     */
    async function validateKey(key) {
        // Temporarily set the key for the validation request
        const originalKey = localStorage.getItem(STORAGE_KEY);
        localStorage.setItem(STORAGE_KEY, key);

        const res = await apiFetch("/api/ips?limit=1");

        // If it failed or was unauthorized, don't keep the key
        if (!res || !res.ok) {
            if (originalKey) localStorage.setItem(STORAGE_KEY, originalKey);
            else localStorage.removeItem(STORAGE_KEY);
            return false;
        }

        return true;
    }

    function handleSessionExpired(notify = true) {
        localStorage.removeItem(STORAGE_KEY);
        showLogin();
        if (notify) {
            alert("Your session or API key has expired. Please log in again.");
        }
    }

    function showDashboard() {
        loginScreen.classList.add("hidden");
        dashboardContainer.classList.remove("hidden");
        // Trigger initial load
        loadData();
        showToast("Dashboard unlocked", "success");
    }

    function showLogin(errorMsg = null) {
        dashboardContainer.classList.add("hidden");
        loginScreen.classList.remove("hidden");
        if (errorMsg) {
            loginError.textContent = errorMsg;
            loginError.classList.remove("hidden");
        } else {
            loginError.classList.add("hidden");
        }
    }

    function logout() {
        localStorage.removeItem(STORAGE_KEY);
        showLogin();
        showToast("Logged out successfully");
    }

    // ─── Initialization & Auto-Login ───────────────────────

    async function init() {
        const savedKey = localStorage.getItem(STORAGE_KEY);
        if (savedKey) {
            // Background validation test
            const isValid = await validateKey(savedKey);
            if (isValid) {
                showDashboard();
            } else {
                handleSessionExpired(false);
            }
        } else {
            showLogin();
        }
    }

    init();

    // ─── Event Listeners ───────────────────────────────────

    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const key = loginKeyInput.value.trim();
        if (!key) return;

        loginSubmit.disabled = true;
        loginSubmit.textContent = "Validating...";
        loginError.classList.add("hidden");

        const isValid = await validateKey(key);

        if (isValid) {
            localStorage.setItem(STORAGE_KEY, key);
            showDashboard();
            loginKeyInput.value = "";
        } else {
            showLogin("Invalid API Key. Please try again.");
        }

        loginSubmit.disabled = false;
        loginSubmit.textContent = "Unlock Dashboard";
    });

    logoutBtn.addEventListener("click", logout);

    refreshBtn.addEventListener("click", () => {
        currentPage = 0;
        loadData();
    });

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
        const params = new URLSearchParams({ limit, page: currentPage });
        if (statusFilter.value) params.append("status", statusFilter.value);

        const res = await apiFetch(`/api/ips?${params.toString()}`);
        if (!res) return;

        if (!res.ok) {
            showTableError(`Error fetching data (${res.status})`);
            return;
        }

        const data = await res.json();
        renderTable(data);

        document.getElementById("page-indicator").textContent = `Page ${currentPage + 1}`;
        document.getElementById("btn-prev").disabled = currentPage === 0;
        document.getElementById("btn-next").disabled = data.length < limit;
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
                showMessage("Group ID must be a valid UUID.", "error");
                return;
            }
            groupId = groupIdRaw;
        }
        groupIdInput.classList.remove("input-error");

        const endpoint = isWhitelist ? "/api/white" : "/api/ban";

        const res = await apiFetch(endpoint, {
            method: "POST",
            body: JSON.stringify({ target_address: address, group_id: groupId, cause }),
        });

        if (!res) return;

        if (res.ok) {
            const action = isWhitelist ? "whitelisted" : "banned";
            showMessage(`Successfully ${action} ${address}`, "success");
            showToast(`${address} ${action} successfully`, "success");
            document.getElementById("ip-address").value = "";
            document.getElementById("cause").value = "";
            document.getElementById("group-id").value = "";
            currentPage = 0;
            loadData();
        } else {
            const text = await res.text().catch(() => "");
            showMessage(`Failed: Server returned ${res.status}. ${text}`, "error");
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

    async function loadAdminData() {
        await Promise.all([loadApiKeys(), loadIpGroups(), loadWebhooks()]);
    }

    // ─── Admin — API Keys ──────────────────────────────────

    document.getElementById("form-create-apikey").addEventListener("submit", async (e) => {
        e.preventDefault();
        const boundIp = document.getElementById("apikey-bound-ip").value.trim();
        if (!boundIp) return;

        const res = await apiFetch("/api/admin/api-keys", {
            method: "POST",
            body: JSON.stringify({ bound_ip: boundIp }),
        });

        if (!res) return;

        if (!res.ok) {
            showToast(`Failed to create API key (${res.status})`, "error");
            return;
        }

        const data = await res.json();
        const revealBox = document.getElementById("apikey-created");
        document.getElementById("apikey-plaintext").textContent = data.plaintext_key;
        revealBox.classList.remove("hidden");

        showToast("API Key created successfully", "success");
        document.getElementById("apikey-bound-ip").value = "";
        loadApiKeys();
    });

    async function loadApiKeys() {
        const tbody = document.getElementById("apikeys-table-body");
        const res = await apiFetch("/api/admin/api-keys");
        if (!res) return;

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

        tbody.querySelectorAll("[data-delete-apikey]").forEach((btn) => {
            btn.addEventListener("click", () => deleteApiKey(btn.dataset.deleteApikey));
        });
    }

    async function deleteApiKey(id) {
        if (!confirm("Delete this API key?")) return;
        const res = await apiFetch(`/api/admin/api-keys/${id}`, {
            method: "DELETE",
        });
        if (!res) return;

        if (res.ok || res.status === 204) {
            showToast("API Key deleted.", "success");
            loadApiKeys();
        } else {
            showToast(`Delete failed (${res.status})`, "error");
        }
    }

    // ─── Admin — IP Groups ─────────────────────────────────

    document.getElementById("form-create-group").addEventListener("submit", async (e) => {
        e.preventDefault();
        const name = document.getElementById("group-name").value.trim();
        if (!name) return;

        const res = await apiFetch("/api/admin/ip-groups", {
            method: "POST",
            body: JSON.stringify({ name }),
        });

        if (!res) return;

        if (!res.ok) {
            showToast(`Failed to create group (${res.status})`, "error");
            return;
        }

        showToast("IP Group created.", "success");
        document.getElementById("group-name").value = "";
        loadIpGroups();
    });

    async function loadIpGroups() {
        const tbody = document.getElementById("groups-table-body");
        const res = await apiFetch("/api/admin/ip-groups");
        if (!res) return;

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
    }

    async function deleteIpGroup(id) {
        if (!confirm("Delete this IP group?")) return;
        const res = await apiFetch(`/api/admin/ip-groups/${id}`, {
            method: "DELETE",
        });
        if (!res) return;

        if (res.ok || res.status === 204) {
            showToast("IP Group deleted.", "success");
            loadIpGroups();
        } else {
            showToast(`Delete failed (${res.status})`, "error");
        }
    }

    // ─── Admin — Webhooks ──────────────────────────────────

    document.getElementById("form-create-webhook").addEventListener("submit", async (e) => {
        e.preventDefault();
        const targetUrl = document.getElementById("webhook-url").value.trim();
        const groupIdRaw = document.getElementById("webhook-group-id").value.trim();

        if (!targetUrl) return;

        let groupId = null;
        if (groupIdRaw) {
            if (!UUID_REGEX.test(groupIdRaw)) {
                showToast("Group ID must be a valid UUID.", "error");
                return;
            }
            groupId = groupIdRaw;
        }

        const res = await apiFetch("/api/admin/webhooks", {
            method: "POST",
            body: JSON.stringify({ target_url: targetUrl, group_id: groupId }),
        });

        if (!res) return;

        if (!res.ok) {
            showToast(`Failed to create webhook (${res.status})`, "error");
            return;
        }

        showToast("Webhook created.", "success");
        document.getElementById("webhook-url").value = "";
        document.getElementById("webhook-group-id").value = "";
        loadWebhooks();
    });

    async function loadWebhooks() {
        const tbody = document.getElementById("webhooks-table-body");
        const res = await apiFetch("/api/admin/webhooks");
        if (!res) return;

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
    }

    async function deleteWebhook(id) {
        if (!confirm("Delete this webhook?")) return;
        const res = await apiFetch(`/api/admin/webhooks/${id}`, {
            method: "DELETE",
        });
        if (!res) return;

        if (res.ok || res.status === 204) {
            showToast("Webhook deleted.", "success");
            loadWebhooks();
        } else {
            showToast(`Delete failed (${res.status})`, "error");
        }
    }

    // ─── Shared Utilities ──────────────────────────────────

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
