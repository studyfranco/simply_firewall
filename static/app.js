document.addEventListener("DOMContentLoaded", () => {
    const apiKeyInput = document.getElementById("api-key-input");
    const ipTableBody = document.getElementById("ip-table-body");
    const statusFilter = document.getElementById("status-filter");
    const refreshBtn = document.getElementById("refresh-btn");
    const toastContainer = document.getElementById("toast-container");

    const TABLE_COLS = 5;

    // Pagination state
    let currentPage = 0;
    const limit = 10;

    // Auto-save API key
    const savedKey = localStorage.getItem("simply_firewall_key");
    if (savedKey) apiKeyInput.value = savedKey;

    apiKeyInput.addEventListener("change", (e) => {
        localStorage.setItem("simply_firewall_key", e.target.value);
        loadData();
    });

    // Initial fetch
    if (savedKey) loadData();

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

    // ─── Data Loading ──────────────────────────────────────

    async function loadData() {
        const key = apiKeyInput.value.trim();
        if (!key) return;

        const params = new URLSearchParams({
            limit: limit,
            page: currentPage,
        });

        if (statusFilter.value) {
            params.append("status", statusFilter.value);
        }

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

    // ─── Table Rendering ───────────────────────────────────

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
                    <td class="text-muted text-sm">${groupId}</td>
                    <td class="text-sm">${date}</td>
                </tr>
            `;
            })
            .join("");
    }

    function showTableError(msg) {
        ipTableBody.innerHTML = `<tr><td colspan="${TABLE_COLS}" class="text-center text-danger">${escapeHtml(msg)}</td></tr>`;
    }

    // ─── Form Submissions ──────────────────────────────────

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
        const groupId = document.getElementById("group-id").value.trim() || null;
        const cause = document.getElementById("cause").value.trim() || null;

        if (!address) return;

        const endpoint = isWhitelist ? "/api/white" : "/api/ban";

        try {
            const res = await fetch(endpoint, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": key,
                },
                body: JSON.stringify({
                    address,
                    group_id: groupId,
                    cause,
                }),
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

        setTimeout(() => {
            msgDiv.classList.add("hidden");
        }, 5000);
    }

    // ─── Toast Notifications ───────────────────────────────

    function showToast(msg, type = "success") {
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.textContent = msg;
        toastContainer.appendChild(toast);

        // Trigger reflow then animate in
        requestAnimationFrame(() => {
            toast.classList.add("visible");
        });

        setTimeout(() => {
            toast.classList.remove("visible");
            toast.addEventListener("transitionend", () => toast.remove());
        }, 3500);
    }

    // ─── Helpers ───────────────────────────────────────────

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
});
