document.addEventListener("DOMContentLoaded", () => {
    const apiKeyInput = document.getElementById("api-key-input");
    const ipTableBody = document.getElementById("ip-table-body");
    const statusFilter = document.getElementById("status-filter");
    const refreshBtn = document.getElementById("refresh-btn");
    
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
    
    async function loadData() {
        const key = apiKeyInput.value.trim();
        if (!key) return; // Silent return if no key
        
        const params = new URLSearchParams({
            limit: limit,
            page: currentPage
        });
        
        if (statusFilter.value) {
            params.append("status", statusFilter.value);
        }
        
        try {
            const res = await fetch(`/api/ips?${params.toString()}`, {
                headers: { "x-api-key": key }
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
            // Best guess for next button (if data len < limit, disable next)
            document.getElementById("btn-next").disabled = data.length < limit;
            
        } catch (err) {
            showTableError("Network Error or Server Unreachable.");
        }
    }
    
    function renderTable(data) {
        if (!data || data.length === 0) {
            ipTableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No records found.</td></tr>`;
            return;
        }
        
        ipTableBody.innerHTML = data.map(record => {
            const statusClass = record.is_whitelist ? "badge-white" : "badge-ban";
            const statusText = record.is_whitelist ? "Whitelist" : "Banned";
            const date = new Date(record.updated_at).toLocaleString();
            
            return `
                <tr>
                    <td style="font-family: monospace;">${record.address}</td>
                    <td><span class="badge ${statusClass}">${statusText}</span></td>
                    <td class="text-muted" style="font-size: 0.8rem;">${record.group_id || '-'}</td>
                    <td>${date}</td>
                </tr>
            `;
        }).join("");
    }
    
    function showTableError(msg) {
        ipTableBody.innerHTML = `<tr><td colspan="4" class="text-center" style="color: var(--danger);">${msg}</td></tr>`;
    }
    
    // Form Submissions
    document.getElementById("manage-form").addEventListener("submit", (e) => {
        e.preventDefault();
        // Since Ban IP is the submit button, this catches Enter key or explicit ban
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
                    "x-api-key": key
                },
                body: JSON.stringify({
                    address,
                    group_id: groupId,
                    cause
                })
            });
            
            if (res.ok) {
                showMessage(`Successfully ${isWhitelist ? 'whitelisted' : 'banned'} ${address}`, "success");
                document.getElementById("ip-address").value = "";
                document.getElementById("cause").value = "";
                // Leave group ID for subsequent adds
                currentPage = 0;
                loadData();
            } else {
                const text = await res.text().catch(()=>"");
                showMessage(`Failed: Server returned ${res.status}. ${text}`, "error");
            }
        } catch (err) {
            showMessage("Network Error.", "error");
        }
    }
    
    function showMessage(msg, type) {
        const msgDiv = document.getElementById("form-message");
        msgDiv.textContent = msg;
        msgDiv.className = `message ${type}`;
        msgDiv.classList.remove("hidden");
        
        setTimeout(() => {
            msgDiv.classList.add("hidden");
        }, 5000);
    }
});
