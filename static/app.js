// Simply Firewall SPA Client
// No external dependencies (Vanilla JS)

class FirewallClient {
    constructor() {
        this.apiKey = localStorage.getItem('simply_firewall_key') || '';
        this.apiBase = '/api';
        this.state = {
            profile: null,
            ips: [],
            apiKeys: [],
            groups: [],
            webhooks: [],
            auditLogs: [],
            pagination: { limit: 15, offset: 0, hasMore: true },
            auditPagination: { limit: 15, offset: 0, hasMore: true }
        };
        this.init();
    }

    async init() {
        this.bindEvents();
        if (this.apiKey) {
            await this.verifyAuth();
        } else {
            this.showLogin();
        }
    }

    // ───────────────────────────────────────────────────────
    // Fetch Wrapper (Global 401/403 interceptor)
    // ───────────────────────────────────────────────────────
    async apiFetch(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
            ...(options.headers || {})
        };

        try {
            const res = await fetch(`${this.apiBase}${endpoint}`, { ...options, headers });
            
            if (res.status === 401 || res.status === 403) {
                this.handleAuthFailure();
                throw new Error("Authentication failed");
            }

            if (!res.ok) {
                const isJson = res.headers.get('content-type')?.includes('application/json');
                const errData = isJson ? await res.json() : await res.text();
                const errMsg = errData.error || errData || `HTTP ${res.status}`;
                throw new Error(errMsg);
            }

            if (res.status === 204) return null;
            return await res.json();
            
        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }

    // ───────────────────────────────────────────────────────
    // Auth Flow
    // ───────────────────────────────────────────────────────
    handleAuthFailure() {
        this.apiKey = '';
        localStorage.removeItem('simply_firewall_key');
        this.showLogin();
    }

    async verifyAuth() {
        try {
            this.state.profile = await this.apiFetch('/auth/me');
            this.showDashboard();
            this.enforceRBACUI();
            this.loadInitialData();
        } catch (e) {
            // Interceptor handles logout
        }
    }

    async login(key) {
        this.apiKey = key;
        localStorage.setItem('simply_firewall_key', key);
        document.getElementById('login-error').classList.add('hidden');
        await this.verifyAuth();
    }

    logout() {
        this.handleAuthFailure();
        this.showToast("Logged out successfully");
    }

    enforceRBACUI() {
        // Enforce RBAC logic
        const p = this.state.profile;
        const manageIpEl = document.getElementById('manage-ip-section');
        const adminTab = document.querySelector('button[data-tab="admin"]');
        const auditTab = document.getElementById('audit-tab-btn');
        const keysSection = document.getElementById('apikey-section');
        const webhooksSection = document.getElementById('webhooks-section');
        const groupsSection = document.getElementById('groups-section');

        // Manage IPs
        if (!p.is_master && p.group_permissions.length === 0 && !p.can_create_groups) {
            manageIpEl.style.display = 'none';
        } else {
            manageIpEl.style.display = 'block';
        }

        // Admin Tab
        let showAdminInfo = p.is_master || p.can_manage_keys || p.can_manage_webhooks;

        if (showAdminInfo) {
            adminTab.style.display = 'inline-block';
            keysSection.style.display = (p.is_master || p.can_manage_keys) ? 'block' : 'none';
            webhooksSection.style.display = (p.is_master || p.can_manage_webhooks) ? 'block' : 'none';
            groupsSection.style.display = 'block';
        } else {
            adminTab.style.display = 'none';
        }

        // Audit Logs Tab — the backend restricts GET /audit-logs to master keys, so hide the tab
        // entirely rather than show it and let every request 403.
        auditTab.style.display = p.is_master ? 'inline-block' : 'none';
    }

    // ───────────────────────────────────────────────────────
    // Data Loading
    // ───────────────────────────────────────────────────────
    async loadInitialData() {
        this.state.pagination.offset = 0;
        await this.loadIps();
        if (this.state.profile.is_master || this.state.profile.can_manage_keys) {
            await this.loadKeys();
            await this.loadGroups();
        }
        if (this.state.profile.is_master || this.state.profile.can_manage_webhooks) {
            await this.loadWebhooks();
        }
        if (this.state.profile.is_master) {
            this.state.auditPagination.offset = 0;
            await this.loadAuditLogs();
        }
    }

    async loadIps() {
        const { limit, offset } = this.state.pagination;
        const ipQ = document.getElementById('ip-filter').value;
        const groupQ = document.getElementById('group-filter').value;
        const causeQ = document.getElementById('cause-filter').value;
        const statQ = document.getElementById('status-filter').value;

        const params = new URLSearchParams({ limit, offset });
        if (ipQ) params.append('ip', ipQ);
        if (groupQ) params.append('group_name', groupQ);
        if (causeQ) params.append('cause', causeQ);
        if (statQ) params.append('status', statQ);

        try {
            const data = await this.apiFetch(`/ips?${params.toString()}`);
            if (offset === 0) {
                this.state.ips = data;
            } else {
                this.state.ips = [...this.state.ips, ...data];
            }
            this.state.pagination.hasMore = data.length === limit;
            this.renderIpTable();
            this.updatePaginationUI();
        } catch(e) {}
    }

    async loadKeys() {
        try {
            this.state.apiKeys = await this.apiFetch('/keys');
            this.renderKeysTable();
            this.updateRightsSelector();
        } catch(e) {}
    }

    async loadGroups() {
        try {
            this.state.groups = await this.apiFetch('/groups');
            this.renderGroupsTable();
            this.updateGroupSelector();
        } catch(e) {}
    }

    async loadWebhooks() {
        try {
            this.state.webhooks = await this.apiFetch('/webhooks');
            this.renderWebhooksTable();
        } catch(e) {}
    }

    async loadAuditLogs() {
        if (!this.state.profile?.is_master) return;
        const { limit, offset } = this.state.auditPagination;
        const params = new URLSearchParams({ limit, offset });
        try {
            const data = await this.apiFetch(`/audit-logs?${params.toString()}`);
            this.state.auditLogs = data;
            this.state.auditPagination.hasMore = data.length === limit;
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        } catch(e) {}
    }

    // ───────────────────────────────────────────────────────
    // UI Rendering
    // ───────────────────────────────────────────────────────
    showLogin() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('dashboard-container').classList.add('hidden');
    }

    showDashboard() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('dashboard-container').classList.remove('hidden');
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // Addresses present in this loaded data set that belong to both a banlist AND a
    // whitelist group at once — a conflicting/ambiguous firewall state worth flagging.
    findConflictingAddresses() {
        const typesByAddress = new Map();
        for (const ip of this.state.ips) {
            if (!typesByAddress.has(ip.target_address)) {
                typesByAddress.set(ip.target_address, new Set());
            }
            typesByAddress.get(ip.target_address).add(ip.group_type);
        }

        const conflicts = new Set();
        for (const [address, types] of typesByAddress) {
            if (types.has('banlist') && types.has('whitelist')) {
                conflicts.add(address);
            }
        }
        return conflicts;
    }

    renderIpTable() {
        const tbody = document.getElementById('ip-table-body');
        if (this.state.ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No records found.</td></tr>';
            return;
        }

        const conflicts = this.findConflictingAddresses();

        tbody.innerHTML = this.state.ips.map(ip => {
            const isConflicting = conflicts.has(ip.target_address);
            const statusBadge = ip.group_type === 'whitelist'
                ? '<span class="badge badge-white">Whitelisted</span>'
                : '<span class="badge badge-ban">Banned</span>';

            return `
            <tr>
                <td class="font-mono">
                    ${escapeHtml(ip.target_address)}
                    ${ip.is_locked ? '<span title="Locked" class="badge">🔒 Locked</span>' : ''}
                    ${isConflicting ? '<span title="This address is in both a banlist and a whitelist group" class="badge badge-conflict">⚠ Conflict</span>' : ''}
                </td>
                <td>${statusBadge}</td>
                <td>${escapeHtml(ip.cause || '-')}</td>
                <td><span class="badge badge-group">${escapeHtml(ip.group_name || 'Global')}</span></td>
                <td>${new Date(ip.last_seen_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="window.app.deleteIp('${escapeHtml(ip.target_address)}', '${escapeHtml(ip.group_name)}')" ${ip.is_locked ? 'disabled' : ''}>Delete</button>
                </td>
            </tr>
        `;
        }).join('');
    }

    renderKeysTable() {
        const tbody = document.getElementById('apikeys-table-body');
        if (this.state.apiKeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No API keys.</td></tr>';
            return;
        }

        tbody.innerHTML = this.state.apiKeys.map(k => `
            <tr>
                <td><strong>${escapeHtml(k.name)}</strong></td>
                <td class="font-mono">${escapeHtml(k.bound_ips || '-')}</td>
                <td>${this.renderKeyScopes(k)}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-secondary" onclick="window.app.openEditKeyModal('${k.id}')">Edit</button>
                        <button class="btn btn-sm btn-secondary" onclick="window.app.regenerateKeySecret('${k.id}')">Regenerate</button>
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteKey('${k.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    // Renders global scope badges (Master / Manage Keys / Manage Webhooks / Create Groups)
    // plus per-group read/write/delete permission badges for an API key row. Each group badge
    // carries a "×" button to revoke that specific group permission.
    renderKeyScopes(k) {
        const scopes = [];
        if (k.is_master) scopes.push('<span class="badge badge-scope badge-scope-master">Master</span>');
        if (k.can_manage_keys) scopes.push('<span class="badge badge-scope">Manage Keys</span>');
        if (k.can_manage_webhooks) scopes.push('<span class="badge badge-scope">Manage Webhooks</span>');
        if (k.can_create_groups) scopes.push('<span class="badge badge-scope">Create Groups</span>');

        const groupBadges = (k.group_permissions || []).map(p => {
            const rights = [p.can_read ? 'R' : '', p.can_write ? 'W' : '', p.can_delete ? 'D' : '']
                .filter(Boolean).join('') || 'none';
            return `<span class="badge badge-group" title="${escapeHtml(p.group_name)}: ${rights}">${escapeHtml(p.group_name)}: ${rights}
                <button type="button" class="badge-revoke" title="Revoke this group permission" onclick="window.app.revokeGroupPermission('${k.id}', '${p.group_id}')">&times;</button>
            </span>`;
        });

        const badges = [...scopes, ...groupBadges];
        if (badges.length === 0) {
            return '<span class="text-muted text-sm">None</span>';
        }
        return `<div class="scope-badges">${badges.join('')}</div>`;
    }

    updateRightsSelector() {
        const sel = document.getElementById('manage-rights-key');
        if (!sel) return;

        sel.innerHTML = '<option value="">-- Select API Key --</option>' + this.state.apiKeys.map(k => {
            // Master keys do not require scoping
            if (k.is_master) return '';
            return `<option value="${k.id}">${escapeHtml(k.name)}</option>`;
        }).join('');
    }

    // Populates the "Manage Group Rights" group dropdown from currently known groups, replacing
    // the old free-text group name input (which allowed unnoticed typos to silently auto-create a
    // brand-new, wrong group instead of granting rights on the intended one).
    updateGroupSelector() {
        const sel = document.getElementById('manage-rights-group');
        if (!sel) return;

        const previousValue = sel.value;
        sel.innerHTML = '<option value="">-- Select Group --</option>' + this.state.groups.map(g =>
            `<option value="${escapeHtml(g.name)}">${escapeHtml(g.name)}</option>`
        ).join('');
        if (previousValue) sel.value = previousValue;
    }

    renderGroupsTable() {
        const tbody = document.getElementById('groups-table-body');
        if (this.state.groups.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No groups.</td></tr>';
            return;
        }

        tbody.innerHTML = this.state.groups.map(g => `
            <tr>
                <td class="font-mono text-sm">${g.id.substring(0, 8)}...</td>
                <td><strong>${escapeHtml(g.name)}</strong></td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="window.app.deleteGroup('${g.id}')">Delete</button>
                </td>
            </tr>
        `).join('');
    }

    renderWebhooksTable() {
        const tbody = document.getElementById('webhooks-table-body');
        if (this.state.webhooks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No webhooks.</td></tr>';
            return;
        }

        tbody.innerHTML = this.state.webhooks.map(w => `
            <tr>
                <td class="font-mono text-sm">${w.id.split('-')[0]}...</td>
                <td><strong>${escapeHtml(w.name)}</strong></td>
                <td class="font-mono text-sm">${escapeHtml(w.target_url)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="window.app.deleteWebhook('${w.id}')">Delete</button>
                </td>
            </tr>
        `).join('');
    }

    updatePaginationUI() {
        const pr = document.getElementById('btn-prev');
        const nt = document.getElementById('btn-next');
        const ind = document.getElementById('page-indicator');

        pr.disabled = this.state.pagination.offset === 0;
        nt.disabled = !this.state.pagination.hasMore;
        ind.textContent = `Page ${Math.floor(this.state.pagination.offset / this.state.pagination.limit) + 1}`;
    }

    renderAuditLogsTable() {
        const tbody = document.getElementById('audit-logs-table-body');
        if (this.state.auditLogs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No audit log entries.</td></tr>';
            return;
        }

        tbody.innerHTML = this.state.auditLogs.map(log => `
            <tr>
                <td class="text-sm">${new Date(log.timestamp).toLocaleString()}</td>
                <td><span class="badge badge-scope">${escapeHtml(log.action)}</span></td>
                <td class="font-mono text-sm">${escapeHtml(log.target_address || '-')}</td>
                <td class="text-sm">${escapeHtml(log.group_names || '-')}</td>
                <td class="text-sm">${escapeHtml(log.details || '-')}</td>
            </tr>
        `).join('');
    }

    updateAuditPaginationUI() {
        const pr = document.getElementById('audit-btn-prev');
        const nt = document.getElementById('audit-btn-next');
        const ind = document.getElementById('audit-page-indicator');

        pr.disabled = this.state.auditPagination.offset === 0;
        nt.disabled = !this.state.auditPagination.hasMore;
        ind.textContent = `Page ${Math.floor(this.state.auditPagination.offset / this.state.auditPagination.limit) + 1}`;
    }

    // ───────────────────────────────────────────────────────
    // Actions
    // ───────────────────────────────────────────────────────
    async upsertIp(isWhite) {
        const address = document.getElementById('ip-address').value;
        const group_name = document.getElementById('group-name').value;
        const cause = document.getElementById('cause').value;
        
        if (!address || !group_name) return;

        try {
            await this.apiFetch(`/${isWhite ? 'white' : 'ban'}`, {
                method: 'POST',
                body: JSON.stringify({ target_address: address, group_name, cause: cause || null })
            });
            this.showToast(`IP successfully ${isWhite ? 'whitelisted' : 'banned'}`, 'success');
            document.getElementById('manage-form').reset();
            this.loadInitialData();
        } catch(e) {}
    }

    async deleteIp(targetAddress, groupName) {
        if (!confirm("Are you sure you want to delete this rule?")) return;
        try {
            const params = new URLSearchParams({ target_address: targetAddress, group_name: groupName });
            await this.apiFetch(`/ips?${params.toString()}`, { method: 'DELETE' });
            this.showToast("Record deleted", 'success');
            this.loadInitialData();
        } catch(e) {}
    }

    async createApiKey(e) {
        e.preventDefault();
        const payload = {
            name: document.getElementById('apikey-name').value,
            bound_ips: document.getElementById('apikey-bound-ips').value,
            is_master: document.getElementById('apikey-is-master').checked,
            can_manage_keys: document.getElementById('apikey-can-manage-keys').checked,
            can_manage_webhooks: document.getElementById('apikey-can-manage-webhooks').checked,
            can_create_groups: document.getElementById('apikey-can-create-groups').checked
        };

        try {
            const res = await this.apiFetch('/keys', { method: 'POST', body: JSON.stringify(payload) });
            const reveal = document.getElementById('apikey-created');
            const pt = document.getElementById('apikey-plaintext');
            pt.textContent = res.plaintext_key;
            reveal.classList.remove('hidden');
            
            document.getElementById('form-create-apikey').reset();
            this.loadKeys();
        } catch(e) {}
    }

    async manageKeyRights(e) {
        e.preventDefault();
        const keyId = document.getElementById('manage-rights-key').value;
        const groupName = document.getElementById('manage-rights-group').value;

        if (!keyId || !groupName) return;

        const payload = {
            group_name: groupName,
            can_read: document.getElementById('manage-rights-read').checked,
            can_write: document.getElementById('manage-rights-write').checked,
            can_delete: document.getElementById('manage-rights-delete').checked
        };

        try {
            await this.apiFetch(`/keys/${keyId}/groups`, { method: 'POST', body: JSON.stringify(payload) });
            this.showToast("Group Rights Assigned Effectively", 'success');
            document.getElementById('form-manage-rights').reset();
            this.loadGroups();
        } catch(e) {}
    }

    async deleteKey(id) {
        if (!confirm("Confirm deleting API Key?")) return;
        try {
            await this.apiFetch(`/keys/${id}`, { method: 'DELETE' });
            this.showToast("Key deleted");
            this.loadKeys();
        } catch(e) {}
    }

    openEditKeyModal(id) {
        const k = this.state.apiKeys.find(k => k.id === id);
        if (!k) return;
        document.getElementById('edit-key-id').value = k.id;
        document.getElementById('edit-key-name').value = k.name;
        document.getElementById('edit-key-bound-ips').value = k.bound_ips || '';
        document.getElementById('edit-key-can-manage-keys').checked = k.can_manage_keys;
        document.getElementById('edit-key-can-manage-webhooks').checked = k.can_manage_webhooks;
        document.getElementById('edit-key-can-create-groups').checked = k.can_create_groups;
        document.getElementById('edit-key-modal').classList.remove('hidden');
    }

    closeEditKeyModal() {
        document.getElementById('edit-key-modal').classList.add('hidden');
    }

    async submitEditKey(e) {
        e.preventDefault();
        const id = document.getElementById('edit-key-id').value;
        const payload = {
            name: document.getElementById('edit-key-name').value,
            bound_ips: document.getElementById('edit-key-bound-ips').value,
            can_manage_keys: document.getElementById('edit-key-can-manage-keys').checked,
            can_manage_webhooks: document.getElementById('edit-key-can-manage-webhooks').checked,
            can_create_groups: document.getElementById('edit-key-can-create-groups').checked
        };

        try {
            await this.apiFetch(`/keys/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
            this.showToast("Key updated", 'success');
            this.closeEditKeyModal();
            this.loadKeys();
        } catch(e) {}
    }

    async regenerateKeySecret(id) {
        if (!confirm("Regenerate this key's secret? The old secret will stop working immediately.")) return;
        try {
            const res = await this.apiFetch(`/keys/${id}/rotate`, { method: 'POST' });
            document.getElementById('secret-reveal-value').textContent = res.plaintext_key;
            document.getElementById('secret-reveal-modal').classList.remove('hidden');
            this.showToast("Secret rotated", 'success');
        } catch(e) {}
    }

    async revokeGroupPermission(keyId, groupIdentifier) {
        if (!confirm("Revoke this key's permission on this group?")) return;
        try {
            await this.apiFetch(`/keys/${keyId}/permissions/${groupIdentifier}`, { method: 'DELETE' });
            this.showToast("Permission revoked", 'success');
            this.loadKeys();
        } catch(e) {}
    }

    async createGroup(e) {
        e.preventDefault();
        const name = document.getElementById('create-group-name').value;
        try {
            await this.apiFetch('/groups', { method: 'POST', body: JSON.stringify({ name }) });
            document.getElementById('form-create-group').reset();
            this.loadGroups();
            this.showToast("Group created");
        } catch(e) {}
    }

    async deleteGroup(id) {
        if (!confirm("Delete entire group? This operation cascade wipes resources.")) return;
        try {
            await this.apiFetch(`/groups/${id}`, { method: 'DELETE' });
            this.loadGroups();
            this.loadIps();
        } catch(e) {}
    }

    async createWebhook(e) {
        e.preventDefault();

        const payload = {
            name: document.getElementById('webhook-name').value,
            target_url: document.getElementById('webhook-url').value,
            secret_token: document.getElementById('webhook-secret').value,
            group_id: document.getElementById('webhook-group-id').value,
            headers_json: document.getElementById('webhook-headers').value || null,
            payload_template: document.getElementById('webhook-template').value
        };

        try {
            await this.apiFetch('/webhooks', { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('form-create-webhook').reset();
            this.loadWebhooks();
            this.showToast("Webhook configured");
        } catch(e) {}
    }

    async deleteWebhook(id) {
        if (!confirm("Delete this webhook?")) return;
        try {
            await this.apiFetch(`/webhooks/${id}`, { method: 'DELETE' });
            this.loadWebhooks();
            this.showToast("Webhook configuration deleted");
        } catch(e) {}
    }

    // ───────────────────────────────────────────────────────
    // Event Binding
    // ───────────────────────────────────────────────────────
    bindEvents() {
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login(document.getElementById('login-key').value);
        });

        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('refresh-btn').addEventListener('click', () => this.loadInitialData());

        // Tabs
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active', 'aria-selected'));
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
                
                const trg = e.target;
                trg.classList.add('active', 'aria-selected');
                document.getElementById(`tab-${trg.dataset.tab}`).classList.add('active');
            });
        });

        // IP Form
        document.getElementById('manage-form').addEventListener('submit', (e) => e.preventDefault());
        document.getElementById('btn-ban').addEventListener('click', () => this.upsertIp(false));
        document.getElementById('btn-white').addEventListener('click', () => this.upsertIp(true));

        // Filters
        const loadDebounced = debounce(() => {
            this.state.pagination.offset = 0;
            this.loadIps();
        }, 500);
        
        document.getElementById('ip-filter').addEventListener('input', loadDebounced);
        document.getElementById('group-filter').addEventListener('input', loadDebounced);
        document.getElementById('cause-filter').addEventListener('input', loadDebounced);
        document.getElementById('status-filter').addEventListener('change', () => {
            this.state.pagination.offset = 0;
            this.loadIps();
        });

        // Pagination
        document.getElementById('btn-prev').addEventListener('click', () => {
            if (this.state.pagination.offset > 0) {
                this.state.pagination.offset -= this.state.pagination.limit;
                this.loadIps();
            }
        });
        document.getElementById('btn-next').addEventListener('click', () => {
            if (this.state.pagination.hasMore) {
                this.state.pagination.offset += this.state.pagination.limit;
                this.loadIps();
            }
        });

        // Admin Forms
        document.getElementById('form-create-apikey').addEventListener('submit', (e) => this.createApiKey(e));
        document.getElementById('form-manage-rights').addEventListener('submit', (e) => this.manageKeyRights(e));
        document.getElementById('form-create-group').addEventListener('submit', (e) => this.createGroup(e));
        document.getElementById('form-create-webhook').addEventListener('submit', (e) => this.createWebhook(e));

        // Edit Key modal
        document.getElementById('form-edit-key').addEventListener('submit', (e) => this.submitEditKey(e));
        document.getElementById('edit-key-cancel').addEventListener('click', () => this.closeEditKeyModal());

        // Secret reveal modal (used after key rotation)
        document.getElementById('secret-reveal-close').addEventListener('click', () => {
            document.getElementById('secret-reveal-modal').classList.add('hidden');
        });

        // Audit log pagination
        document.getElementById('audit-btn-prev').addEventListener('click', () => {
            if (this.state.auditPagination.offset > 0) {
                this.state.auditPagination.offset -= this.state.auditPagination.limit;
                this.loadAuditLogs();
            }
        });
        document.getElementById('audit-btn-next').addEventListener('click', () => {
            if (this.state.auditPagination.hasMore) {
                this.state.auditPagination.offset += this.state.auditPagination.limit;
                this.loadAuditLogs();
            }
        });
    }
}

// Utils
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function debounce(func, timeout = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => { func.apply(this, args); }, timeout);
    };
}

// Bootstrap
window.addEventListener('DOMContentLoaded', () => {
    window.app = new FirewallClient();
});
