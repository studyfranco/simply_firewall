// Simply IP Vault SPA Client
// No external dependencies (Vanilla JS)

// ═══════════════════════════════════════════════════════════════════════════
// Pure-JS HMAC-SHA256 fallback
//
// Every API request must be signed (see FirewallClient.signRequest). The Web Crypto API is the
// preferred implementation, but `crypto.subtle` exists ONLY in a secure context — HTTPS, or
// http://localhost. A homelab deployment reached over plain HTTP at a LAN address (which is the
// normal way this tool gets used) therefore has no `crypto.subtle` at all, and without a fallback
// the dashboard simply cannot authenticate there.
//
// So: a self-contained SHA-256 + HMAC implementation, no dependencies, per the project's strict
// vanilla-JS rule. It is used ONLY when `crypto.subtle` is unavailable — where Web Crypto exists it
// wins, being both constant-time and far faster.
//
// Security note: this fallback is not constant-time and the derived signature is computed in
// interpreted JS. That is an accepted, explicit trade-off — on a plain-HTTP LAN connection the
// request and its headers are already fully visible to anyone on the path, so timing side-channels
// in the browser are not the weak link. HTTPS remains the recommended deployment.
// ═══════════════════════════════════════════════════════════════════════════

/** SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes). */
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

/** SHA-256 block size in bytes — also the HMAC key-padding width. */
const SHA256_BLOCK_BYTES = 64;

/** Rotate a 32-bit word right by n bits (1..31). */
function rotr32(x, n) {
    return (x >>> n) | (x << (32 - n));
}

/**
 * SHA-256 of a Uint8Array, returning a 32-byte Uint8Array.
 *
 * Intermediate sums are reduced with `>>> 0` (ToUint32), which is correct even when an operand is a
 * negative int32 — JS bitwise operators yield signed 32-bit values, but ToUint32 adds 2^32, leaving
 * every result congruent mod 2^32 as the spec requires.
 */
function sha256Bytes(bytes) {
    const h = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);

    // Pad to a multiple of 64: the 0x80 marker, then zeros, then a 64-bit big-endian bit length.
    const bitLen = bytes.length * 8;
    const totalLen = ((bytes.length + 9 + 63) >> 6) << 6;
    const msg = new Uint8Array(totalLen);
    msg.set(bytes);
    msg[bytes.length] = 0x80;

    const view = new DataView(msg.buffer);
    // The high word is derived by division, not by shifting: JS bitwise ops truncate to 32 bits, so
    // `bitLen >>> 32` would be wrong for inputs above 512 MiB.
    view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(totalLen - 4, bitLen >>> 0, false);

    const w = new Uint32Array(64);
    for (let off = 0; off < totalLen; off += SHA256_BLOCK_BYTES) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(off + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }

        let [a, b, c, d, e, f, g, hh] = h;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;
            hh = g; g = f; f = e;
            e = (d + t1) >>> 0;
            d = c; c = b; b = a;
            a = (t1 + t2) >>> 0;
        }

        h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
        h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
        h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
        h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) {
        outView.setUint32(i * 4, h[i], false);
    }
    return out;
}

/** HMAC-SHA256 (RFC 2104) of `msgBytes` under `keyBytes`, returning a 32-byte Uint8Array. */
function hmacSha256Bytes(keyBytes, msgBytes) {
    // Keys longer than one block are hashed down first; shorter keys are zero-padded up.
    const key = keyBytes.length > SHA256_BLOCK_BYTES ? sha256Bytes(keyBytes) : keyBytes;
    const padded = new Uint8Array(SHA256_BLOCK_BYTES);
    padded.set(key);

    const inner = new Uint8Array(SHA256_BLOCK_BYTES + msgBytes.length);
    const outer = new Uint8Array(SHA256_BLOCK_BYTES + 32);
    for (let i = 0; i < SHA256_BLOCK_BYTES; i++) {
        inner[i] = padded[i] ^ 0x36;
        outer[i] = padded[i] ^ 0x5c;
    }
    inner.set(msgBytes, SHA256_BLOCK_BYTES);
    outer.set(sha256Bytes(inner), SHA256_BLOCK_BYTES);
    return sha256Bytes(outer);
}

/** Lowercase hex encoding of a Uint8Array, matching Rust's `hex::encode`. */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Reusable searchable dropdown ("combobox"): a text input plus a live-filtered option list.
// Two modes, chosen by whether searchId and valueId are the same element:
//   - allowFreeText: true  — searchId === valueId; the input's own text IS the value (used by
//     the IP Group filter, which already does substring matching server-side). The dropdown is
//     purely a convenience of known-group suggestions; typing anything not in the list still
//     works exactly as the old plain <input> did.
//   - allowFreeText: false — searchId !== valueId; the search input only displays a label, and
//     valueId (a hidden input) only changes when the user actually picks a listed option. Typing
//     without picking a fresh option clears the hidden value, so a stale prior selection can
//     never be silently resubmitted alongside now-mismatched displayed text.
class SearchableSelect {
    constructor({ rootId, searchId, valueId, allowFreeText = false, onSelect }) {
        this.root = document.getElementById(rootId);
        this.search = document.getElementById(searchId);
        this.valueInput = document.getElementById(valueId);
        this.menu = this.root.querySelector('.combobox-menu');
        this.allowFreeText = allowFreeText;
        this.onSelect = onSelect || (() => {});
        this.options = [];

        this.search.addEventListener('input', () => {
            if (!this.allowFreeText) {
                this.valueInput.value = '';
            }
            this.renderMenu(this.search.value);
            this.openMenu();
        });
        this.search.addEventListener('focus', () => {
            this.renderMenu(this.search.value);
            this.openMenu();
        });
        this.search.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeMenu();
            } else if (e.key === 'Enter') {
                const first = this.menu.querySelector('.combobox-option');
                if (first) {
                    e.preventDefault();
                    first.dispatchEvent(new MouseEvent('mousedown'));
                }
            }
        });
        document.addEventListener('click', (e) => {
            if (!this.root.contains(e.target)) this.closeMenu();
        });
    }

    // options: [{ value, label }]
    setOptions(options) {
        this.options = options;
        // Keep an already-selected strict value's displayed label in sync if the underlying
        // group list changed (e.g. renamed) while this control wasn't being actively edited.
        if (!this.allowFreeText && this.valueInput.value) {
            const current = this.options.find(o => String(o.value) === this.valueInput.value);
            if (current) this.search.value = current.label;
        }
    }

    renderMenu(filterText) {
        const q = (filterText || '').trim().toLowerCase();
        const filtered = this.options.filter(o => o.label.toLowerCase().includes(q));
        if (filtered.length === 0) {
            this.menu.innerHTML = '<div class="combobox-empty">No matching groups</div>';
            return;
        }
        this.menu.innerHTML = filtered.map((o, i) =>
            `<div class="combobox-option" data-index="${i}">${escapeHtml(o.label)}</div>`
        ).join('');
        this.menu.querySelectorAll('.combobox-option').forEach((el, i) => {
            // mousedown (not click) with preventDefault: fires before — and suppresses — the
            // search input's own blur, so the selection always registers on the first press
            // instead of the menu disappearing out from under the click.
            el.addEventListener('mousedown', (e) => {
                e.preventDefault();
                this.select(filtered[i]);
            });
        });
    }

    select(opt) {
        this.search.value = opt.label;
        if (this.valueInput !== this.search) {
            this.valueInput.value = opt.value;
        }
        // onSelect is the single mechanism external code reacts to a selection through, in both
        // modes — e.g. the IP Group filter's combobox wires this straight to an explicit search.
        this.onSelect(opt.value);
        this.closeMenu();
    }

    openMenu() {
        this.menu.classList.remove('hidden');
    }

    closeMenu() {
        this.menu.classList.add('hidden');
    }
}

// Client-side cache for a paginated list endpoint: fetches large chunks from the server
// (chunkSize, e.g. 100 items) but paginates locally in small pages (pageSize, e.g. 15) — most
// "Next"/"Prev" clicks are then a pure client-side slice with no network round-trip at all.
// Background-prefetches the next server chunk as soon as the user reaches the second-to-last
// local page of whatever's currently cached, so by the time they'd actually need it, it's
// typically already there.
class PagedCache {
    constructor({ chunkSize = 100, pageSize = 15, fetchChunk }) {
        this.chunkSize = chunkSize;
        this.pageSize = pageSize;
        this.fetchChunk = fetchChunk; // async (serverOffset, chunkSize) => Array<item>
        this.reset();
    }

    reset() {
        this.items = [];
        this.serverOffset = 0;
        this.hasMoreOnServer = true;
        this.localPage = 0;
        this.prefetching = null; // in-flight prefetch promise, if any
    }

    get totalLocalPages() {
        return Math.max(1, Math.ceil(this.items.length / this.pageSize));
    }

    get currentPageItems() {
        const start = this.localPage * this.pageSize;
        return this.items.slice(start, start + this.pageSize);
    }

    get hasNextPage() {
        const nextPageStart = (this.localPage + 1) * this.pageSize;
        return nextPageStart < this.items.length || this.hasMoreOnServer;
    }

    get hasPrevPage() {
        return this.localPage > 0;
    }

    // Discards everything cached and fetches a fresh first chunk — used on initial load and
    // whenever the active filters/search change (a different query is a different dataset, not
    // more pages of the old one).
    async loadFirstChunk() {
        this.reset();
        const chunk = await this.fetchChunk(0, this.chunkSize);
        this.items = chunk;
        this.serverOffset = chunk.length;
        this.hasMoreOnServer = chunk.length === this.chunkSize;
        this._maybePrefetch();
    }

    async fetchNextChunk() {
        if (!this.hasMoreOnServer) return;
        if (this.prefetching) return this.prefetching;
        this.prefetching = (async () => {
            const chunk = await this.fetchChunk(this.serverOffset, this.chunkSize);
            this.items = [...this.items, ...chunk];
            this.serverOffset += chunk.length;
            this.hasMoreOnServer = chunk.length === this.chunkSize;
            this.prefetching = null;
        })();
        return this.prefetching;
    }

    // Advances one local page. If the next page isn't cached yet but the server might still have
    // more, fetches synchronously first (the one case where "Next" still has to wait on the
    // network — normally avoided by the background prefetch below already having run ahead).
    async nextPage() {
        const nextPageStart = (this.localPage + 1) * this.pageSize;
        if (nextPageStart >= this.items.length && this.hasMoreOnServer) {
            await this.fetchNextChunk();
        }
        if (nextPageStart < this.items.length) {
            this.localPage++;
        }
        this._maybePrefetch();
    }

    prevPage() {
        if (this.localPage > 0) this.localPage--;
    }

    // Fires a background fetch the moment the user lands on the second-to-last page of the
    // currently cached chunk — re-evaluated dynamically off the live item count, so it correctly
    // fires again after each new chunk arrives, not just once.
    _maybePrefetch() {
        if (!this.hasMoreOnServer || this.prefetching) return;
        if (this.localPage === this.totalLocalPages - 2) {
            this.fetchNextChunk();
        }
    }
}

class FirewallClient {
    constructor() {
        this.apiKey = localStorage.getItem('simply_ip_vault_key') || '';
        this.signingSecret = localStorage.getItem('simply_ip_vault_signing_secret') || '';
        this.apiBase = '/api';
        // Cached CryptoKey for HMAC signing, so the secret is imported once per session rather than
        // on every request. Invalidated (alongside the cached secret it was derived from) whenever
        // the credentials change — see setCredentials().
        this.hmacKey = null;
        this.hmacKeySource = '';
        this.state = {
            profile: null,
            apiKeys: [],
            groups: [],
            webhooks: [],
            showConflictsOnly: false,
            // Row-selection state for the batch-delete checkboxes, keyed by each row's own
            // stable id (IpRecordResponse.id, group.id, key.id) — never a synthesized composite
            // key, since e.g. IPv6 addresses can themselves contain "::" and would corrupt any
            // delimiter-based encoding of (address, group) pairs.
            selectedIpIds: new Set(),
            selectedGroupIds: new Set(),
            selectedKeyIds: new Set()
        };

        // IP records and audit logs are both large, append-only lists — fetched from the server
        // 100 at a time and paginated locally 15 at a time via PagedCache, instead of one small
        // network round-trip per page.
        this.ipCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchIpsChunk(offset, limit) });
        this.auditCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchAuditLogsChunk(offset, limit) });

        // Searchable group comboboxes — populated from this.state.groups by loadGroups() via
        // setOptions() on each. The IP-group filter is free-text (its value IS the substring
        // filter sent to the API); the other two require picking an actual existing group.
        // Explicitly selecting a suggestion is a deliberate action (not a keystroke), so it's
        // exempt from the "search fires on Enter/button only" rule and searches immediately.
        this.groupFilterCombobox = new SearchableSelect({
            rootId: 'group-filter-combobox',
            searchId: 'group-filter',
            valueId: 'group-filter',
            allowFreeText: true,
            onSelect: () => this.triggerIpSearch()
        });
        this.rightsGroupCombobox = new SearchableSelect({
            rootId: 'manage-rights-group-combobox',
            searchId: 'manage-rights-group-search',
            valueId: 'manage-rights-group'
        });
        this.webhookGroupCombobox = new SearchableSelect({
            rootId: 'webhook-group-combobox',
            searchId: 'webhook-group-search',
            valueId: 'webhook-group-id'
        });

        this.init();
    }

    async init() {
        this.bindEvents();
        // Both halves of the credential are required: the key alone can no longer authenticate.
        if (this.apiKey && this.signingSecret) {
            await this.verifyAuth();
        } else {
            this.showLogin();
        }
    }

    // ───────────────────────────────────────────────────────
    // Request Signing (HMAC-SHA256 via Web Crypto)
    // ───────────────────────────────────────────────────────

    /**
     * Imports this.signingSecret as an HMAC-SHA256 CryptoKey, memoized for the session.
     *
     * The secret is imported as its raw UTF-8 bytes — NOT hex-decoded — because the server keys its
     * HMAC with `secret.as_bytes()`, i.e. the ASCII bytes of the hex string. Decoding to 32 bytes
     * here would produce a different key and fail every signature check.
     */
    async getHmacKey() {
        if (this.hmacKey && this.hmacKeySource === this.signingSecret) {
            return this.hmacKey;
        }
        this.hmacKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(this.signingSecret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        this.hmacKeySource = this.signingSecret;
        return this.hmacKey;
    }

    /**
     * True when the Web Crypto API is usable. `crypto.subtle` is exposed only in a secure context
     * (HTTPS, or http://localhost), so a homelab instance reached over plain HTTP at a LAN address
     * lands on the pure-JS fallback instead.
     */
    static hasWebCrypto() {
        return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
    }

    /**
     * Computes the hex X-Signature-256 over the CANONICAL_V1 string
     * `METHOD\nPATH\nTIMESTAMP\nRAW_BODY`.
     *
     * `path` must exclude the query string, matching the server's `crypto::verify_signature`.
     *
     * Prefers Web Crypto and falls back to the pure-JS HMAC above when `crypto.subtle` is absent.
     * Both paths produce byte-identical output: the secret is used as its raw UTF-8 bytes (NOT
     * hex-decoded), because the server keys its HMAC with `secret.as_bytes()`.
     */
    async signRequest(method, path, timestamp, body) {
        const encoder = new TextEncoder();
        const message = encoder.encode(`${method}\n${path}\n${timestamp}\n${body}`);

        if (!FirewallClient.hasWebCrypto()) {
            return bytesToHex(hmacSha256Bytes(encoder.encode(this.signingSecret), message));
        }

        const key = await this.getHmacKey();
        const digest = await crypto.subtle.sign('HMAC', key, message);
        return bytesToHex(new Uint8Array(digest));
    }

    // ───────────────────────────────────────────────────────
    // Fetch Wrapper (Global 401/403 interceptor)
    // ───────────────────────────────────────────────────────
    async apiFetch(endpoint, options = {}) {
        // The signature covers the path only, so strip any query string before signing while still
        // requesting the full URL. Mutating fields all travel in the (signed) body.
        const [pathOnly] = endpoint.split('?');
        const method = (options.method || 'GET').toUpperCase();
        const rawBody = options.body ?? '';
        const timestamp = Math.floor(Date.now() / 1000).toString();

        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };

        try {
            if (this.apiKey && this.signingSecret) {
                headers['X-API-Key'] = this.apiKey;
                headers['X-Timestamp'] = timestamp;
                headers['X-Signature-256'] = await this.signRequest(
                    method,
                    `${this.apiBase}${pathOnly}`,
                    timestamp,
                    rawBody
                );
            }

            const res = await fetch(`${this.apiBase}${endpoint}`, { ...options, headers });

            // 401 means the key itself is invalid/missing — the session is unrecoverable, so log
            // out. 403 means the key IS valid but lacks permission for this one action; it must
            // NOT log the user out or swallow the server's specific "Permission denied: ..."
            // message behind a generic one — that message is exactly what the user needs to see,
            // and falls through to the generic error handling below like any other 4xx.
            if (res.status === 401) {
                this.handleAuthFailure();
                throw new Error("Session expired or invalid API key — please log in again.");
            }

            // Read the body as text first and only attempt to parse it when there's actually
            // something to parse. Several endpoints (e.g. POST /api/keys/:id/groups) return a
            // bare 200 with no body at all — exactly as "empty" as a real 204 as far as parsing
            // is concerned — and `res.json()` throws "Unexpected end of JSON input" on either.
            // A parse failure on a genuinely non-empty body (e.g. an upstream proxy's HTML error
            // page, not actually JSON) falls back to the raw text rather than crashing.
            const text = await res.text();
            let data = {};
            if (text && text.trim().length > 0) {
                try {
                    data = JSON.parse(text);
                } catch {
                    data = text;
                }
            }

            if (!res.ok) {
                const errMsg = (data && typeof data === 'object' ? data.error : null) || (typeof data === 'string' ? data : null) || `HTTP ${res.status}`;
                throw new Error(errMsg);
            }

            return data;

        } catch (error) {
            this.showToast(error.message, 'error');
            throw error;
        }
    }

    // ───────────────────────────────────────────────────────
    // Auth Flow
    // ───────────────────────────────────────────────────────
    /**
     * Sets (or clears, when called with empty strings) both halves of the credential at once, in
     * localStorage and in memory. Centralized so the key and its signing secret can never drift out
     * of sync — a stale secret paired with a fresh key would fail every request with a 401.
     */
    setCredentials(key, signingSecret) {
        this.apiKey = key;
        this.signingSecret = signingSecret;
        this.hmacKey = null;
        this.hmacKeySource = '';

        if (key && signingSecret) {
            localStorage.setItem('simply_ip_vault_key', key);
            localStorage.setItem('simply_ip_vault_signing_secret', signingSecret);
        } else {
            localStorage.removeItem('simply_ip_vault_key');
            localStorage.removeItem('simply_ip_vault_signing_secret');
        }
    }

    handleAuthFailure() {
        this.setCredentials('', '');
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

    async login(key, signingSecret) {
        this.setCredentials(key, signingSecret);
        document.getElementById('login-error').classList.add('hidden');
        await this.verifyAuth();
    }

    logout() {
        this.handleAuthFailure();
        this.showToast("Logged out successfully", 'success');
    }

    enforceRBACUI() {
        // Enforce RBAC logic
        const p = this.state.profile;
        const manageIpEl = document.getElementById('manage-ip-section');
        const groupsTab = document.getElementById('groups-tab-btn');
        const keysTab = document.getElementById('keys-tab-btn');
        const webhooksTab = document.getElementById('webhooks-tab-btn');
        const auditTab = document.getElementById('audit-tab-btn');

        // Manage IPs
        if (!p.is_master && p.group_permissions.length === 0 && !p.can_create_groups) {
            manageIpEl.style.display = 'none';
        } else {
            manageIpEl.style.display = 'block';
        }

        // IP Groups tab — kept visible under the same condition that used to gate the whole
        // shared "Administration" tab, since either scope previously implied seeing it.
        const showAdminInfo = p.is_master || p.can_manage_keys || p.can_manage_webhooks;
        groupsTab.style.display = showAdminInfo ? 'inline-block' : 'none';

        // API Keys & Permissions tab
        keysTab.style.display = (p.is_master || p.can_manage_keys) ? 'inline-block' : 'none';

        // Webhooks tab
        webhooksTab.style.display = (p.is_master || p.can_manage_webhooks) ? 'inline-block' : 'none';

        // Audit Logs Tab — the backend restricts GET /audit-logs to master keys, so hide the tab
        // entirely rather than show it and let every request 403.
        auditTab.style.display = p.is_master ? 'inline-block' : 'none';
    }

    // ───────────────────────────────────────────────────────
    // Data Loading
    // ───────────────────────────────────────────────────────
    async loadInitialData() {
        await this.loadIps();
        if (this.state.profile.is_master || this.state.profile.can_manage_keys) {
            await this.loadKeys();
        }
        // Unconditional (not scope-gated): GET /api/groups is safe for any authenticated key —
        // the backend already narrows results to what that key can read — and the result feeds
        // the IP Group filter's suggestion combobox for every user, not just the admin-only
        // "Manage Group Rights" and "Target Group" selectors on the Keys/Webhooks tabs.
        await this.loadGroups();
        if (this.state.profile.is_master || this.state.profile.can_manage_webhooks) {
            await this.loadWebhooks();
        }
        if (this.state.profile.is_master) {
            await this.loadAuditLogs();
        }
    }

    // Fetches one chunk (up to 100 records) from the server for the current filter values —
    // called by PagedCache, both for the initial page and for background prefetches. Filter
    // values are read fresh on every call (not captured once) so a prefetch mid-typing session
    // still reflects whatever was actually searched, not stale values from page load.
    async fetchIpsChunk(offset, limit) {
        const ipQ = document.getElementById('ip-filter').value;
        const groupQ = document.getElementById('group-filter').value;
        const causeQ = document.getElementById('cause-filter').value;
        const statQ = document.getElementById('status-filter').value;

        const params = new URLSearchParams({ limit, offset });
        if (ipQ) params.append('ip', ipQ);
        if (groupQ) params.append('group_name', groupQ);
        if (causeQ) params.append('cause', causeQ);
        if (statQ) params.append('status', statQ);

        return await this.apiFetch(`/ips?${params.toString()}`);
    }

    async loadIps() {
        try {
            this.state.selectedIpIds.clear();
            await this.ipCache.loadFirstChunk();
            this.renderIpTable();
            this.updatePaginationUI();
        } catch(e) {}
    }

    // Discards the current IP cache and fetches fresh from the server with whatever's currently
    // in the filter inputs — the explicit "search" action (button click / Enter / combobox pick),
    // never fired on every keystroke.
    triggerIpSearch() {
        this.loadIps();
    }

    async loadKeys() {
        try {
            this.state.selectedKeyIds.clear();
            this.state.apiKeys = await this.apiFetch('/keys');
            this.renderKeysTable();
            this.updateRightsSelector();
        } catch(e) {}
    }

    async loadGroups() {
        try {
            this.state.selectedGroupIds.clear();
            this.state.groups = await this.apiFetch('/groups');
            this.renderGroupsTable();
            // manage-rights-group and the IP filter both operate on group NAME (the API's
            // group_name field is flexible/name-based); the webhook target needs the real UUID,
            // since CreateWebhookPayload.group_id has no name-or-id flexible resolution.
            const byName = this.state.groups.map(g => ({ value: g.name, label: g.name }));
            const byId = this.state.groups.map(g => ({ value: g.id, label: g.name }));
            this.groupFilterCombobox.setOptions(byName);
            this.rightsGroupCombobox.setOptions(byName);
            this.webhookGroupCombobox.setOptions(byId);
        } catch(e) {}
    }

    async loadWebhooks() {
        try {
            this.state.webhooks = await this.apiFetch('/webhooks');
            this.renderWebhooksTable();
        } catch(e) {}
    }

    async fetchAuditLogsChunk(offset, limit) {
        const params = new URLSearchParams({ limit, offset });
        return await this.apiFetch(`/audit-logs?${params.toString()}`);
    }

    async loadAuditLogs() {
        if (!this.state.profile?.is_master) return;
        try {
            await this.auditCache.loadFirstChunk();
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

        // The base .toast class starts hidden (opacity: 0, slid off-screen) so this class add
        // triggers the CSS transition into view. Applying it in the same tick as appendChild()
        // often gets coalesced by the browser with no visible transition, so defer one frame to
        // let the hidden state actually paint first.
        requestAnimationFrame(() => {
            toast.classList.add('visible');
        });

        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // Custom dark-themed replacement for window.confirm(). Populates and shows #confirm-modal,
    // then resolves true/false based on which button (or Escape/backdrop/Enter) the user picks.
    // Every call re-binds its own listeners and tears them down on resolve, so concurrent calls
    // never leak or stack duplicate handlers on the shared modal element.
    showConfirmModal({ title = 'Are you sure?', message = '', confirmText = 'Confirm', cancelText = 'Cancel', danger = false } = {}) {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-modal-title');
        const messageEl = document.getElementById('confirm-modal-message');
        const confirmBtn = document.getElementById('confirm-modal-confirm');
        const cancelBtn = document.getElementById('confirm-modal-cancel');

        titleEl.textContent = title;
        messageEl.textContent = message;
        confirmBtn.textContent = confirmText;
        cancelBtn.textContent = cancelText;
        confirmBtn.className = `btn ${danger ? 'btn-danger' : 'btn-primary'}`;

        modal.classList.remove('hidden');

        return new Promise((resolve) => {
            const cleanup = (result) => {
                modal.classList.add('hidden');
                confirmBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                modal.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onKeydown);
                resolve(result);
            };
            const onConfirm = () => cleanup(true);
            const onCancel = () => cleanup(false);
            const onBackdropClick = (e) => { if (e.target === modal) cleanup(false); };
            const onKeydown = (e) => {
                if (e.key === 'Escape') cleanup(false);
                if (e.key === 'Enter') cleanup(true);
            };

            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
            modal.addEventListener('click', onBackdropClick);
            document.addEventListener('keydown', onKeydown);
            confirmBtn.focus();
        });
    }

    // Wires a table's "select all" header checkbox and its .row-select body checkboxes to a
    // shared Set of selected row ids, keeping the header checkbox's checked/indeterminate state
    // and the "Delete Selected" button's enabled state + label in sync. Called at the end of
    // every render*Table() — row checkboxes are recreated each time (tbody.innerHTML replace),
    // so they get fresh listeners each call; the header checkbox and delete button are static
    // elements outside the tbody, so their handlers are (re)assigned via .onchange/.onclick
    // rather than addEventListener to avoid stacking duplicate handlers across renders.
    wireRowSelection({ tbodySelector, selectAllId, deleteBtnId, deleteBtnLabel, selectedSet, onDeleteSelected }) {
        const selectAllEl = document.getElementById(selectAllId);
        const deleteBtn = document.getElementById(deleteBtnId);
        const rowCheckboxes = () => [...document.querySelectorAll(`${tbodySelector} .row-select`)];

        const updateControls = () => {
            const boxes = rowCheckboxes();
            const checkedCount = boxes.filter(cb => cb.checked).length;
            selectAllEl.checked = boxes.length > 0 && checkedCount === boxes.length;
            selectAllEl.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
            // With nothing selected the batch-delete control is hidden outright rather than merely
            // disabled: a greyed-out button that can never be clicked in that state is pure noise.
            // The wrapper is hidden alongside the button so it reclaims its vertical space instead
            // of leaving a gap above the table.
            const nothingSelected = selectedSet.size === 0;
            deleteBtn.classList.toggle('hidden', nothingSelected);
            deleteBtn.closest('.batch-actions')?.classList.toggle('hidden', nothingSelected);
            deleteBtn.disabled = nothingSelected;
            deleteBtn.textContent = selectedSet.size > 0 ? `${deleteBtnLabel} (${selectedSet.size})` : deleteBtnLabel;
        };

        rowCheckboxes().forEach(cb => {
            cb.checked = selectedSet.has(cb.dataset.id);
            cb.addEventListener('change', () => {
                if (cb.checked) selectedSet.add(cb.dataset.id); else selectedSet.delete(cb.dataset.id);
                updateControls();
            });
        });

        selectAllEl.onchange = () => {
            rowCheckboxes().forEach(cb => {
                cb.checked = selectAllEl.checked;
                if (cb.checked) selectedSet.add(cb.dataset.id); else selectedSet.delete(cb.dataset.id);
            });
            updateControls();
        };

        deleteBtn.onclick = () => onDeleteSelected();

        updateControls();
    }

    // Addresses in the given data set that belong to both a banlist AND a whitelist group at
    // once — a conflicting/ambiguous firewall state worth flagging. Scans the caller-supplied
    // array (the full cached chunk, up to 100 records) rather than just the visible 15-row page,
    // so a conflict is far less likely to be missed just because its two rows landed on
    // different local pages of the same chunk.
    findConflictingAddresses(items) {
        const typesByAddress = new Map();
        for (const ip of items) {
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
        const cached = this.ipCache.items;
        const conflicts = this.findConflictingAddresses(cached);

        // "Conflicted IPs Only" shows every match across the whole cached chunk at once (usually
        // a short list — conflicts are the exception, not the rule) rather than being paginated
        // like the normal view; the normal view stays a clean 15-row local page.
        const rows = this.state.showConflictsOnly
            ? cached.filter(ip => conflicts.has(ip.target_address))
            : this.ipCache.currentPageItems;

        if (rows.length === 0) {
            const msg = this.state.showConflictsOnly
                ? 'No conflicting records in the current view.'
                : 'No records found.';
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">${msg}</td></tr>`;
            this.wireRowSelection({
                tbodySelector: '#ip-table-body', selectAllId: 'select-all-ips', deleteBtnId: 'delete-selected-ips',
                deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedIpIds,
                onDeleteSelected: () => this.batchDeleteIps()
            });
            return;
        }

        tbody.innerHTML = rows.map(ip => {
            const isConflicting = conflicts.has(ip.target_address);
            const statusBadge = ip.group_type === 'whitelist'
                ? '<span class="badge badge-white">Whitelisted</span>'
                : '<span class="badge badge-ban">Banned</span>';

            return `
            <tr>
                <td>${ip.is_locked ? '' : `<input type="checkbox" class="row-select" data-id="${ip.id}">`}</td>
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
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteIp('${escapeHtml(ip.target_address)}', '${escapeHtml(ip.group_name)}')" ${ip.is_locked ? 'disabled' : ''}>Delete</button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');

        this.wireRowSelection({
            tbodySelector: '#ip-table-body', selectAllId: 'select-all-ips', deleteBtnId: 'delete-selected-ips',
            deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedIpIds,
            onDeleteSelected: () => this.batchDeleteIps()
        });
    }

    renderKeysTable() {
        const tbody = document.getElementById('apikeys-table-body');
        if (this.state.apiKeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No API keys.</td></tr>';
            this.wireRowSelection({
                tbodySelector: '#apikeys-table-body', selectAllId: 'select-all-keys', deleteBtnId: 'delete-selected-keys',
                deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedKeyIds,
                onDeleteSelected: () => this.batchDeleteKeys()
            });
            return;
        }

        tbody.innerHTML = this.state.apiKeys.map(k => `
            <tr>
                <td><input type="checkbox" class="row-select" data-id="${k.id}"></td>
                <td><strong>${escapeHtml(k.name)}</strong></td>
                <td class="font-mono">${escapeHtml(k.bound_ips || '-')}</td>
                <td>${this.renderKeyScopes(k)}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-secondary" onclick="window.app.openEditKeyModal('${k.id}')">Edit</button>
                        <button class="btn btn-sm btn-secondary" onclick="window.app.regenerateKeySecret('${k.id}')" title="Replace BOTH the API key and its signing secret">Regenerate</button>
                        <button class="btn btn-sm btn-cancel" onclick="window.app.rotateSigningSecret('${k.id}')" title="Replace only the HMAC signing secret; the API key, name and permissions stay the same">Rotate Secret</button>
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteKey('${k.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `).join('');

        this.wireRowSelection({
            tbodySelector: '#apikeys-table-body', selectAllId: 'select-all-keys', deleteBtnId: 'delete-selected-keys',
            deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedKeyIds,
            onDeleteSelected: () => this.batchDeleteKeys()
        });
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

    renderGroupsTable() {
        const tbody = document.getElementById('groups-table-body');
        if (this.state.groups.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No groups.</td></tr>';
            this.wireRowSelection({
                tbodySelector: '#groups-table-body', selectAllId: 'select-all-groups', deleteBtnId: 'delete-selected-groups',
                deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedGroupIds,
                onDeleteSelected: () => this.batchDeleteGroups()
            });
            return;
        }

        tbody.innerHTML = this.state.groups.map(g => {
            const typeBadge = g.group_type === 'whitelist'
                ? '<span class="badge badge-white">Whitelist</span>'
                : '<span class="badge badge-ban">Banlist</span>';
            return `
            <tr>
                <td><input type="checkbox" class="row-select" data-id="${g.id}"></td>
                <td class="font-mono text-sm">${g.id.substring(0, 8)}...</td>
                <td><strong>${escapeHtml(g.name)}</strong></td>
                <td>${typeBadge}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteGroup('${g.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');

        this.wireRowSelection({
            tbodySelector: '#groups-table-body', selectAllId: 'select-all-groups', deleteBtnId: 'delete-selected-groups',
            deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedGroupIds,
            onDeleteSelected: () => this.batchDeleteGroups()
        });
    }

    renderWebhooksTable() {
        const tbody = document.getElementById('webhooks-table-body');
        if (this.state.webhooks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No webhooks.</td></tr>';
            return;
        }

        tbody.innerHTML = this.state.webhooks.map(w => {
            // Older rows (and any response from a pre-signature-mode server) carry no field at all;
            // treat that as the legacy default rather than rendering "undefined".
            const mode = w.signature_mode || 'BODY_ONLY';
            const badgeClass = mode === 'CANONICAL_V1' ? 'badge-canonical' : 'badge-body-only';
            return `
            <tr>
                <td class="font-mono text-sm">${w.id.split('-')[0]}...</td>
                <td><strong>${escapeHtml(w.name)}</strong></td>
                <td class="font-mono text-sm">${escapeHtml(w.target_url)}</td>
                <td><span class="badge ${badgeClass}">${escapeHtml(mode)}</span></td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteWebhook('${w.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');
    }

    updatePaginationUI() {
        const pr = document.getElementById('btn-prev');
        const nt = document.getElementById('btn-next');
        const ind = document.getElementById('page-indicator');

        pr.disabled = !this.ipCache.hasPrevPage;
        nt.disabled = !this.ipCache.hasNextPage;
        ind.textContent = `Page ${this.ipCache.localPage + 1}`;
    }

    renderAuditLogsTable() {
        const tbody = document.getElementById('audit-logs-table-body');
        const rows = this.auditCache.currentPageItems;
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No audit log entries.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(log => {
            const keyDisplay = log.api_key_name
                ? `${escapeHtml(log.api_key_name)}${log.api_key_prefix ? ` <span class="text-muted text-sm">(${escapeHtml(log.api_key_prefix)}...)</span>` : ''}`
                : '<span class="text-muted">System</span>';
            return `
            <tr>
                <td class="text-sm">${new Date(log.timestamp).toLocaleString()}</td>
                <td class="text-sm">${keyDisplay}</td>
                <td class="font-mono text-sm">${escapeHtml(log.client_ip || '-')}</td>
                <td><span class="badge badge-scope">${escapeHtml(log.action)}</span></td>
                <td class="font-mono text-sm">${escapeHtml(log.target_address || '-')}</td>
                <td class="text-sm">${escapeHtml(log.group_names || '-')}</td>
                <td class="text-sm">${escapeHtml(log.details || '-')}</td>
            </tr>
        `;
        }).join('');
    }

    updateAuditPaginationUI() {
        const pr = document.getElementById('audit-btn-prev');
        const nt = document.getElementById('audit-btn-next');
        const ind = document.getElementById('audit-page-indicator');

        pr.disabled = !this.auditCache.hasPrevPage;
        nt.disabled = !this.auditCache.hasNextPage;
        ind.textContent = `Page ${this.auditCache.localPage + 1}`;
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
        const ok = await this.showConfirmModal({
            title: 'Delete IP Record',
            message: `Delete the rule for ${targetAddress} in group "${groupName}"?`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            const params = new URLSearchParams({ target_address: targetAddress, group_name: groupName });
            await this.apiFetch(`/ips?${params.toString()}`, { method: 'DELETE' });
            this.showToast("Record deleted", 'success');
            this.loadInitialData();
        } catch(e) {}
    }

    async batchDeleteIps() {
        const count = this.state.selectedIpIds.size;
        if (count === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected IP Records',
            message: `Delete ${count} selected IP record${count === 1 ? '' : 's'}? This cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const targets = this.ipCache.items.filter(ip => this.state.selectedIpIds.has(ip.id));
        const results = await Promise.allSettled(targets.map(ip => {
            const params = new URLSearchParams({ target_address: ip.target_address, group_name: ip.group_name });
            return this.apiFetch(`/ips?${params.toString()}`, { method: 'DELETE' });
        }));

        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0 ? `${count} record${count === 1 ? '' : 's'} deleted` : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
        this.loadInitialData();
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
            // Both halves must be surfaced: a key without its signing secret cannot sign a single
            // request, and the secret is never retrievable again after this response.
            document.getElementById('apikey-signing-secret').textContent = res.signing_secret;
            reveal.classList.remove('hidden');
            
            document.getElementById('form-create-apikey').reset();
            this.loadKeys();
        } catch(e) {}
    }

    async manageKeyRights(e) {
        e.preventDefault();
        const keyId = document.getElementById('manage-rights-key').value;
        const groupName = document.getElementById('manage-rights-group').value;

        if (!keyId || !groupName) {
            this.showToast('Please select both a target key and a group', 'error');
            return;
        }

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
        const key = this.state.apiKeys.find(k => k.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete API Key',
            message: `Delete the API key "${key ? key.name : id}"? This immediately revokes its access and cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/keys/${id}`, { method: 'DELETE' });
            this.showToast("Key deleted", 'success');
            this.loadKeys();
        } catch(e) {}
    }

    async batchDeleteKeys() {
        const count = this.state.selectedKeyIds.size;
        if (count === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected API Keys',
            message: `Delete ${count} selected API key${count === 1 ? '' : 's'}? This immediately revokes their access and cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const ids = [...this.state.selectedKeyIds];
        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/keys/${id}`, { method: 'DELETE' })));

        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0 ? `${count} key${count === 1 ? '' : 's'} deleted` : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
        this.loadKeys();
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

    /**
     * Rotates only the HMAC signing secret via POST /api/keys/{id}/rotate-secret.
     *
     * Narrower than regenerateKeySecret(): the API key itself, its name, and every RBAC grant are
     * left intact, so only the signing half of the credential needs redistributing.
     */
    async rotateSigningSecret(id) {
        const key = this.state.apiKeys.find(k => k.id === id);
        const ok = await this.showConfirmModal({
            title: 'Rotate Signing Secret',
            message: `Generate a new HMAC signing secret for "${key ? key.name : id}"? `
                + `The API key, its name and its permissions stay the same, but the current signing `
                + `secret stops working immediately — every client using this key must be updated.`,
            confirmText: 'Rotate Secret',
            danger: true
        });
        if (!ok) return;

        try {
            const res = await this.apiFetch(`/keys/${id}/rotate-secret`, { method: 'POST' });
            document.getElementById('signing-secret-key-name').textContent = res.name;
            document.getElementById('signing-secret-value').textContent = res.signing_secret;
            document.getElementById('signing-secret-modal').classList.remove('hidden');
            this.showToast('Signing secret rotated', 'success');

            // Rotating your own key re-keys the credential this very session signs with. Unlike a
            // full regenerate, the API key is still valid — so re-sign in place with the new secret
            // rather than forcing a logout, keeping the session alive.
            if (this.state.profile && this.state.profile.id === id) {
                this.setCredentials(this.apiKey, res.signing_secret);
                this.showToast('Your own signing secret was updated — this session now uses it.', 'success');
            }
        } catch (e) {}
    }

    async regenerateKeySecret(id) {
        const ok = await this.showConfirmModal({
            title: 'Regenerate Secret',
            message: "Regenerate this key's secret? The old secret will stop working immediately.",
            confirmText: 'Regenerate',
            danger: true
        });
        if (!ok) return;
        try {
            const res = await this.apiFetch(`/keys/${id}/rotate`, { method: 'POST' });
            document.getElementById('secret-reveal-value').textContent = res.plaintext_key;
            document.getElementById('secret-reveal-signing-secret').textContent = res.signing_secret;
            document.getElementById('secret-reveal-modal').classList.remove('hidden');
            this.showToast("Secret rotated", 'success');

            // Rotating the key you are currently logged in with invalidates the credential this
            // session is signing with, so every subsequent request would 401. Log out deliberately
            // (after the modal has the new values on screen) rather than letting that look like a
            // random session failure.
            if (this.state.profile && this.state.profile.id === id) {
                this.showToast("You rotated your own key — log in again with the new credentials.", 'error');
                this.setCredentials('', '');
                // The reveal modal (z-index 20000) stays layered above the login screen (10000), so
                // the new credentials remain readable and copyable while logged out.
                this.showLogin();
            }
        } catch(e) {}
    }

    async revokeGroupPermission(keyId, groupIdentifier) {
        const ok = await this.showConfirmModal({
            title: 'Revoke Permission',
            message: "Revoke this key's permission on this group?",
            confirmText: 'Revoke',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/keys/${keyId}/permissions/${groupIdentifier}`, { method: 'DELETE' });
            this.showToast("Permission revoked", 'success');
            this.loadKeys();
        } catch(e) {}
    }

    async createGroup(e) {
        e.preventDefault();
        const name = document.getElementById('create-group-name').value;
        const group_type = document.getElementById('group-type-select').value;
        try {
            await this.apiFetch('/groups', { method: 'POST', body: JSON.stringify({ name, group_type }) });
            document.getElementById('form-create-group').reset();
            this.loadGroups();
            this.showToast("Group created", 'success');
        } catch(e) {}
    }

    async deleteGroup(id) {
        const group = this.state.groups.find(g => g.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete Group',
            message: `Delete the group "${group ? group.name : id}"? This operation cascades and wipes all associated resources.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/groups/${id}`, { method: 'DELETE' });
            this.loadGroups();
            this.loadIps();
        } catch(e) {}
    }

    async batchDeleteGroups() {
        const count = this.state.selectedGroupIds.size;
        if (count === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected Groups',
            message: `Delete ${count} selected group${count === 1 ? '' : 's'}? This cascades and wipes all associated resources.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const ids = [...this.state.selectedGroupIds];
        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/groups/${id}`, { method: 'DELETE' })));

        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0 ? `${count} group${count === 1 ? '' : 's'} deleted` : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
        this.loadGroups();
        this.loadIps();
    }

    async createWebhook(e) {
        e.preventDefault();

        const groupId = document.getElementById('webhook-group-id').value;
        if (!groupId) {
            this.showToast('Please select a valid target group from the list', 'error');
            return;
        }

        const eventKeys = { add: 'IP_ADD', update: 'IP_UPDATE', delete: 'IP_DELETE' };
        const checkedEvents = Object.entries(eventKeys)
            .filter(([id]) => document.getElementById(`webhook-event-${id}`).checked)
            .map(([, action]) => action);
        if (checkedEvents.length === 0) {
            this.showToast('Select at least one event for this webhook to trigger on', 'error');
            return;
        }
        // All three checked is equivalent to (and sent as) "no filter" — the backend's own
        // default for an omitted `events` field — rather than a redundant explicit list.
        const events = checkedEvents.length === Object.keys(eventKeys).length ? null : checkedEvents.join(',');

        const payload = {
            name: document.getElementById('webhook-name').value,
            target_url: document.getElementById('webhook-url').value,
            secret_token: document.getElementById('webhook-secret').value,
            group_id: groupId,
            headers_json: document.getElementById('webhook-headers').value || null,
            payload_template: document.getElementById('webhook-template').value,
            signature_mode: document.getElementById('webhook-signature-mode').value,
            events
        };

        try {
            await this.apiFetch('/webhooks', { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('form-create-webhook').reset();
            this.loadWebhooks();
            this.showToast("Webhook configured", 'success');
        } catch(e) {}
    }

    async deleteWebhook(id) {
        const webhook = this.state.webhooks.find(w => w.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete Webhook',
            message: `Delete the webhook "${webhook ? webhook.name : id}"?`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/webhooks/${id}`, { method: 'DELETE' });
            this.loadWebhooks();
            this.showToast("Webhook configuration deleted", 'success');
        } catch(e) {}
    }

    // ───────────────────────────────────────────────────────
    // Event Binding
    // ───────────────────────────────────────────────────────
    bindEvents() {
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.login(
                document.getElementById('login-key').value.trim(),
                document.getElementById('login-secret').value.trim()
            );
        });

        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('refresh-btn').addEventListener('click', () => this.loadInitialData());

        // Tabs. Each panel is fully re-rendered from cached/fetched state on every switch (see
        // the render* methods) rather than mutated in place, so repeatedly switching tabs can
        // never accumulate stale rows — every render starts from tbody.innerHTML = ..., a full
        // replace, never an append.
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.tab-btn').forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

                const trg = e.target;
                trg.classList.add('active');
                trg.setAttribute('aria-selected', 'true');
                document.getElementById(`tab-${trg.dataset.tab}`).classList.add('active');
            });
        });

        // IP Form
        document.getElementById('manage-form').addEventListener('submit', (e) => e.preventDefault());
        document.getElementById('btn-ban').addEventListener('click', () => this.upsertIp(false));
        document.getElementById('btn-white').addEventListener('click', () => this.upsertIp(true));

        // Filters — explicit search only: the search button, Enter in a text filter, or the
        // status dropdown's own change event. Typing alone no longer fires a request.
        document.getElementById('ip-search-btn').addEventListener('click', () => this.triggerIpSearch());
        document.getElementById('ip-filter').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.triggerIpSearch(); }
        });
        document.getElementById('cause-filter').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.triggerIpSearch(); }
        });
        document.getElementById('group-filter').addEventListener('keydown', (e) => {
            // If the combobox's suggestion menu is open, let its own Enter handler pick the
            // highlighted option first (which itself triggers a search via onSelect above) —
            // otherwise this would double-fire. Only handle Enter directly when the menu is
            // closed (nothing to select, e.g. no matches or not focused).
            if (e.key === 'Enter' && this.groupFilterCombobox.menu.classList.contains('hidden')) {
                e.preventDefault();
                this.triggerIpSearch();
            }
        });
        document.getElementById('status-filter').addEventListener('change', () => this.triggerIpSearch());
        document.getElementById('conflict-filter-btn').addEventListener('click', (e) => {
            this.state.showConflictsOnly = !this.state.showConflictsOnly;
            e.currentTarget.classList.toggle('active', this.state.showConflictsOnly);
            this.renderIpTable();
        });

        // Pagination — most clicks are a pure client-side slice of the cached chunk; nextPage()
        // only actually awaits a network request on the rare occasion the background prefetch
        // hasn't resolved yet by the time the user gets there.
        document.getElementById('btn-prev').addEventListener('click', () => {
            this.ipCache.prevPage();
            this.renderIpTable();
            this.updatePaginationUI();
        });
        document.getElementById('btn-next').addEventListener('click', async () => {
            await this.ipCache.nextPage();
            this.renderIpTable();
            this.updatePaginationUI();
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

        // Signing-secret reveal modal (used after POST /api/keys/{id}/rotate-secret)
        document.getElementById('signing-secret-close').addEventListener('click', () => {
            document.getElementById('signing-secret-modal').classList.add('hidden');
        });
        document.getElementById('signing-secret-copy').addEventListener('click', async () => {
            const value = document.getElementById('signing-secret-value').textContent;
            // navigator.clipboard is itself gated on a secure context — the same limitation that
            // makes the pure-JS HMAC fallback necessary — so fall back to selecting the text and
            // telling the user to copy manually rather than silently doing nothing.
            try {
                if (!navigator.clipboard) throw new Error('clipboard unavailable');
                await navigator.clipboard.writeText(value);
                this.showToast('Signing secret copied to clipboard', 'success');
            } catch {
                const node = document.getElementById('signing-secret-value');
                const range = document.createRange();
                range.selectNodeContents(node);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                this.showToast('Clipboard unavailable (needs HTTPS) — the secret is selected, press Ctrl+C', 'error');
            }
        });

        // Audit log pagination — same client-side-slice-first model as the IP table above.
        document.getElementById('audit-btn-prev').addEventListener('click', () => {
            this.auditCache.prevPage();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        });
        document.getElementById('audit-btn-next').addEventListener('click', async () => {
            await this.auditCache.nextPage();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
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

// Bootstrap
window.addEventListener('DOMContentLoaded', () => {
    window.app = new FirewallClient();
});
