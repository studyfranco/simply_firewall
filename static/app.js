const PAGE_SIZE = 50;
let currentPage = 1;

const searchInput = document.getElementById('search-input');
const statusSelect = document.getElementById('status-select');
const prevBtn = document.getElementById('prev-btn');
const nextBtn = document.getElementById('next-btn');
const pageIndicator = document.getElementById('page-indicator');
const tableBody = document.getElementById('table-body');

const apiKeyInput = document.getElementById('api-key-input');
const targetIpInput = document.getElementById('target-ip');
const btnBan = document.getElementById('btn-ban');
const btnWhite = document.getElementById('btn-white');
const ruleStatus = document.getElementById('rule-status');

// Debounce for input
let typingTimer;
const doneTypingInterval = 300; // ms

async function fetchIps(page) {
    const search = searchInput.value.trim();
    const status = statusSelect.value;
    const offset = (page - 1) * PAGE_SIZE;

    const query = new URLSearchParams({
        limit: PAGE_SIZE,
        offset: offset
    });

    if (status) query.append('status', status);

    try {
        const response = await fetch(`/api/ips?${query.toString()}`);
        if (!response.ok) throw new Error('Failed to fetch data');
        const data = await response.json();

        tableBody.innerHTML = '';
        if (data.length === 0 && page === 1) {
            tableBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No records found.</td></tr>';
        } else {
            const renderedData = search
                ? data.filter(r => r.address.includes(search))
                : data;

            renderedData.forEach(ip => {
                const tr = document.createElement('tr');
                tr.className = 'ip-row file-row';

                const addressTd = document.createElement('td');
                addressTd.className = 'font-mono';
                addressTd.textContent = ip.address;

                const statusTd = document.createElement('td');
                const badge = document.createElement('span');
                badge.className = `badge ${ip.is_whitelist ? 'white' : 'ban'}`;
                badge.style.border = `1px solid ${ip.is_whitelist ? 'var(--success)' : 'var(--danger)'}`;
                badge.style.color = ip.is_whitelist ? 'var(--success)' : 'var(--danger)';
                badge.style.padding = '3px 8px';
                badge.style.borderRadius = '4px';
                badge.textContent = ip.is_whitelist ? 'Whitelist' : 'Banned';
                statusTd.appendChild(badge);

                const createdTd = document.createElement('td');
                createdTd.textContent = ip.created_at.replace('T', ' ');
                createdTd.className = 'text-muted';

                const updatedTd = document.createElement('td');
                updatedTd.textContent = ip.updated_at.replace('T', ' ');
                updatedTd.className = 'text-muted';

                tr.appendChild(addressTd);
                tr.appendChild(statusTd);
                tr.appendChild(createdTd);
                tr.appendChild(updatedTd);

                tableBody.appendChild(tr);
            });

            if (renderedData.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No records matched your search in this subset.</td></tr>';
            }
        }

        currentPage = page;
        pageIndicator.textContent = `Page ${page}`;
        prevBtn.disabled = page === 1;
        nextBtn.disabled = data.length < PAGE_SIZE;

    } catch (e) {
        console.error('Error:', e);
        tableBody.innerHTML = '<tr><td colspan="4" class="text-center" style="color:var(--danger)">Failed to load data.</td></tr>';
    }
}

async function mutateRule(isWhitelist) {
    const key = apiKeyInput.value.trim();
    const target = targetIpInput.value.trim();

    ruleStatus.className = 'toast text-sm mt-2 visible';
    if (!key || !target) {
        ruleStatus.className = 'toast toast-error text-sm mt-2 visible';
        ruleStatus.style.color = 'var(--danger)';
        ruleStatus.textContent = 'API Key and Target IP are required.';
        return;
    }

    ruleStatus.style.color = 'var(--text-main)';
    ruleStatus.textContent = 'Processing request...';

    const endpoint = isWhitelist ? '/api/white' : '/api/ban';

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': key
            },
            body: JSON.stringify({
                address: target,
                group_id: null,
                cause: null
            })
        });

        if (res.ok) {
            ruleStatus.className = 'toast toast-success text-sm mt-2 visible';
            ruleStatus.style.color = 'var(--success)';
            ruleStatus.textContent = `Successfully ${isWhitelist ? 'whitelisted' : 'banned'} ${target}.`;
            targetIpInput.value = '';
            // Refresh table dynamically to Page 1 to see the new addition
            fetchIps(1);
        } else {
            let errorText = await res.text();
            ruleStatus.className = 'toast toast-error text-sm mt-2 visible';
            ruleStatus.style.color = 'var(--danger)';
            ruleStatus.textContent = `Error ${res.status}: ${errorText || 'Unauthorized or Bad Request'}`;
        }
    } catch (err) {
        ruleStatus.className = 'toast toast-error text-sm mt-2 visible';
        ruleStatus.style.color = 'var(--danger)';
        ruleStatus.textContent = `Network Error: ${err.message}`;
    }
    
    setTimeout(() => {
        ruleStatus.classList.remove('visible');
    }, 4000);
}

// Event Listeners
searchInput.addEventListener('input', () => {
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
        fetchIps(1);
    }, doneTypingInterval);
});

statusSelect.addEventListener('change', () => {
    fetchIps(1);
});

prevBtn.addEventListener('click', () => {
    if (currentPage > 1) fetchIps(currentPage - 1);
});

nextBtn.addEventListener('click', () => {
    fetchIps(currentPage + 1);
});

btnBan.addEventListener('click', () => mutateRule(false));
btnWhite.addEventListener('click', () => mutateRule(true));
