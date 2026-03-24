/* ─── Q KB Explorer — Frontend Logic ─── */
/* Adapted from Qualys API Engine by netsecops-76 */

let platforms = {};
let activeCredentialId = null;
let apiVersionPref = "v5";
const VAULT_MASKED = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"; // ••••••••
let _sessionTimeoutInterval = null;

// ─── Vault Auth Cookie ──────────────────────────────────────────────────
const VAULT_AUTH_COOKIE = "qkbe-vault-unlocked";

function hasVaultCookie() {
    // Cookie is HttpOnly so not readable via JS — track auth state in localStorage
    return localStorage.getItem("qkbe_vault_unlocked_at") !== null;
}
function markVaultAuthenticated() {
    // Called after successful server-side verify (server sets HttpOnly cookie)
    localStorage.setItem("qkbe_vault_unlocked_at", Date.now().toString());
}
function clearVaultState() {
    // Server clears the HttpOnly cookie via /api/auth/logout
    localStorage.removeItem("qkbe_vault_unlocked_at");
    fetch("/api/auth/logout", {
        method: "POST",
        headers: { "X-Requested-With": "QKBE" },
    }).catch(() => {});
}

// ─── Session Timeout ────────────────────────────────────────────────────
function formatTimeout(minutes) {
    if (minutes < 60) return minutes + " min";
    const hrs = Math.floor(minutes / 60);
    const mins = minutes % 60;
    if (mins === 0) return hrs + " hr";
    return hrs + " hr " + mins + " min";
}

function initSessionTimeout() {
    if (_sessionTimeoutInterval) {
        clearInterval(_sessionTimeoutInterval);
        _sessionTimeoutInterval = null;
    }
    const saved = localStorage.getItem("qkbe_settings");
    if (!saved) return;
    let s;
    try { s = JSON.parse(saved); } catch (e) { return; }
    if (!s.sessionTimeout || !s.sessionTimeout.enabled) return;

    const timeoutMs = s.sessionTimeout.minutes * 60 * 1000;

    _sessionTimeoutInterval = setInterval(() => {
        const unlockedAt = parseInt(localStorage.getItem("qkbe_vault_unlocked_at") || "0", 10);
        if (!unlockedAt) return;
        if (Date.now() - unlockedAt >= timeoutMs) {
            clearInterval(_sessionTimeoutInterval);
            _sessionTimeoutInterval = null;
            clearVaultState();
            showToast("Session expired — please re-authenticate", "info");
            fetch("/api/credentials")
                .then(r => r.json())
                .then(creds => {
                    if (Array.isArray(creds) && creds.length > 0) showVaultAuth(creds);
                })
                .catch(() => {});
        }
    }, 30000);
}

function _updateServerSessionTimeout(seconds) {
    // Update the server-side cookie max_age for session timeout
    if (hasVaultCookie()) {
        fetch("/api/auth/session", {
            method: "PATCH",
            headers: { "Content-Type": "application/json", "X-Requested-With": "QKBE" },
            body: JSON.stringify({ max_age: seconds }),
        }).catch(() => {});
    }
}

function onSessionTimeoutToggle(checked) {
    document.getElementById("sessionTimeoutSliderGroup").style.display = checked ? "block" : "none";
    saveSettings();
    initSessionTimeout();
    if (checked && hasVaultCookie()) {
        const minutes = parseInt(document.getElementById("sessionTimeoutSlider").value, 10);
        _updateServerSessionTimeout(minutes * 60);
    }
}

function onSessionTimeoutSlider(value) {
    const minutes = parseInt(value, 10);
    document.getElementById("sessionTimeoutDisplay").textContent = formatTimeout(minutes);
    saveSettings();
    initSessionTimeout();
    _updateServerSessionTimeout(minutes * 60);
}

async function apiFetch(url, options = {}) {
    // Merge CSRF header into all requests
    options.headers = Object.assign({ "X-Requested-With": "QKBE" }, options.headers || {});
    const resp = await fetch(url, options);
    if (resp.status === 401) {
        clearVaultState();
        try {
            const creds = await fetch("/api/credentials").then(r => r.json());
            if (Array.isArray(creds) && creds.length > 0) showVaultAuth(creds);
        } catch (e) { /* ignore */ }
        throw new Error("Authentication required");
    }
    return resp;
}

// ── Total record counts per data type (updated from sync status) ────────
let _totalCounts = { qids: 0, cids: 0, policies: 0, mandates: 0 };

// ── Track whether each tab has auto-loaded its first page ───────────────
let _tabLoaded = { dashboard: false, qids: false, cids: false, policies: false, mandates: false, help: false };

// ── In-flight request abort controllers for type-ahead ──────────────────
const _searchAbort = { qids: null, cids: null, policies: null, mandates: null };

// ── Chart.js instances (for destroy/recreate on theme change) ────────────
let _charts = { severity: null, criticality: null, categories: null };

// ── Modal stack for z-index management ──────────────────────────────────
let _modalStack = [];
const _MODAL_BASE_Z = 9999;

// ── Keyboard Shortcuts map ──────────────────────────────────────────────
const _TAB_NAMES = ["dashboard", "qids", "cids", "policies", "mandates", "settings", "help"];
const _SEARCH_INPUTS = {
    qids: "qidSearchInput", cids: "cidSearchInput",
    policies: "policySearchInput", mandates: "mandateSearchInput",
};
const _SHORTCUTS = {
    "1": { action: () => switchTab("dashboard"), desc: "Dashboard tab" },
    "2": { action: () => switchTab("qids"), desc: "QIDs tab" },
    "3": { action: () => switchTab("cids"), desc: "CIDs tab" },
    "4": { action: () => switchTab("policies"), desc: "Policies tab" },
    "5": { action: () => switchTab("mandates"), desc: "Mandates tab" },
    "6": { action: () => switchTab("settings"), desc: "Settings tab" },
    "7": { action: () => switchTab("help"), desc: "Help tab" },
    "/": { action: () => _focusCurrentSearch(), desc: "Focus search input" },
    "?": { action: () => _showShortcutsModal(), desc: "Show shortcuts" },
    "t": { action: () => toggleTheme(), desc: "Toggle theme" },
    "b": { action: () => _toggleCurrentBookmark(), desc: "Toggle bookmark" },
};

function _focusCurrentSearch() {
    const active = document.querySelector(".tab-btn.active");
    const tab = active ? active.dataset.tab : "";
    const inputId = _SEARCH_INPUTS[tab];
    if (inputId) {
        const el = document.getElementById(inputId);
        if (el) el.focus();
    }
}

function _showShortcutsModal() {
    const content = document.getElementById("shortcutsContent");
    if (content) {
        content.innerHTML = '<table class="shortcuts-table">' +
            Object.entries(_SHORTCUTS).map(([key, s]) =>
                `<tr><td><kbd class="kbd">${escapeHtml(key)}</kbd></td><td>${escapeHtml(s.desc)}</td></tr>`
            ).join("") + '</table>';
    }
    openModal("shortcutsModal");
}

// ── Bookmarks (localStorage) ────────────────────────────────────────────
const _BOOKMARKS_KEY = "qkbe_bookmarks";
const _BOOKMARKS_MAX = 500;

function _getBookmarks() {
    try { return JSON.parse(localStorage.getItem(_BOOKMARKS_KEY) || "{}"); }
    catch { return {}; }
}
function _saveBookmarks(bm) { localStorage.setItem(_BOOKMARKS_KEY, JSON.stringify(bm)); }

function isBookmarked(type, id) {
    return (type + ":" + id) in _getBookmarks();
}

function toggleBookmark(type, id, title, event) {
    if (event) event.stopPropagation();
    const bm = _getBookmarks();
    const key = type + ":" + id;
    if (bm[key]) {
        delete bm[key];
        _saveBookmarks(bm);
        showToast("Bookmark removed", "info");
    } else {
        if (Object.keys(bm).length >= _BOOKMARKS_MAX) {
            showToast("Bookmark limit reached (" + _BOOKMARKS_MAX + ")", "error");
            return;
        }
        bm[key] = { title: title || "", savedAt: new Date().toISOString() };
        _saveBookmarks(bm);
        showToast("Bookmarked", "success");
    }
    _refreshBookmarkStars();
}

function _toggleCurrentBookmark() {
    const modals = [
        { id: "qidDetailModal", type: "qid", titleEl: "qidDetailTitle" },
        { id: "cidDetailModal", type: "cid", titleEl: "cidDetailTitle" },
        { id: "policyDetailModal", type: "policy", titleEl: "policyDetailTitle" },
    ];
    for (const m of modals) {
        const el = document.getElementById(m.id);
        if (el && el.style.display !== "none") {
            const titleText = document.getElementById(m.titleEl)?.textContent || "";
            const idMatch = titleText.match(/\d+/);
            if (idMatch) toggleBookmark(m.type, parseInt(idMatch[0]), titleText);
            return;
        }
    }
}

function _refreshBookmarkStars() {
    document.querySelectorAll(".bookmark-star").forEach(star => {
        const type = star.dataset.bmType;
        const id = star.dataset.bmId;
        if (isBookmarked(type, id)) {
            star.classList.add("bookmarked");
            star.title = "Remove bookmark";
        } else {
            star.classList.remove("bookmarked");
            star.title = "Bookmark";
        }
    });
}

function _starHtml(type, id, title) {
    const filled = isBookmarked(type, id);
    const safeTitle = escapeHtml((title || "").replace(/'/g, ""));
    return `<span class="bookmark-star${filled ? " bookmarked" : ""}" data-bm-type="${type}" data-bm-id="${id}" onclick="toggleBookmark('${type}',${id},'${safeTitle}',event)" title="${filled ? "Remove bookmark" : "Bookmark"}">` +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="' + (filled ? "currentColor" : "none") + '" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></span>';
}

// ── Recent Searches (localStorage) ──────────────────────────────────────
const _RECENT_KEY = "qkbe_recent_searches";
const _RECENT_MAX = 20;

function _getRecentSearches() {
    try { return JSON.parse(localStorage.getItem(_RECENT_KEY) || "[]"); }
    catch { return []; }
}

function _saveRecentSearch(type, query, resultCount) {
    if (!query && !resultCount) return;
    const recent = _getRecentSearches();
    const filtered = recent.filter(r => !(r.type === type && r.query === query));
    filtered.unshift({ type, query: query || "", resultCount: resultCount || 0, timestamp: new Date().toISOString() });
    if (filtered.length > _RECENT_MAX) filtered.length = _RECENT_MAX;
    localStorage.setItem(_RECENT_KEY, JSON.stringify(filtered));
}

function clearRecentSearches(type) {
    if (type) {
        const recent = _getRecentSearches().filter(r => r.type !== type);
        localStorage.setItem(_RECENT_KEY, JSON.stringify(recent));
    } else {
        localStorage.removeItem(_RECENT_KEY);
    }
    _closeAllRecentDropdowns();
    showToast("Search history cleared", "info");
}

function toggleRecentDropdown(type) {
    const dd = document.getElementById(type + "RecentDropdown");
    if (!dd) return;
    if (dd.style.display !== "none") { dd.style.display = "none"; return; }
    _closeAllRecentDropdowns();
    const recent = _getRecentSearches().filter(r => r.type === type);
    if (recent.length === 0) {
        dd.innerHTML = '<div class="recent-item recent-empty">No recent searches</div>';
    } else {
        dd.innerHTML = recent.map((r, i) =>
            `<div class="recent-item" onclick="restoreSearch('${type}',${i})">` +
            `<span class="recent-query">${escapeHtml(r.query || "(all)")}</span>` +
            `<span class="recent-meta">${r.resultCount.toLocaleString()} results &middot; ${_timeAgo(new Date(r.timestamp))}</span>` +
            `</div>`
        ).join("") +
        `<div class="recent-item recent-clear" onclick="clearRecentSearches('${type}')">Clear history</div>`;
    }
    dd.style.display = "block";
}

function _closeAllRecentDropdowns() {
    document.querySelectorAll(".recent-dropdown").forEach(d => d.style.display = "none");
}

function restoreSearch(type, index) {
    const recent = _getRecentSearches().filter(r => r.type === type);
    const entry = recent[index];
    if (!entry) return;
    _closeAllRecentDropdowns();
    const inputId = _SEARCH_INPUTS[type];
    if (inputId) document.getElementById(inputId).value = entry.query || "";
    if (type === "qids") searchQids();
    else if (type === "cids") searchCids();
    else if (type === "policies") searchPolicies();
    else if (type === "mandates") searchMandates();
}

function openModal(id) {
    const el = document.getElementById(id);
    if (!el) return;
    // Remove from stack if already present (prevent duplicates inflating z-index)
    _modalStack = _modalStack.filter(m => m !== id);
    _modalStack.push(id);
    // Reassign z-indexes for the entire stack so order is always correct
    _modalStack.forEach((mId, i) => {
        const mEl = document.getElementById(mId);
        if (mEl) mEl.style.zIndex = _MODAL_BASE_Z + i + 1;
    });
    el.style.display = "flex";
}

function closeTopModal() {
    if (_modalStack.length === 0) return;
    const id = _modalStack.pop();
    const el = document.getElementById(id);
    if (el) { el.style.display = "none"; el.style.zIndex = ""; }
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (el) { el.style.display = "none"; el.style.zIndex = ""; }
    _modalStack = _modalStack.filter(m => m !== id);
}

// ─── Multi-Select Dropdown Component ─────────────────────────────────────
// Reusable type-ahead multi-select with pill tags.
// Options: { placeholder, serverSearch(q, callback), items }
class MultiSelect {
    constructor(wrapId, opts = {}) {
        this.wrap = document.getElementById(wrapId);
        if (!this.wrap) return;
        this.placeholder = opts.placeholder || "Search...";
        this.serverSearch = opts.serverSearch || null; // fn(query, cb) for remote search
        this.selected = [];
        this.allItems = [];
        this.highlightIdx = -1;
        this.mode = "or";                                   // "or" | "and"
        this.showModeToggle = opts.showModeToggle !== false; // default true
        this._build();
        if (opts.items) this.setItems(opts.items);
    }

    _build() {
        this.wrap.innerHTML = `
            <div class="ms-container">
                <div class="ms-pills"></div>
                <button type="button" class="ms-mode-toggle" style="display:none;" title="Toggle AND/OR filter mode">OR</button>
                <input type="text" class="ms-input" placeholder="${this.placeholder}">
            </div>
            <div class="ms-dropdown" style="display:none;"></div>`;
        this.containerEl = this.wrap.querySelector(".ms-container");
        this.pillsEl = this.wrap.querySelector(".ms-pills");
        this.toggleEl = this.wrap.querySelector(".ms-mode-toggle");
        this.inputEl = this.wrap.querySelector(".ms-input");
        this.dropdownEl = this.wrap.querySelector(".ms-dropdown");
        this.inputEl.addEventListener("input", () => this._onInput());
        this.inputEl.addEventListener("focus", () => this._open());
        this.inputEl.addEventListener("keydown", (e) => this._onKey(e));
        this.containerEl.addEventListener("click", (e) => {
            if (e.target !== this.toggleEl) this.inputEl.focus();
        });
        this.toggleEl.addEventListener("click", (e) => {
            e.stopPropagation();
            this.mode = this.mode === "or" ? "and" : "or";
            this._updateToggle();
        });
        document.addEventListener("click", (e) => {
            if (!this.wrap.contains(e.target)) this._close();
        });
    }

    _updateToggle() {
        if (!this.showModeToggle || this.selected.length < 2) {
            this.toggleEl.style.display = "none";
            return;
        }
        this.toggleEl.style.display = "";
        this.toggleEl.textContent = this.mode.toUpperCase();
        this.toggleEl.classList.toggle("ms-mode-and", this.mode === "and");
    }

    setItems(items) {
        this.allItems = items || [];
        this._renderDropdown();
    }

    _onInput() {
        const q = this.inputEl.value.trim();
        if (this.serverSearch) {
            clearTimeout(this._timer);
            this._timer = setTimeout(() => {
                this.serverSearch(q, (items) => {
                    this.allItems = items || [];
                    this.highlightIdx = -1;
                    this._renderDropdown();
                });
            }, 200);
        } else {
            this.highlightIdx = -1;
            this._renderDropdown();
        }
        if (!this._isOpen) this._open();
    }

    _onKey(e) {
        const opts = this.dropdownEl.querySelectorAll(".ms-option");
        if (e.key === "ArrowDown") {
            e.preventDefault();
            this.highlightIdx = Math.min(this.highlightIdx + 1, opts.length - 1);
            this._updateHighlight(opts);
        } else if (e.key === "ArrowUp") {
            e.preventDefault();
            this.highlightIdx = Math.max(this.highlightIdx - 1, 0);
            this._updateHighlight(opts);
        } else if (e.key === "Enter") {
            e.preventDefault();
            if (this.highlightIdx >= 0 && opts[this.highlightIdx]) {
                this._select(opts[this.highlightIdx].dataset.value);
            }
        } else if (e.key === "Backspace" && !this.inputEl.value && this.selected.length) {
            this._deselect(this.selected[this.selected.length - 1]);
        }
    }

    _updateHighlight(opts) {
        opts.forEach((o, i) => o.classList.toggle("highlighted", i === this.highlightIdx));
        if (opts[this.highlightIdx]) opts[this.highlightIdx].scrollIntoView({ block: "nearest" });
    }

    _getVisible() {
        const q = (this.inputEl.value || "").trim().toLowerCase();
        return this.allItems.filter(item =>
            !this.selected.includes(item) && (!q || item.toLowerCase().includes(q))
        );
    }

    _renderDropdown() {
        const visible = this._getVisible().slice(0, 80);
        if (visible.length === 0) {
            this.dropdownEl.innerHTML = '<div class="ms-empty">No matches</div>';
            return;
        }
        this.dropdownEl.innerHTML = visible.map(item =>
            `<div class="ms-option" data-value="${escapeHtml(item)}">${escapeHtml(item)}</div>`
        ).join("");
        this.dropdownEl.querySelectorAll(".ms-option").forEach(opt => {
            opt.addEventListener("mousedown", (e) => {
                e.preventDefault();
                this._select(opt.dataset.value);
            });
        });
    }

    _select(value) {
        if (!this.selected.includes(value)) this.selected.push(value);
        this.inputEl.value = "";
        this.highlightIdx = -1;
        this._renderPills();
        this._updateToggle();
        this._renderDropdown();
    }

    _deselect(value) {
        this.selected = this.selected.filter(v => v !== value);
        // Auto-reset to OR when fewer than 2 items remain
        if (this.selected.length < 2) this.mode = "or";
        this._renderPills();
        this._updateToggle();
        this._renderDropdown();
    }

    _renderPills() {
        this.pillsEl.innerHTML = this.selected.map(v =>
            `<span class="ms-pill" title="${escapeHtml(v)}">${escapeHtml(v)}<button class="ms-pill-x" data-value="${escapeHtml(v)}">&times;</button></span>`
        ).join("");
        this.pillsEl.querySelectorAll(".ms-pill-x").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                this._deselect(btn.dataset.value);
            });
        });
    }

    _open() {
        this._isOpen = true;
        this.dropdownEl.style.display = "block";
        // Pre-load items from server on first open if allItems is still empty
        if (this.serverSearch && this.allItems.length === 0) {
            this.serverSearch("", (items) => {
                this.allItems = items || [];
                this.highlightIdx = -1;
                this._renderDropdown();
            });
        }
        this._renderDropdown();
    }

    _close() {
        this._isOpen = false;
        this.dropdownEl.style.display = "none";
        this.highlightIdx = -1;
    }

    getValues() { return [...this.selected]; }

    getMode() { return this.mode; }

    clear() {
        this.selected = [];
        this.mode = "or";
        this.inputEl.value = "";
        this._renderPills();
        this._updateToggle();
    }
}

// ─── Multi-Select Instances ──────────────────────────────────────────────
let qidCveMs, qidCategoryMs, qidSupportedModulesMs;
let cidCategoryMs, cidTechnologyMs;
let policyCtrlCatMs, policyTechMs, policyCidMs, policyCtrlNameMs;
let mandatePublisherMs;

// ─── Initialization ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
    initTheme();

    // ── Vault Auth Gate ──
    if (await shouldShowVaultAuth()) {
        return; // Block app init until identity verified
    }

    await initApp();
});

async function shouldShowVaultAuth() {
    if (hasVaultCookie()) return false;
    try {
        const resp = await apiFetch("/api/credentials");
        const creds = await resp.json();
        if (!Array.isArray(creds) || creds.length === 0) return false;
        showVaultAuth(creds);
        return true;
    } catch (e) {
        return false;
    }
}

async function initApp() {
    await loadPlatforms();
    loadSavedSettings();
    await syncVaultFromServer();
    loadSyncStatus();
    initMultiSelects();

    // ── Type-ahead search-as-you-type ──
    ["qidSearchInput", "cidSearchInput", "policySearchInput", "mandateSearchInput"].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        const dataType = id === "qidSearchInput" ? "qids" : id === "cidSearchInput" ? "cids" : id === "policySearchInput" ? "policies" : "mandates";
        const fn = dataType === "qids" ? searchQids : dataType === "cids" ? searchCids : dataType === "policies" ? searchPolicies : searchMandates;
        el.addEventListener("input", createTypeAheadHandler(dataType, fn, id));
    });

    // Clear vault credential when user manually types in credential fields.
    const pwField = document.getElementById("password");
    if (pwField) {
        pwField.addEventListener("focus", function() {
            if (this.getAttribute("data-vault-masked") === "true") {
                this.value = "";
                this.removeAttribute("data-vault-masked");
                activeCredentialId = null;
            }
        });
        pwField.addEventListener("input", function() {
            this.removeAttribute("data-vault-masked");
            activeCredentialId = null;
        });
    }
    const userField = document.getElementById("username");
    if (userField) {
        userField.addEventListener("input", function() {
            activeCredentialId = null;
        });
    }

    // Auto-load dashboard (default active tab)
    loadDashboard();

    // Start session timeout monitor if configured
    initSessionTimeout();
}

// ─── Multi-Select Initialization ─────────────────────────────────────────
function initMultiSelects() {
    // QID filters
    qidCveMs = new MultiSelect("qidCveMs", {
        placeholder: "CVE (e.g. CVE-2022-31629)",
        serverSearch: (q, cb) => {
            apiFetch("/api/qids/filter-values?field=cves&q=" + encodeURIComponent(q))
                .then(r => r.json()).then(cb).catch(() => cb([]));
        }
    });
    qidCategoryMs = new MultiSelect("qidCategoryMs", {
        placeholder: "Category...",
        showModeToggle: false,
    });
    qidSupportedModulesMs = new MultiSelect("qidSupportedModulesMs", {
        placeholder: "Supported Modules...",
        showModeToggle: false,
    });

    // CID filters
    cidCategoryMs = new MultiSelect("cidCategoryMs", {
        placeholder: "Category...",
        showModeToggle: false,
    });
    cidTechnologyMs = new MultiSelect("cidTechnologyMs", {
        placeholder: "Technology...",
        serverSearch: (q, cb) => {
            apiFetch("/api/cids/filter-values?field=technologies&q=" + encodeURIComponent(q))
                .then(r => r.json()).then(cb).catch(() => cb([]));
        }
    });

    // Policy filters
    policyCtrlCatMs = new MultiSelect("policyCtrlCatMs", {
        placeholder: "Control Category...",
    });
    policyTechMs = new MultiSelect("policyTechMs", {
        placeholder: "Technology...",
        serverSearch: (q, cb) => {
            apiFetch("/api/policies/filter-values?field=technologies&q=" + encodeURIComponent(q))
                .then(r => r.json()).then(cb).catch(() => cb([]));
        }
    });
    policyCidMs = new MultiSelect("policyCidMs", {
        placeholder: "CID...",
        serverSearch: (q, cb) => {
            apiFetch("/api/policies/filter-values?field=cids&q=" + encodeURIComponent(q))
                .then(r => r.json()).then(cb).catch(() => cb([]));
        }
    });
    policyCtrlNameMs = new MultiSelect("policyCtrlNameMs", {
        placeholder: "Control Name...",
        showModeToggle: false,
        serverSearch: (q, cb) => {
            apiFetch("/api/policies/filter-values?field=control_names&q=" + encodeURIComponent(q))
                .then(r => r.json()).then(cb).catch(() => cb([]));
        }
    });

    // Mandate filters
    mandatePublisherMs = new MultiSelect("mandatePublisherMs", {
        placeholder: "Publisher...",
        showModeToggle: false,
    });

    // Load preloaded (non-server-search) filter values
    loadFilterOptions();
}

async function loadFilterOptions() {
    try {
        const [qidCats, cidCats, polCats, mandatePublishers, qidModules] = await Promise.all([
            apiFetch("/api/qids/filter-values?field=categories").then(r => r.json()),
            apiFetch("/api/cids/filter-values?field=categories").then(r => r.json()),
            apiFetch("/api/policies/filter-values?field=control_categories").then(r => r.json()),
            apiFetch("/api/mandates/filter-values?field=publishers").then(r => r.json()),
            apiFetch("/api/qids/filter-values?field=supported_modules").then(r => r.json()),
        ]);
        if (qidCategoryMs) qidCategoryMs.setItems(qidCats);
        if (qidSupportedModulesMs) qidSupportedModulesMs.setItems(qidModules);
        if (cidCategoryMs) cidCategoryMs.setItems(cidCats);
        if (policyCtrlCatMs) policyCtrlCatMs.setItems(polCats);
        if (mandatePublisherMs) mandatePublisherMs.setItems(mandatePublishers);
    } catch (e) {
        // Filter values not available until first sync — ignore
    }
}

// ─── Platform Loading ───────────────────────────────────────────────────
async function loadPlatforms() {
    try {
        const resp = await apiFetch("/api/platforms");
        platforms = await resp.json();
        const sel = document.getElementById("platformSelect");
        Object.keys(platforms).forEach(key => {
            const opt = document.createElement("option");
            opt.value = key;
            opt.textContent = key + " \u2014 " + platforms[key].api;
            sel.appendChild(opt);
        });
    } catch (e) {
        console.error("Failed to load platforms:", e);
    }
}

function onPlatformChange() {
    const sel = document.getElementById("platformSelect");
    const plat = platforms[sel.value];
    if (plat) {
        document.getElementById("baseUrl").value = plat.api;
        document.getElementById("gatewayUrl").value = plat.gateway || "";
    }
}

// ─── Tab Switching ──────────────────────────────────────────────────────
function switchTab(tabName) {
    document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
    const content = document.getElementById("tab-" + tabName);
    const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (content) content.classList.add("active");
    if (btn) btn.classList.add("active");

    // Auto-load records on first visit to a tab
    if (tabName === "dashboard" && !_tabLoaded.dashboard) {
        _tabLoaded.dashboard = true;
        loadDashboard();
    } else if (tabName === "qids" && !_tabLoaded.qids && _totalCounts.qids > 0) {
        _tabLoaded.qids = true;
        searchQids();
    } else if (tabName === "cids" && !_tabLoaded.cids && _totalCounts.cids > 0) {
        _tabLoaded.cids = true;
        searchCids();
    } else if (tabName === "policies" && !_tabLoaded.policies && _totalCounts.policies > 0) {
        _tabLoaded.policies = true;
        searchPolicies();
    } else if (tabName === "mandates" && !_tabLoaded.mandates && _totalCounts.mandates > 0) {
        _tabLoaded.mandates = true;
        searchMandates();
    }
}

// ─── Policy Sub-tabs ────────────────────────────────────────────────────
function switchPolicySubTab(subtab) {
    document.querySelectorAll(".policy-subtab").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".sub-tab-btn").forEach(el => el.classList.remove("active"));
    const content = document.getElementById("policy-subtab-" + subtab);
    const btn = document.querySelector(`.sub-tab-btn[data-subtab="${subtab}"]`);
    if (content) content.classList.add("active");
    if (btn) btn.classList.add("active");
    if (subtab === "migration") loadMigrationPolicies();
}

async function loadMigrationPolicies() {
    const container = document.getElementById("migrationPolicyList");
    // Also populate destination credential dropdown
    const destSelect = document.getElementById("migrationDestCred");
    try {
        // Load all credentials for dest selector
        const credResp = await apiFetch("/api/credentials");
        const creds = await credResp.json();
        if (Array.isArray(creds) && creds.length) {
            destSelect.innerHTML = '<option value="">— Select Destination —</option>' +
                creds.map(c => `<option value="${c.id}">${escapeHtml(formatCredLabel(c))}</option>`).join("");
        }
        // Load all policies (no pagination limit)
        const resp = await apiFetch("/api/policies?per_page=10000");
        const data = await resp.json();
        const policies = data.results || [];
        if (policies.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No policies synced yet. Sync policies from the Settings tab first.</p></div>';
            return;
        }
        container.innerHTML = policies.map(p => `
            <div class="migration-policy-row">
                <label class="migration-cb-label">
                    <input type="checkbox" data-policy-id="${p.policy_id}" data-policy-title="${escapeHtml(p.title || "Untitled")}" data-control-count="${p.control_count || 0}">
                    <span class="migration-policy-info">
                        <strong>#${p.policy_id}</strong> ${escapeHtml(p.title || "")}
                        <span class="migration-policy-meta">
                            ${p.status ? `<span class="badge-status badge-status-${(p.status || "").toLowerCase()}">${escapeHtml(p.status)}</span>` : ""}
                            ${p.is_locked ? '<span class="badge-status badge-locked">Locked</span>' : ""}
                            ${p.control_count ? `<span>${p.control_count} controls</span>` : '<span class="badge-status badge-empty-policy" title="No sections/controls — will be skipped during upload">Empty Policy</span>'}
                            ${p.export_date ? '<span class="badge-pill badge-patchable">Exported</span>' : '<span class="badge-pill" style="background:var(--orange-dim);color:var(--orange);">Not Exported</span>'}
                        </span>
                    </span>
                </label>
                <div class="migration-policy-opts">
                    <input type="text" id="migration-title-${p.policy_id}" class="migration-title-input" placeholder="Rename (optional)" value="${escapeHtml(p.title || "")}" data-original-title="${escapeHtml(p.title || "")}" oninput="onMigrationTitleChange(this, ${p.policy_id})">
                    <select id="migration-lock-${p.policy_id}" class="migration-lock-select">
                        <option value="">Lock: Default</option>
                        <option value="locked">Locked</option>
                        <option value="unlocked">Unlocked</option>
                    </select>
                </div>
            </div>
        `).join("");
    } catch (e) {
        container.innerHTML = '<div class="empty-state"><p>Failed to load policies: ' + escapeHtml(e.message) + '</p></div>';
    }
}

// ─── Theme ──────────────────────────────────────────────────────────────
function initTheme() {
    const saved = localStorage.getItem("qkbe_theme");
    if (saved === "light") {
        document.documentElement.setAttribute("data-theme", "light");
        document.getElementById("themeIconDark").style.display = "none";
        document.getElementById("themeIconLight").style.display = "block";
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme");
    if (current === "light") {
        document.documentElement.removeAttribute("data-theme");
        document.getElementById("themeIconDark").style.display = "block";
        document.getElementById("themeIconLight").style.display = "none";
        localStorage.setItem("qkbe_theme", "dark");
    } else {
        document.documentElement.setAttribute("data-theme", "light");
        document.getElementById("themeIconDark").style.display = "none";
        document.getElementById("themeIconLight").style.display = "block";
        localStorage.setItem("qkbe_theme", "light");
    }
    // Redraw dashboard charts with updated theme colors
    if (_tabLoaded.dashboard) {
        _tabLoaded.dashboard = false;
        loadDashboard();
    }
}

// ─── Toast Notifications ────────────────────────────────────────────────
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = "toast " + type;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = "0"; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ─── Loading Overlay ────────────────────────────────────────────────────
function showLoading(text = "Loading...") {
    document.getElementById("loadingText").textContent = text;
    document.getElementById("loadingOverlay").style.display = "flex";
}

function hideLoading() {
    document.getElementById("loadingOverlay").style.display = "none";
}

// ─── Settings Persistence ───────────────────────────────────────────────
function loadSavedSettings() {
    const saved = localStorage.getItem("qkbe_settings");
    if (!saved) return;
    try {
        const s = JSON.parse(saved);
        if (s.baseUrl) document.getElementById("baseUrl").value = s.baseUrl;
        if (s.gatewayUrl) document.getElementById("gatewayUrl").value = s.gatewayUrl;
        if (s.platform) document.getElementById("platformSelect").value = s.platform;
        if (s.apiVersion) { apiVersionPref = s.apiVersion; updateApiVersionToggle(); }
        if (s.activeCredentialId) activeCredentialId = s.activeCredentialId;
        // Session timeout
        if (s.sessionTimeout) {
            const cb = document.getElementById("sessionTimeoutEnabled");
            const slider = document.getElementById("sessionTimeoutSlider");
            const display = document.getElementById("sessionTimeoutDisplay");
            const group = document.getElementById("sessionTimeoutSliderGroup");
            if (cb) cb.checked = !!s.sessionTimeout.enabled;
            if (slider) slider.value = s.sessionTimeout.minutes || 60;
            if (display) display.textContent = formatTimeout(s.sessionTimeout.minutes || 60);
            if (group) group.style.display = s.sessionTimeout.enabled ? "block" : "none";
        }
    } catch (e) { /* ignore corrupt settings */ }
}

function saveSettings() {
    const timeoutCb = document.getElementById("sessionTimeoutEnabled");
    const timeoutSlider = document.getElementById("sessionTimeoutSlider");
    const settings = {
        baseUrl: document.getElementById("baseUrl").value,
        gatewayUrl: document.getElementById("gatewayUrl").value,
        platform: document.getElementById("platformSelect").value,
        apiVersion: apiVersionPref,
        activeCredentialId: activeCredentialId,
        sessionTimeout: {
            enabled: timeoutCb ? timeoutCb.checked : false,
            minutes: timeoutSlider ? parseInt(timeoutSlider.value, 10) : 60,
        },
    };
    localStorage.setItem("qkbe_settings", JSON.stringify(settings));
}

function setApiVersion(version, btn) {
    apiVersionPref = version;
    updateApiVersionToggle();
    saveSettings();
}

function updateApiVersionToggle() {
    document.querySelectorAll(".api-ver-toggle .toggle-btn").forEach(b => {
        b.classList.toggle("active", b.textContent.toLowerCase().includes(apiVersionPref));
    });
}

// ─── Credential Vault (Server-side) ────────────────────────────────────
async function syncVaultFromServer() {
    try {
        const resp = await apiFetch("/api/credentials");
        const creds = await resp.json();
        updateCredentialCount(creds.length);
        if (activeCredentialId) {
            setConnected(true);
        }
    } catch (e) {
        console.error("Failed to sync vault:", e);
    }
}

function updateCredentialCount(count) {
    const el = document.getElementById("credVaultCount");
    el.textContent = count === 0 ? "No saved credentials" : count + " saved credential" + (count > 1 ? "s" : "");
}

/**
 * Format a credential for display in dropdowns.
 * Format: "POD# - Display Name - UserID"  (if display_name set)
 *         "POD# - UserID"                 (if no display_name)
 * The platform field (e.g. "US3", "EU1") is the POD identifier.
 */
function formatCredLabel(cred) {
    const pod = cred.platform || "Unknown";
    const user = cred.username || cred.id;
    const name = cred.display_name || "";
    if (name) return pod + " - " + name + " - " + user;
    return pod + " - " + user;
}

function maskCredId(str) {
    if (!str || str.length <= 4) return str || "";
    return str.slice(0, 2) + "*".repeat(str.length - 4) + str.slice(-2);
}

function formatCredLabelMasked(cred) {
    const pod = cred.platform || "Unknown";
    const user = maskCredId(cred.username || cred.id);
    const name = cred.display_name || "";
    if (name) return pod + " - " + name + " - " + user;
    return pod + " - " + user;
}

async function saveCredential() {
    const username = document.getElementById("username").value.trim();
    const pwField = document.getElementById("password");
    const password = pwField.value;
    const isMasked = pwField.getAttribute("data-vault-masked") === "true";
    const platform = document.getElementById("platformSelect").value;
    const display_name = (document.getElementById("credDisplayName").value || "").trim();

    if (!platform) {
        showToast("Select a Qualys platform first", "error");
        return;
    }

    // If password is masked (loaded from vault), update metadata only — don't overwrite password
    if (isMasked && activeCredentialId) {
        try {
            const resp = await apiFetch("/api/credentials/" + activeCredentialId, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ platform, api_version: apiVersionPref, display_name }),
            });
            const result = await resp.json();
            if (result.error) { showToast(result.error, "error"); return; }
            saveSettings();
            showToast("Settings updated (password unchanged)", "success");
            syncVaultFromServer();
        } catch (e) {
            showToast("Failed to update settings: " + e.message, "error");
        }
        return;
    }

    if (!username || !password) {
        showToast("Username and password required", "error");
        return;
    }
    try {
        const resp = await apiFetch("/api/credentials", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, platform, api_version: apiVersionPref, display_name }),
        });
        const result = await resp.json();
        if (result.error) { showToast(result.error, "error"); return; }
        activeCredentialId = result.id;
        // Mask the password field — server decrypts via credential_id from now on
        pwField.value = VAULT_MASKED;
        pwField.setAttribute("data-vault-masked", "true");
        saveSettings();
        setConnected(true);
        showToast("Credential saved securely", "success");
        syncVaultFromServer();
    } catch (e) {
        showToast("Failed to save credential: " + e.message, "error");
    }
}

async function deleteCredential(credId) {
    try {
        await apiFetch("/api/credentials/" + credId, { method: "DELETE" });
        if (activeCredentialId === credId) {
            activeCredentialId = null;
            setConnected(false);
        }
        showToast("Credential deleted", "info");
        syncVaultFromServer();
    } catch (e) {
        showToast("Failed to delete credential", "error");
    }
}

async function loadCredential(credId) {
    try {
        const resp = await apiFetch("/api/credentials");
        const creds = await resp.json();
        const cred = creds.find(c => c.id === credId);
        if (!cred) return;

        // Fill username + masked password (password resolved server-side via credential_id)
        document.getElementById("username").value = cred.username;
        const pwField = document.getElementById("password");
        pwField.value = VAULT_MASKED;
        pwField.setAttribute("data-vault-masked", "true");

        if (cred.platform) {
            document.getElementById("platformSelect").value = cred.platform;
            onPlatformChange();
        }
        if (cred.api_version) {
            apiVersionPref = cred.api_version;
            updateApiVersionToggle();
        }
        document.getElementById("credDisplayName").value = cred.display_name || "";
        activeCredentialId = credId;
        setConnected(true);
        saveSettings();
        toggleCredentialPicker();
        showToast("Loaded: " + formatCredLabel(cred) + " — ready to use", "info");
    } catch (e) {
        showToast("Failed to load credential", "error");
    }
}

function toggleCredentialPicker() {
    const dropdown = document.getElementById("credPickerDropdown");
    if (dropdown.style.display === "none") {
        populateCredentialPicker();
        dropdown.style.display = "block";
    } else {
        dropdown.style.display = "none";
    }
}

async function populateCredentialPicker() {
    const dropdown = document.getElementById("credPickerDropdown");
    try {
        const resp = await apiFetch("/api/credentials");
        const creds = await resp.json();
        if (creds.length === 0) {
            dropdown.innerHTML = '<div class="cred-empty">No saved credentials</div>';
            return;
        }
        dropdown.innerHTML = creds.map(c => `
            <div class="cred-item" onclick="loadCredential('${c.id}')">
                <div class="cred-item-info">
                    <span class="cred-item-user">${escapeHtml(formatCredLabel(c))}</span>
                    <span class="cred-item-meta">${c.api_version || "v5"}</span>
                </div>
                <div class="cred-item-actions">
                    <button class="cred-item-del" onclick="event.stopPropagation();deleteCredential('${c.id}')" title="Delete">&times;</button>
                </div>
            </div>
        `).join("");
    } catch (e) {
        dropdown.innerHTML = '<div class="cred-empty">Failed to load credentials</div>';
    }
}

function clearCredentials() {
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
    document.getElementById("password").removeAttribute("data-vault-masked");
    document.getElementById("credDisplayName").value = "";
    activeCredentialId = null;
    setConnected(false);
    saveSettings();
    showToast("Credentials cleared", "info");
}

// ─── Vault Auth Gate ────────────────────────────────────────────────────
function showVaultAuth(creds) {
    const select = document.getElementById("vaultAuthSelect");
    select.innerHTML = creds.map(c =>
        `<option value="${c.id}">${escapeHtml(formatCredLabelMasked(c))}</option>`
    ).join("");
    document.getElementById("vaultAuthPassword").value = "";
    document.getElementById("vaultAuthError").style.display = "none";
    document.getElementById("vaultAuthModal").style.display = "flex";
}

async function verifyVaultAuth() {
    const credId = document.getElementById("vaultAuthSelect").value;
    const password = document.getElementById("vaultAuthPassword").value;
    if (!password) {
        document.getElementById("vaultAuthError").textContent = "Password required";
        document.getElementById("vaultAuthError").style.display = "block";
        return;
    }
    try {
        // Include session timeout in verify request so server sets cookie max_age
        const saved = localStorage.getItem("qkbe_settings");
        let maxAge = null;
        if (saved) {
            try {
                const st = JSON.parse(saved);
                if (st.sessionTimeout && st.sessionTimeout.enabled) {
                    maxAge = st.sessionTimeout.minutes * 60;
                }
            } catch (e) { /* ignore */ }
        }
        const resp = await apiFetch("/api/credentials/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: credId, password, max_age: maxAge }),
        });
        const result = await resp.json();
        if (result.verified) {
            // Server set the HttpOnly cookie — mark local auth state
            markVaultAuthenticated();
            document.getElementById("vaultAuthModal").style.display = "none";
            showToast("Identity verified", "success");
            await initApp();
        } else {
            document.getElementById("vaultAuthError").textContent = result.error || "Verification failed";
            document.getElementById("vaultAuthError").style.display = "block";
            document.getElementById("vaultAuthPassword").value = "";
            document.getElementById("vaultAuthPassword").focus();
        }
    } catch (e) {
        document.getElementById("vaultAuthError").textContent = "Verification error";
        document.getElementById("vaultAuthError").style.display = "block";
    }
}

// ─── Connection Indicator ───────────────────────────────────────────────
function setConnected(connected) {
    const indicator = document.getElementById("connIndicator");
    const label = document.getElementById("connLabel");
    const disconnectBtn = document.getElementById("disconnectBtn");
    if (connected) {
        indicator.classList.add("connected");
        label.textContent = "Connected";
        disconnectBtn.style.display = "inline-flex";
    } else {
        indicator.classList.remove("connected");
        label.textContent = "Not Connected";
        disconnectBtn.style.display = "none";
    }
}

function disconnectAll() {
    activeCredentialId = null;
    setConnected(false);
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
    document.getElementById("password").removeAttribute("data-vault-masked");
    document.getElementById("credDisplayName").value = "";
    saveSettings();
    showToast("Disconnected", "info");
}

// ─── API Auth Helper ────────────────────────────────────────────────────
function getApiAuth() {
    const platform = document.getElementById("platformSelect").value;
    return { credential_id: activeCredentialId, platform };
}

// ─── Test Connection ────────────────────────────────────────────────────
async function testConnection() {
    const platform = document.getElementById("platformSelect").value;
    if (!platform) { showToast("Select a Qualys platform first", "error"); return; }

    // Build payload — credential_id after save, raw creds for test-before-save
    const payload = { platform };
    if (activeCredentialId) {
        // Vault credential — server decrypts password via credential_id
        payload.credential_id = activeCredentialId;
    } else {
        // Raw credentials — test before save
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        if (!username) { showToast("Enter a username", "error"); return; }
        if (!password) { showToast("Enter a password", "error"); return; }
        payload.username = username;
        payload.password = password;
    }

    showLoading("Testing connection...");
    try {
        const resp = await apiFetch("/api/test-connection", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        const result = await resp.json();
        if (result.success) {
            setConnected(true);
            showToast(result.message || "Connection successful", "success");
        } else {
            setConnected(false);
            showToast(result.error || "Connection failed", "error");
        }
    } catch (e) {
        showToast("Connection test failed: " + e.message, "error");
    } finally {
        hideLoading();
    }
}

// ─── Sync Status ────────────────────────────────────────────────────────
async function loadSyncStatus() {
    try {
        const resp = await apiFetch("/api/sync/status");
        const status = await resp.json();
        updateSyncDisplay("Qid", status.qids);
        updateSyncDisplay("Cid", status.cids);
        updateSyncDisplay("Policy", status.policies);
        updateMandateSyncDisplay(status.mandates, status.cids);

        // CID dependency warning for Policies
        const cidWarning = document.getElementById("policyCidWarning");
        const techHint = document.getElementById("policyTechHint");
        const cidMissing = !status.cids || !status.cids.last_sync;
        const cidStale = status.cids && status.cids.needs_full_refresh;
        if (cidMissing || cidStale) {
            const msg = cidMissing
                ? "CID data has not been synced. Technology filters and CID cross-references in Policies require a CID sync."
                : "CID data is stale (>30 days). Technology filters may be incomplete. A CID sync is recommended.";
            document.getElementById("policyCidWarningText").textContent = msg;
            if (cidWarning) cidWarning.style.display = "flex";
            if (techHint) techHint.style.display = "";
        } else {
            if (cidWarning) cidWarning.style.display = "none";
            if (techHint) techHint.style.display = "none";
        }

        // Auto-load QIDs tab (default active tab) on initial page load
        if (!_tabLoaded.qids && _totalCounts.qids > 0) {
            _tabLoaded.qids = true;
            searchQids();
        }

        // Fetch and display schedule badges
        try {
            const schedResp = await apiFetch("/api/schedules");
            const schedules = await schedResp.json();
            updateScheduleBadges(schedules);
        } catch (e) { /* schedules endpoint may not exist */ }
    } catch (e) {
        // Sync routes may not exist yet in Phase 1
    }
}

// Map display type → data type key for _totalCounts
const _typeToDataKey = { "Qid": "qids", "Cid": "cids", "Policy": "policies", "Mandate": "mandates" };
// Reverse map: API data type → display key for updateSyncDisplay()
const _dataKeyToDisplay = { "qids": "Qid", "cids": "Cid", "policies": "Policy", "mandates": "Mandate" };

function updateSyncDisplay(type, state) {
    const metaEl = document.getElementById("sync" + type + "Meta");
    const countEl = document.getElementById(type.toLowerCase() + "Count");
    const dataKey = _typeToDataKey[type] || type.toLowerCase() + "s";
    if (!state || !state.last_sync) {
        metaEl.textContent = "Not synced";
        _totalCounts[dataKey] = 0;
        if (countEl) countEl.textContent = "Total: 0";
        return;
    }
    const count = state.record_count || 0;
    _totalCounts[dataKey] = count;
    const date = new Date(state.last_sync).toLocaleString();
    let meta = count.toLocaleString() + " records \u00B7 Last sync: " + date;
    // Add elapsed time in MM:SS
    if (state.elapsed_seconds != null) {
        const totalSec = Math.round(state.elapsed_seconds);
        const min = Math.floor(totalSec / 60);
        const sec = totalSec % 60;
        meta += "  [" + min + ":" + (sec < 10 ? "0" : "") + sec + "]";
    }
    metaEl.textContent = meta;
    if (countEl) countEl.textContent = "Total: " + count.toLocaleString();
}

function updateMandateSyncDisplay(mandateState, cidState) {
    const metaEl = document.getElementById("syncMandateMeta");
    const countEl = document.getElementById("mandateCount");
    const count = (mandateState && mandateState.record_count) || 0;
    _totalCounts.mandates = count;

    if (count > 0 && mandateState.last_sync) {
        const date = new Date(mandateState.last_sync).toLocaleString();
        metaEl.textContent = count.toLocaleString() + " frameworks \u00B7 Updated from CID sync: " + date;
    } else if (cidState && cidState.last_sync && count === 0) {
        metaEl.textContent = "No frameworks found \u00B7 Run a CID Full Sync to extract mandate data";
    } else if (!cidState || !cidState.last_sync) {
        metaEl.textContent = "Extracted from CID sync \u00B7 Run a CID sync first";
    } else {
        metaEl.textContent = "Extracted from CID sync";
    }
    if (countEl) countEl.textContent = "Total: " + count.toLocaleString();
}

function updateCountBadge(prefix, foundCount) {
    // prefix: "qid", "cid", "policy", "mandate"
    const dataKey = prefix === "qid" ? "qids" : prefix === "cid" ? "cids" : prefix === "mandate" ? "mandates" : "policies";
    const total = _totalCounts[dataKey] || 0;
    const el = document.getElementById(prefix + "Count");
    if (!el) return;
    if (foundCount == null) {
        el.textContent = "Total: " + total.toLocaleString();
        return;
    }
    const pct = total > 0 ? (foundCount / total * 100).toFixed(2) : "0.00";
    el.textContent = "Total: " + total.toLocaleString() + " | Found: " + foundCount.toLocaleString() + " | " + pct + "%";
}

// Page timeout limits (seconds) — must match sync.py values
const SYNC_TIMEOUTS = { qids: 600, cids: 300, policies: 300, mandates: 300 };

// ─── Type-Ahead Search ──────────────────────────────────────────────────
function createTypeAheadHandler(dataType, searchFn, inputId) {
    let timer = null;
    const DEBOUNCE_MS = 250;
    const MIN_KEYWORD_LEN = 2;

    return function () {
        clearTimeout(timer);
        const q = document.getElementById(inputId).value.trim();
        const isNumeric = /^\d+$/.test(q);

        // Numeric input → fire from first digit (user typing a known ID)
        // Keyword input → require 2+ chars to avoid overly broad matches
        // Empty → fire immediately (reload all results)
        if (q.length > 0 && !isNumeric && q.length < MIN_KEYWORD_LEN) return;

        timer = setTimeout(() => {
            if (_searchAbort[dataType]) _searchAbort[dataType].abort();
            _searchAbort[dataType] = new AbortController();
            searchFn(_searchAbort[dataType].signal);
        }, DEBOUNCE_MS);
    };
}

async function triggerSync(type, full) {
    if (!activeCredentialId) {
        showToast("Save credentials first in Settings", "error");
        switchTab("settings");
        return;
    }
    // Full sync: show purge confirmation modal (skip if no data to purge)
    if (full) {
        const currentCount = _totalCounts[type] || 0;
        if (currentCount === 0) {
            _executeSyncInternal(type, true);
            return;
        }
        const labels = { qids: "QID (Knowledge Base)", cids: "CID (Controls)", policies: "Policy", mandates: "Mandate" };
        document.getElementById("purgeDataTypeLabel").textContent = labels[type] || type;
        document.getElementById("purgeSyncContinueBtn").onclick = () => {
            closePurgeSyncModal();
            _executeSyncInternal(type, true);
        };
        openModal("purgeSyncModal");
        return;
    }
    _executeSyncInternal(type, false);
}

function closePurgeSyncModal() {
    closeModal("purgeSyncModal");
}

async function _executeSyncInternal(type, full) {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a Qualys platform first", "error"); return; }

    const label = full ? "Full sync" : "Delta sync";

    // Full sync purges all data — clear the status card and browse tab
    // immediately so the user doesn't see stale data while re-downloading.
    if (full) {
        const displayKey = _dataKeyToDisplay[type];
        if (displayKey) updateSyncDisplay(displayKey, null);
        const containerMap = {qids: "qidResults", cids: "cidResults", policies: "policyResults"};
        const badgeKeyMap = {qids: "qid", cids: "cid", policies: "policy"};
        const cid = containerMap[type];
        if (cid) {
            const el = document.getElementById(cid);
            if (el) el.innerHTML = '<div class="empty-state"><p>Full sync in progress\u2026</p></div>';
            updateCountBadge(badgeKeyMap[type], 0);
        }
    }

    // Show progress bar with countdown
    const typeKey = type.charAt(0).toUpperCase() + type.slice(1);
    const progressEl = document.getElementById("syncProgress" + typeKey);
    const textEl = document.getElementById("syncText" + typeKey);
    const fillEl = document.getElementById("syncFill" + typeKey);
    if (progressEl) {
        progressEl.style.display = "flex";
        fillEl.style.width = "0%";
        fillEl.className = "sync-progress-fill indeterminate";
    }

    // Start countdown timer immediately
    const timeoutSec = SYNC_TIMEOUTS[type] || 300;
    const countdownStart = Date.now();
    const countdownInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - countdownStart) / 1000);
        const remaining = Math.max(0, timeoutSec - elapsed);
        const min = Math.floor(remaining / 60);
        const sec = remaining % 60;
        const timeStr = min + ":" + (sec < 10 ? "0" : "") + sec;
        // Only update if we haven't received data yet (countdown shows while waiting)
        if (fillEl.classList.contains("indeterminate")) {
            textEl.textContent = "Waiting for Qualys API response... " + timeStr + " remaining";
        }
    }, 1000);
    // Store interval so pollSyncProgress can clear it
    progressEl.dataset.countdownId = countdownInterval;

    try {
        const resp = await apiFetch("/api/sync/" + type, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...auth, full }),
        });
        const result = await resp.json();
        if (result.error) {
            clearInterval(countdownInterval);
            showToast(result.error, "error");
            textEl.textContent = "Error: " + result.error;
            fillEl.className = "sync-progress-fill error";
            fillEl.style.width = "100%";
        } else if (result.started) {
            showToast(type.toUpperCase() + " " + label.toLowerCase() + " started", "info");
            pollSyncProgress(type);
        }
    } catch (e) {
        clearInterval(countdownInterval);
        showToast("Sync failed: " + e.message, "error");
        textEl.textContent = "Error: " + e.message;
        fillEl.className = "sync-progress-fill error";
        fillEl.style.width = "100%";
    }
}

async function pollSyncProgress(type) {
    const typeKey = type.charAt(0).toUpperCase() + type.slice(1);
    const progressEl = document.getElementById("syncProgress" + typeKey);
    const textEl = document.getElementById("syncText" + typeKey);
    const fillEl = document.getElementById("syncFill" + typeKey);
    const countdownId = parseInt(progressEl.dataset.countdownId || "0");

    const poll = async () => {
        try {
            const resp = await apiFetch("/api/sync/" + type + "/progress");
            const p = await resp.json();
            if (p.running) {
                // Live progress update — data is flowing
                if (p.items_synced !== undefined && p.items_synced > 0) {
                    // Data arrived — stop countdown, show live counter
                    if (countdownId) { clearInterval(countdownId); progressEl.dataset.countdownId = "0"; }
                    const count = p.items_synced.toLocaleString();
                    const pages = p.pages_fetched || 0;
                    if (p.status === "processing" && p.processing_item !== undefined) {
                        // Per-control processing phase
                        const procItem = p.processing_item.toLocaleString();
                        const procTotal = (p.processing_total || 0).toLocaleString();
                        textEl.textContent = count + " synced — processing " + procItem + "/" + procTotal + " on page " + pages;
                    } else {
                        textEl.textContent = count + " records synced (page " + pages + ") — waiting for API...";
                    }
                    fillEl.classList.remove("indeterminate");
                    const est = type === "qids" ? 100000 : type === "cids" ? 30000 : type === "mandates" ? 500 : 500;
                    const pct = Math.min(95, (p.items_synced / est) * 100);
                    fillEl.style.width = pct + "%";
                } else if (p.status === "started") {
                    // First request in-flight, no data yet
                    if (!countdownId) textEl.textContent = "Requesting data from Qualys API...";
                }
                // If items_synced is 0 or undefined, countdown timer handles the text
                setTimeout(poll, 2000);
            } else {
                // Sync complete — stop countdown
                if (countdownId) clearInterval(countdownId);
                fillEl.className = "sync-progress-fill";
                fillEl.style.width = "100%";
                if (p.error) {
                    textEl.textContent = "Error: " + p.error;
                    fillEl.classList.add("error");
                    showToast(type.toUpperCase() + " sync error: " + p.error, "error");
                } else if (p.errors && p.errors.length > 0) {
                    textEl.textContent = "Error: " + p.errors[0];
                    fillEl.classList.add("error");
                    showToast(type.toUpperCase() + " sync error — check Last Sync Details", "error");
                } else {
                    const count = (p.items_synced || 0).toLocaleString();
                    const pages = p.pages_fetched || 0;
                    textEl.textContent = "Done — " + count + " records synced (" + pages + " pages)";
                    fillEl.classList.add("complete");
                    showToast(type.toUpperCase() + " sync complete: " + count + " records", "success");
                }
                loadSyncStatus();
                loadFilterOptions(); // Refresh multi-select dropdown options
                // Reset tab loaded flag so auto-search re-fires with fresh data
                _tabLoaded[type] = false;
                // Auto-refresh if the synced type's tab is currently active
                const activeTab = document.querySelector(".tab-btn.active");
                const activeTabName = activeTab ? activeTab.dataset.tab : null;
                if (activeTabName === type) {
                    _tabLoaded[type] = true;
                    if (type === "qids") searchQids();
                    else if (type === "cids") searchCids();
                    else if (type === "policies") searchPolicies();
                    else if (type === "mandates") searchMandates();
                }
                // Keep progress bar visible — don't auto-hide
            }
        } catch (e) {
            // Keep polling — don't hide the bar on transient network errors
            setTimeout(poll, 3000);
        }
    };
    setTimeout(poll, 1500);
}

// ─── Sync Details Modal ─────────────────────────────────────────────────
// ── Sync history state ──
let _syncHistoryType = null;
let _syncHistoryCache = null;
let _syncHistoryExpanded = false;

async function showSyncDetails(type) {
    const labels = { qids: "QIDs (Knowledge Base)", cids: "CIDs (Controls)", policies: "Policies", mandates: "Mandates" };
    const titleEl = document.getElementById("syncDetailsTitle");
    const contentEl = document.getElementById("syncDetailsContent");
    const modal = document.getElementById("syncDetailsModal");

    titleEl.textContent = "Sync Log — " + (labels[type] || type);
    contentEl.textContent = "Loading...";

    // Reset history state on each open
    _syncHistoryType = type;
    _syncHistoryCache = null;
    _syncHistoryExpanded = false;
    document.getElementById("syncHistoryContainer").style.display = "none";
    document.getElementById("syncHistoryToggleBtn").textContent = "Show History";

    openModal("syncDetailsModal");

    try {
        const resp = await apiFetch("/api/sync/" + type + "/log");
        const data = await resp.json();

        if (data.error) {
            contentEl.textContent = data.error;
            return;
        }

        // Server returns pre-rendered text log
        contentEl.textContent = data.text || "No log data available.";
    } catch (e) {
        contentEl.textContent = "Failed to load sync log: " + e.message;
    }
}

async function toggleSyncHistory() {
    const container = document.getElementById("syncHistoryContainer");
    const btn = document.getElementById("syncHistoryToggleBtn");

    if (_syncHistoryExpanded) {
        container.style.display = "none";
        btn.textContent = "Show History";
        _syncHistoryExpanded = false;
        return;
    }

    _syncHistoryExpanded = true;
    btn.textContent = "Hide History";
    container.style.display = "block";

    // Fetch history on first expand (cache for subsequent toggles)
    if (!_syncHistoryCache) {
        const historyContent = document.getElementById("syncHistoryContent");
        historyContent.innerHTML = '<div style="padding:12px;color:var(--text-2);">Loading history...</div>';

        try {
            const resp = await apiFetch("/api/sync/" + _syncHistoryType + "/history");
            const runs = await resp.json();
            _syncHistoryCache = runs;

            if (runs.length <= 1) {
                historyContent.innerHTML = '<div style="padding:12px;color:var(--text-2);">No previous runs found.</div>';
                return;
            }

            // Skip the first run (already displayed above)
            const previous = runs.slice(1);
            historyContent.innerHTML = previous.map((run, i) => {
                const num = previous.length - i;
                const mode = (run.mode || "?").charAt(0).toUpperCase() + (run.mode || "?").slice(1);
                const status = (run.status || "?").charAt(0).toUpperCase() + (run.status || "?").slice(1);
                const started = run.started_at ? new Date(run.started_at).toLocaleString() : "?";
                const label = "Run #" + num + " \u2014 " + mode + " \u2014 " + status + " \u2014 " + started;
                return '<div style="margin-bottom:16px;">' +
                    '<div style="font-size:12px;font-weight:600;color:var(--text-2);margin-bottom:4px;">' + escapeHtml(label) + '</div>' +
                    '<pre class="sync-details-pre" style="max-height:200px;overflow-y:auto;">' + escapeHtml(run.text || "No data") + '</pre>' +
                    '</div>';
            }).join("");
        } catch (e) {
            historyContent.innerHTML = '<div style="padding:12px;color:var(--red);">Failed to load history: ' + escapeHtml(e.message) + '</div>';
        }
    }
}

function copySyncDetails() {
    let content = document.getElementById("syncDetailsContent").textContent;
    // Include history text when the history section is visible
    if (_syncHistoryExpanded) {
        const historyEl = document.getElementById("syncHistoryContent");
        if (historyEl && historyEl.textContent.trim()) {
            content += "\n\n" + "=".repeat(64) + "\n  SYNC HISTORY\n" + "=".repeat(64) + "\n\n" + historyEl.textContent;
        }
    }
    navigator.clipboard.writeText(content).then(() => {
        showToast("Copied to clipboard", "success");
    }).catch(() => {
        // Fallback for older browsers
        const ta = document.createElement("textarea");
        ta.value = content;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        showToast("Copied to clipboard", "success");
    });
}

// ─── Advanced Filters: QIDs ──────────────────────────────────────────────
function toggleAdvancedQidFilters() {
    const panel = document.getElementById("qidAdvancedFilters");
    const toggle = panel.previousElementSibling;
    const isHidden = panel.style.display === "none";
    panel.style.display = isHidden ? "" : "none";
    toggle.classList.toggle("expanded", isHidden);
}

function _updateAdvFilterBadge() {
    let count = 0;
    if (document.getElementById("qidVulnTypeFilter").value) count++;
    if (document.getElementById("qidPciFilter").value) count++;
    if (document.getElementById("qidDiscoveryFilter").value) count++;
    if (document.getElementById("qidCvssBaseMin").value) count++;
    if (document.getElementById("qidCvss3BaseMin").value) count++;
    if (document.getElementById("qidPublishedAfter").value) count++;
    if (document.getElementById("qidModifiedAfter").value) count++;
    document.querySelectorAll("#qidAdvancedFilters .rti-checkboxes input:checked").forEach(() => count++);
    if (qidSupportedModulesMs && qidSupportedModulesMs.getValues().length) count++;
    const badge = document.getElementById("qidAdvFilterCount");
    if (count > 0) {
        badge.textContent = count + " active";
        badge.style.display = "";
    } else {
        badge.style.display = "none";
    }
}

// ─── Search: QIDs ───────────────────────────────────────────────────────
function _qidSearchParams(page) {
    const params = new URLSearchParams();
    const q = document.getElementById("qidSearchInput").value;
    if (q) params.set("q", q);
    const cves = qidCveMs ? qidCveMs.getValues() : [];
    if (cves.length) {
        params.set("cve", cves.join(","));
        if (qidCveMs.getMode() === "and") params.set("cve_mode", "and");
    }
    const severity = document.getElementById("qidSeverityFilter").value;
    if (severity) params.set("severity", severity);
    const patchable = document.getElementById("qidPatchableFilter").value;
    if (patchable) params.set("patchable", patchable);
    const categories = qidCategoryMs ? qidCategoryMs.getValues() : [];
    if (categories.length) params.set("category", categories.join(","));
    // Advanced filters
    const vulnType = document.getElementById("qidVulnTypeFilter").value;
    if (vulnType) params.set("vuln_type", vulnType);
    const pci = document.getElementById("qidPciFilter").value;
    if (pci) params.set("pci_flag", pci);
    const disc = document.getElementById("qidDiscoveryFilter").value;
    if (disc) params.set("discovery_method", disc);
    const cvssBase = document.getElementById("qidCvssBaseMin").value;
    if (cvssBase) params.set("cvss_base_min", cvssBase);
    const cvss3Base = document.getElementById("qidCvss3BaseMin").value;
    if (cvss3Base) params.set("cvss3_base_min", cvss3Base);
    const pubAfter = document.getElementById("qidPublishedAfter").value;
    if (pubAfter) params.set("published_after", pubAfter);
    const modAfter = document.getElementById("qidModifiedAfter").value;
    if (modAfter) params.set("modified_after", modAfter);
    // RTI checkboxes
    const rti = ["qidRtiExploit","qidRtiMalware","qidRtiActiveAttack","qidRtiRansomware","qidRtiCisaKev"]
        .filter(id => document.getElementById(id).checked)
        .map(id => document.getElementById(id).value);
    if (rti.length) params.set("rti", rti.join(","));
    // Supported modules
    const supportedMods = qidSupportedModulesMs ? qidSupportedModulesMs.getValues() : [];
    if (supportedMods.length) params.set("supported_modules", supportedMods.join(","));
    _updateAdvFilterBadge();
    if (page) params.set("page", page);
    return params;
}

async function searchQids(signal) {
    try {
        const opts = signal ? { signal } : {};
        const resp = await apiFetch("/api/qids?" + _qidSearchParams().toString(), opts);
        const data = await resp.json();
        if (data.error) { showToast(data.error, "error"); return; }
        renderQidResults(data);
        _saveRecentSearch("qids", document.getElementById("qidSearchInput").value.trim(), data.total || 0);
    } catch (e) {
        if (e.name === "AbortError") return;
        showToast("Search failed: " + e.message, "error");
    }
}

function renderQidResults(data) {
    const container = document.getElementById("qidResults");
    const items = data.results || [];
    updateCountBadge("qid", data.total || 0);
    _showExportButtons("qid", data.total || 0);
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No QIDs found matching your search.</p></div>';
        document.getElementById("qidPagination").style.display = "none";
        return;
    }
    container.innerHTML = items.map(v => `
        <div class="qid-card" onclick="showQidDetail(${v.qid})">
            ${_starHtml("qid", v.qid, v.title)}
            <div class="qid-card-severity severity-${v.severity_level || 1}">${v.severity_level || "?"}</div>
            <div class="qid-card-body">
                <div class="qid-card-title">
                    <span class="qid-num">QID ${v.qid}</span>${escapeHtml(v.title || "")}
                </div>
                <div class="qid-card-meta">
                    <span>${escapeHtml(v.category || "")}</span>
                    ${v.published_datetime ? `<span>Published: ${new Date(v.published_datetime).toLocaleDateString()}</span>` : ""}
                    ${v.last_service_modification_datetime ? `<span>Modified: ${new Date(v.last_service_modification_datetime).toLocaleDateString()}</span>` : ""}
                </div>
                <div class="qid-card-badges">
                    ${v.cve_count ? `<span class="badge-pill badge-cve">${v.cve_count} CVE${v.cve_count > 1 ? "s" : ""}</span>` : ""}
                    ${v.patchable ? '<span class="badge-pill badge-patchable">Patchable</span>' : '<span class="badge-pill badge-not-patchable">Not Patchable</span>'}
                    ${v.supported_modules ? v.supported_modules.split(', ').map(m => `<span class="badge-pill badge-module" title="${escapeHtml(m)}">${escapeHtml(m)}</span>`).join('') : ""}
                </div>
            </div>
        </div>
    `).join("");
    renderPagination("qid", data);
}

async function showQidDetail(qid) {
    try {
        const resp = await apiFetch("/api/qids/" + qid);
        const v = await resp.json();
        if (v.error) { showToast(v.error, "error"); return; }

        document.getElementById("qidDetailTitle").textContent = "QID " + v.qid + " — " + (v.title || "");
        const content = document.getElementById("qidDetailContent");
        content.innerHTML = `
            <div class="detail-meta-grid">
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Severity</span>
                    <span class="detail-meta-value">${v.severity_level || "?"} / 5</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Category</span>
                    <span class="detail-meta-value">${escapeHtml(v.category || "N/A")}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Type</span>
                    <span class="detail-meta-value">${escapeHtml(v.vuln_type || "N/A")}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Patchable</span>
                    <span class="detail-meta-value">${v.patchable ? "Yes" : "No"}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Published</span>
                    <span class="detail-meta-value">${v.published_datetime ? new Date(v.published_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Last Modified</span>
                    <span class="detail-meta-value">${v.last_service_modification_datetime ? new Date(v.last_service_modification_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                ${v.cvss3_base ? `<div class="detail-meta-item"><span class="detail-meta-label">CVSS v3</span><span class="detail-meta-value">${v.cvss3_base}</span></div>` : ""}
                ${v.cvss_base ? `<div class="detail-meta-item"><span class="detail-meta-label">CVSS v2</span><span class="detail-meta-value">${v.cvss_base}</span></div>` : ""}
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Supported Modules</span>
                    <span class="detail-meta-value">${(v.supported_modules && v.supported_modules.length) ? v.supported_modules.map(m => escapeHtml(m)).join(', ') : 'N/A'}</span>
                </div>
            </div>
            ${v.diagnosis ? `<div class="detail-section"><h4>Diagnosis</h4><div class="detail-content">${v.diagnosis}</div></div>` : ""}
            ${v.consequence ? `<div class="detail-section"><h4>Consequence</h4><div class="detail-content">${v.consequence}</div></div>` : ""}
            ${v.solution ? `<div class="detail-section"><h4>Solution</h4><div class="detail-content">${v.solution}</div></div>` : ""}
            ${renderRefList("CVEs", v.cves)}
            ${renderRefList("Bugtraq References", v.bugtraqs)}
            ${renderRefList("Vendor References", v.vendor_refs)}
        `;
        openModal("qidDetailModal");
    } catch (e) {
        showToast("Failed to load QID detail", "error");
    }
}

// ─── Search: CIDs ───────────────────────────────────────────────────────
function _cidSearchParams(page) {
    const params = new URLSearchParams();
    const q = document.getElementById("cidSearchInput").value;
    if (q) params.set("q", q);
    const categories = cidCategoryMs ? cidCategoryMs.getValues() : [];
    if (categories.length) params.set("category", categories.join(","));
    const criticality = document.getElementById("cidCriticalityFilter").value;
    if (criticality) params.set("criticality", criticality);
    const technologies = cidTechnologyMs ? cidTechnologyMs.getValues() : [];
    if (technologies.length) {
        params.set("technology", technologies.join(","));
        if (cidTechnologyMs.getMode() === "and") params.set("technology_mode", "and");
    }
    if (page) params.set("page", page);
    return params;
}

async function searchCids(signal) {
    try {
        const opts = signal ? { signal } : {};
        const resp = await apiFetch("/api/cids?" + _cidSearchParams().toString(), opts);
        const data = await resp.json();
        if (data.error) { showToast(data.error, "error"); return; }
        renderCidResults(data);
        _saveRecentSearch("cids", document.getElementById("cidSearchInput").value.trim(), data.total || 0);
    } catch (e) {
        if (e.name === "AbortError") return;
        showToast("Search failed: " + e.message, "error");
    }
}

function renderCidResults(data) {
    const container = document.getElementById("cidResults");
    const items = data.results || [];
    updateCountBadge("cid", data.total || 0);
    _showExportButtons("cid", data.total || 0);
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No CIDs found matching your search.</p></div>';
        document.getElementById("cidPagination").style.display = "none";
        return;
    }
    container.innerHTML = items.map(c => `
        <div class="cid-card" onclick="showCidDetail(${c.cid})">
            ${_starHtml("cid", c.cid, c.category)}
            <div class="cid-card-criticality criticality-${(c.criticality_label || "minimal").toLowerCase()}">${escapeHtml(decodeHtmlEntities(c.criticality_label || "?"))}</div>
            <div class="cid-card-body">
                <div class="cid-card-title">
                    <span class="cid-num">CID ${c.cid}</span>${escapeHtml(decodeHtmlEntities(c.category || ""))}
                </div>
                <div class="cid-card-statement">${escapeHtml(decodeHtmlEntities(c.statement || ""))}</div>
                <div class="cid-card-meta">
                    <span>${escapeHtml(decodeHtmlEntities(c.check_type || ""))}</span>
                    ${c.created_date ? `<span>Created: ${new Date(c.created_date).toLocaleDateString()}</span>` : ""}
                    ${c.update_date ? `<span>Modified: ${new Date(c.update_date).toLocaleDateString()}</span>` : ""}
                    ${c.policy_count ? `<span>${c.policy_count} linked policies</span>` : ""}
                </div>
            </div>
        </div>
    `).join("");
    renderPagination("cid", data);
}

async function showCidDetail(cid, policyTechs) {
    try {
        const resp = await apiFetch("/api/cids/" + cid);
        const c = await resp.json();
        if (c.error) { showToast(c.error, "error"); return; }

        // If called from a policy context, filter technologies to only policy-relevant ones
        let displayTechs = c.technologies || [];
        let techFilterNote = "";
        if (policyTechs && policyTechs.length && displayTechs.length) {
            const policyTechNames = new Set(policyTechs.map(t => t.tech_name));
            const filtered = displayTechs.filter(t => policyTechNames.has(t.tech_name));
            if (filtered.length < displayTechs.length) {
                techFilterNote = `<span style="font-size:10px;font-weight:400;color:var(--text-2);text-transform:none;letter-spacing:0;margin-left:6px;">Showing ${filtered.length} of ${displayTechs.length} (filtered to policy)</span>`;
                displayTechs = filtered;
            }
        }

        document.getElementById("cidDetailTitle").textContent = "CID " + c.cid;
        const content = document.getElementById("cidDetailContent");
        content.innerHTML = `
            <div class="detail-meta-grid">
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Criticality</span>
                    <span class="detail-meta-value">${escapeHtml(decodeHtmlEntities(c.criticality_label || "N/A"))} (${c.criticality_value || "?"})</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Category</span>
                    <span class="detail-meta-value">${escapeHtml(decodeHtmlEntities(c.category || "N/A"))}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Check Type</span>
                    <span class="detail-meta-value">${escapeHtml(decodeHtmlEntities(c.check_type || "N/A"))}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Updated</span>
                    <span class="detail-meta-value">${c.update_date ? new Date(c.update_date).toLocaleDateString() : "N/A"}</span>
                </div>
            </div>
            <div class="detail-section">
                <h4>Statement</h4>
                <div class="detail-content">${escapeHtml(decodeHtmlEntities(c.statement || "N/A"))}</div>
            </div>
            ${displayTechs.length ? `
                <div class="detail-section">
                    <h4>Technologies (${displayTechs.length})${techFilterNote}</h4>
                    <div class="detail-content">
                        ${displayTechs.map(t => `<div style="margin-bottom:8px;"><strong>${escapeHtml(decodeHtmlEntities(t.tech_name || ""))}</strong>${t.rationale ? " — " + escapeHtml(decodeHtmlEntities(t.rationale)) : ""}</div>`).join("")}
                    </div>
                </div>
            ` : ""}
            ${c.linked_policies && c.linked_policies.length ? `
                <div class="detail-section">
                    <h4>Linked Policies</h4>
                    <ul class="detail-ref-list">
                        ${c.linked_policies.map(p => `<li><a href="#" onclick="event.preventDefault();showPolicyDetail(${p.policy_id})">Policy ${p.policy_id}: ${escapeHtml(p.title || "")}</a></li>`).join("")}
                    </ul>
                </div>
            ` : ""}
            ${c.linked_mandates && c.linked_mandates.length ? `<div class="detail-section"><h4>Linked Mandates</h4><ul class="detail-ref-list">${c.linked_mandates.map(m => `<li><a href="#" onclick="event.preventDefault();showMandateDetail(${m.mandate_id})">${escapeHtml(m.title || "Mandate " + m.mandate_id)}${m.version ? " v" + escapeHtml(m.version) : ""}</a>${m.section_id ? ` <span style="color:var(--text-2);font-size:11px;">(${escapeHtml(m.section_id)})</span>` : ""}</li>`).join("")}</ul></div>` : ""}
        `;
        openModal("cidDetailModal");
    } catch (e) {
        showToast("Failed to load CID detail", "error");
    }
}

// ─── Search: Policies ───────────────────────────────────────────────────
function _policySearchParams(page) {
    const params = new URLSearchParams();
    const q = document.getElementById("policySearchInput").value;
    if (q) params.set("q", q);
    const status = document.getElementById("policyStatusFilter").value;
    if (status) params.set("status", status);
    const ctrlCats = policyCtrlCatMs ? policyCtrlCatMs.getValues() : [];
    if (ctrlCats.length) {
        params.set("control_category", ctrlCats.join(","));
        if (policyCtrlCatMs.getMode() === "and") params.set("control_category_mode", "and");
    }
    const techs = policyTechMs ? policyTechMs.getValues() : [];
    if (techs.length) {
        params.set("technology", techs.join(","));
        if (policyTechMs.getMode() === "and") params.set("technology_mode", "and");
    }
    const cids = policyCidMs ? policyCidMs.getValues() : [];
    if (cids.length) {
        params.set("cid", cids.join(","));
        if (policyCidMs.getMode() === "and") params.set("cid_mode", "and");
    }
    const ctrlNames = policyCtrlNameMs ? policyCtrlNameMs.getValues() : [];
    if (ctrlNames.length) params.set("control_name", ctrlNames[0]); // text search, use first value
    if (page) params.set("page", page);
    return params;
}

async function searchPolicies(signal) {
    try {
        const opts = signal ? { signal } : {};
        const resp = await apiFetch("/api/policies?" + _policySearchParams().toString(), opts);
        const data = await resp.json();
        if (data.error) { showToast(data.error, "error"); return; }
        renderPolicyResults(data);
        _saveRecentSearch("policies", document.getElementById("policySearchInput").value.trim(), data.total || 0);
    } catch (e) {
        if (e.name === "AbortError") return;
        showToast("Search failed: " + e.message, "error");
    }
}

function searchPoliciesById(id) {
    document.getElementById("policySearchInput").value = id;
    searchPolicies();
}

// ─── Clear Filters ──────────────────────────────────────────────────────
function clearQidFilters() {
    document.getElementById("qidSearchInput").value = "";
    document.getElementById("qidSeverityFilter").value = "";
    document.getElementById("qidPatchableFilter").value = "";
    if (qidCveMs) qidCveMs.clear();
    if (qidCategoryMs) qidCategoryMs.clear();
    // Advanced filters
    document.getElementById("qidVulnTypeFilter").value = "";
    document.getElementById("qidPciFilter").value = "";
    document.getElementById("qidDiscoveryFilter").value = "";
    document.getElementById("qidCvssBaseMin").value = "";
    document.getElementById("qidCvss3BaseMin").value = "";
    document.getElementById("qidPublishedAfter").value = "";
    document.getElementById("qidModifiedAfter").value = "";
    document.querySelectorAll("#qidAdvancedFilters .rti-checkboxes input[type='checkbox']")
        .forEach(cb => cb.checked = false);
    if (qidSupportedModulesMs) qidSupportedModulesMs.clear();
    _updateAdvFilterBadge();
    searchQids();
}

function clearCidFilters() {
    document.getElementById("cidSearchInput").value = "";
    document.getElementById("cidCriticalityFilter").value = "";
    if (cidCategoryMs) cidCategoryMs.clear();
    if (cidTechnologyMs) cidTechnologyMs.clear();
    searchCids();
}

function clearPolicyFilters() {
    document.getElementById("policySearchInput").value = "";
    document.getElementById("policyStatusFilter").value = "";
    if (policyCtrlCatMs) policyCtrlCatMs.clear();
    if (policyTechMs) policyTechMs.clear();
    if (policyCidMs) policyCidMs.clear();
    if (policyCtrlNameMs) policyCtrlNameMs.clear();
    searchPolicies();
}

// ─── Search: Mandates ────────────────────────────────────────────────────
function _mandateSearchParams(page) {
    const params = new URLSearchParams();
    const q = document.getElementById("mandateSearchInput").value;
    if (q) params.set("q", q);
    const publishers = mandatePublisherMs ? mandatePublisherMs.getValues() : [];
    if (publishers.length) params.set("publisher", publishers.join(","));
    if (page) params.set("page", page);
    return params;
}

async function searchMandates(signal) {
    try {
        const opts = signal ? { signal } : {};
        const resp = await apiFetch("/api/mandates?" + _mandateSearchParams().toString(), opts);
        const data = await resp.json();
        if (data.error) { showToast(data.error, "error"); return; }
        renderMandateResults(data);
        _saveRecentSearch("mandates", document.getElementById("mandateSearchInput").value.trim(), data.total || 0);
    } catch (e) {
        if (e.name === "AbortError") return;
        showToast("Search failed: " + e.message, "error");
    }
}

function clearMandateFilters() {
    document.getElementById("mandateSearchInput").value = "";
    if (mandatePublisherMs) mandatePublisherMs.clear();
    searchMandates();
}

function renderMandateResults(data) {
    const container = document.getElementById("mandateResults");
    const items = data.results || [];
    updateCountBadge("mandate", data.total || 0);
    _showExportButtons("mandate", data.total || 0);
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No mandates found matching your search.</p></div>';
        document.getElementById("mandatePagination").style.display = "none";
        return;
    }
    container.innerHTML = items.map(m => {
        const desc = m.description ? escapeHtml(m.description.length > 120 ? m.description.substring(0, 120) + "…" : m.description) : "";
        return `
        <div class="mandate-card" onclick="showMandateDetail(${m.mandate_id})">
            <div class="mandate-card-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div class="mandate-card-body">
                <div class="mandate-card-title">
                    <span class="mandate-id">#${m.mandate_id}</span>${escapeHtml(m.title || "")}
                </div>
                ${desc ? `<div class="mandate-card-desc">${desc}</div>` : ""}
                <div class="mandate-card-meta">
                    ${m.version ? `<span class="badge-pill badge-cve">v${escapeHtml(m.version)}</span>` : ""}
                    ${m.publisher ? `<span>${escapeHtml(m.publisher)}</span>` : ""}
                    ${m.released_date ? `<span>Released: ${m.released_date}</span>` : ""}
                    ${m.last_modified_date ? `<span>Modified: ${m.last_modified_date}</span>` : ""}
                    ${m.control_count ? `<span>${m.control_count} controls</span>` : ""}
                </div>
            </div>
        </div>`;
    }).join("");
    renderPagination("mandate", data);
}

async function showMandateDetail(id) {
    try {
        const resp = await apiFetch("/api/mandates/" + id);
        const m = await resp.json();
        if (m.error) { showToast(m.error, "error"); return; }
        document.getElementById("mandateDetailTitle").textContent =
            "Mandate " + m.mandate_id + " — " + (m.title || "");
        const content = document.getElementById("mandateDetailContent");
        const _metaMissing = !m.version && !m.publisher && !m.released_date && !m.last_modified_date;
        let html = `<div class="detail-meta-grid">
            <div class="detail-meta-item"><span class="detail-meta-label">Title</span><span class="detail-meta-value">${escapeHtml(m.title || "N/A")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Version</span><span class="detail-meta-value">${escapeHtml(m.version || "N/A")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Publisher</span><span class="detail-meta-value">${escapeHtml(m.publisher || "N/A")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Released</span><span class="detail-meta-value">${m.released_date || "N/A"}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Last Modified</span><span class="detail-meta-value">${m.last_modified_date || "N/A"}</span></div>
        </div>`;
        if (_metaMissing) {
            html += `<div style="background:var(--bg-2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin:12px 0;font-size:12px;color:var(--text-2);display:flex;align-items:center;gap:8px;">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                <span>Mandate metadata (version, publisher, dates) may not be available from the Qualys PC API for all mandates.</span>
            </div>`;
        }
        if (m.description) html += `<div class="detail-section"><h4>Description</h4><div class="detail-content">${escapeHtml(m.description)}</div></div>`;
        if (m.controls && m.controls.length) {
            // Sort controls — default by criticality (highest first)
            let sortedControls = [...m.controls];
            const _sortMandateControls = (arr, sortBy) => {
                if (sortBy === "criticality") arr.sort((a, b) => (b.criticality_value || 0) - (a.criticality_value || 0));
                else if (sortBy === "category") arr.sort((a, b) => (a.category || "").localeCompare(b.category || ""));
                else if (sortBy === "section") arr.sort((a, b) => (a.section_id || "").localeCompare(b.section_id || ""));
                else if (sortBy === "cid") arr.sort((a, b) => a.cid - b.cid);
                return arr;
            };
            _sortMandateControls(sortedControls, "criticality");

            html += `<div class="detail-section"><h4>Associated Controls (${m.controls.length})</h4>
                <div style="margin-bottom:10px;display:flex;align-items:center;gap:8px;">
                    <label style="font-size:12px;text-transform:none;letter-spacing:0;">Sort by:</label>
                    <select id="mandateControlSort" style="padding:4px 8px;font-size:12px;" onchange="(function(sel){
                        const tbody = document.getElementById('mandateControlsBody');
                        if (!tbody) return;
                        const rows = Array.from(tbody.querySelectorAll('tr'));
                        rows.sort((a, b) => {
                            const v = sel.value;
                            if (v === 'criticality') return (parseInt(b.dataset.critVal)||0) - (parseInt(a.dataset.critVal)||0);
                            if (v === 'category') return (a.dataset.cat||'').localeCompare(b.dataset.cat||'');
                            if (v === 'section') return (a.dataset.sec||'').localeCompare(b.dataset.sec||'');
                            if (v === 'cid') return (parseInt(a.dataset.cid)||0) - (parseInt(b.dataset.cid)||0);
                            return 0;
                        });
                        rows.forEach(r => tbody.appendChild(r));
                    })(this)">
                        <option value="criticality">Criticality (High → Low)</option>
                        <option value="category">Category</option>
                        <option value="section">Section</option>
                        <option value="cid">CID Number</option>
                    </select>
                </div>
                <div style="overflow-x:auto;">
                <table class="detail-controls-table" style="width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed;">
                    <thead><tr style="text-align:left;border-bottom:2px solid var(--border);">
                        <th style="padding:6px 8px;font-weight:600;color:var(--text-2);width:100px;">CID</th>
                        <th style="padding:6px 8px;font-weight:600;color:var(--text-2);width:100px;">Criticality</th>
                        <th style="padding:6px 8px;font-weight:600;color:var(--text-2);width:140px;">Category</th>
                        <th style="padding:6px 8px;font-weight:600;color:var(--text-2);width:100px;">Section</th>
                        <th style="padding:6px 8px;font-weight:600;color:var(--text-2);">Statement</th>
                    </tr></thead>
                    <tbody id="mandateControlsBody">`;
            html += sortedControls.map(c => `<tr data-crit-val="${c.criticality_value || 0}" data-cat="${escapeHtml(c.category || "")}" data-sec="${escapeHtml(c.section_id || "")}" data-cid="${c.cid}" style="border-bottom:1px solid var(--border);">
                        <td style="padding:6px 8px;"><a href="#" onclick="event.preventDefault();showCidDetail(${c.cid})" style="color:var(--accent);font-weight:600;">CID ${c.cid}</a></td>
                        <td style="padding:6px 8px;"><span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;background:${_criticalityColor(c.criticality_label)}">${escapeHtml(decodeHtmlEntities(c.criticality_label || "?"))}</span></td>
                        <td style="padding:6px 8px;color:var(--text-2);font-size:12px;">${escapeHtml(decodeHtmlEntities(c.category || ""))}</td>
                        <td style="padding:6px 8px;color:var(--text-2);font-size:12px;">${escapeHtml(c.section_id || "")}</td>
                        <td style="padding:6px 8px;">${escapeHtml(decodeHtmlEntities(c.statement || ""))}</td>
                    </tr>`).join("");
            html += `</tbody></table></div></div>`;
        }
        if (m.policies && m.policies.length) {
            html += `<div class="detail-section"><h4>Related Policies (${m.policies.length})</h4><ul class="detail-ref-list">`;
            html += m.policies.map(p => `<li><a href="#" onclick="event.preventDefault();showPolicyDetail(${p.policy_id})">Policy ${p.policy_id}: ${escapeHtml(p.title || "")}</a></li>`).join("");
            html += `</ul></div>`;
        }
        content.innerHTML = html;
        openModal("mandateDetailModal");
    } catch (e) { showToast("Failed to load mandate detail", "error"); }
}

async function searchMandatesPage(page) {
    try {
        const resp = await apiFetch("/api/mandates?" + _mandateSearchParams(page).toString());
        const data = await resp.json();
        renderMandateResults(data);
    } catch (e) { showToast("Search failed", "error"); }
}

function renderPolicyResults(data) {
    const container = document.getElementById("policyResults");
    const items = data.results || [];
    updateCountBadge("policy", data.total || 0);
    _showExportButtons("policy", data.total || 0);
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No policies found matching your search.</p></div>';
        document.getElementById("policyPagination").style.display = "none";
        return;
    }
    container.innerHTML = items.map(p => `
        <div class="policy-card" onclick="showPolicyDetail(${p.policy_id})">
            ${_starHtml("policy", p.policy_id, p.title)}
            <div class="policy-card-body">
                <div class="policy-card-title">
                    <span class="policy-id">#${p.policy_id}</span>${escapeHtml(p.title || "")}
                </div>
                <div class="policy-card-meta">
                    ${p.status ? `<span class="badge-status badge-status-${(p.status || "").toLowerCase()}">${escapeHtml(p.status)}</span>` : ""}
                    ${p.is_locked ? '<span class="badge-status badge-locked">Locked</span>' : ""}
                    ${p.created_datetime ? `<span>Created: ${new Date(p.created_datetime).toLocaleDateString()}</span>` : ""}
                    ${p.last_modified_datetime ? `<span>Modified: ${new Date(p.last_modified_datetime).toLocaleDateString()}</span>` : ""}
                    ${p.control_count ? `<span>${p.control_count} controls</span>` : ""}
                    ${p.tech_count ? `<span>${p.tech_count} technologies</span>` : ""}
                    ${p.export_date ? '<span class="badge-pill badge-patchable">Exported</span>' : ""}
                </div>
            </div>
        </div>
    `).join("");
    renderPagination("policy", data);
}

// ─── Policy Select / Delete Mode ─────────────────────────────────────────
let _policySelectMode = false;
let _policyDetailId = null;  // Track currently viewed policy in detail modal

function enterPolicySelectMode() {
    _policySelectMode = true;
    document.getElementById("policyDeleteBar").style.display = "flex";
    document.getElementById("policySelectBtn").style.display = "none";
    document.getElementById("policySelectAll").checked = false;
    _updatePolicySelectedCount();
    // Add checkboxes to existing cards
    document.querySelectorAll("#policyResults .policy-card").forEach(card => {
        const pid = card.getAttribute("onclick")?.match(/showPolicyDetail\((\d+)\)/)?.[1];
        if (!pid) return;
        card.removeAttribute("onclick");
        card.style.cursor = "default";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.className = "policy-select-cb";
        cb.dataset.policyId = pid;
        cb.addEventListener("change", _updatePolicySelectedCount);
        cb.addEventListener("click", e => e.stopPropagation());
        card.insertBefore(cb, card.firstChild);
        card.addEventListener("click", () => { cb.checked = !cb.checked; _updatePolicySelectedCount(); });
    });
}

function exitPolicySelectMode() {
    _policySelectMode = false;
    document.getElementById("policyDeleteBar").style.display = "none";
    document.getElementById("policySelectBtn").style.display = "";
    // Re-render to restore normal cards
    searchPolicies();
}

function toggleAllPolicies(checked) {
    document.querySelectorAll("#policyResults .policy-select-cb").forEach(cb => cb.checked = checked);
    _updatePolicySelectedCount();
}

function _updatePolicySelectedCount() {
    const count = document.querySelectorAll("#policyResults .policy-select-cb:checked").length;
    document.getElementById("policySelectedCount").textContent = count + " selected";
}

async function deleteSelectedPolicies() {
    const cbs = document.querySelectorAll("#policyResults .policy-select-cb:checked");
    const ids = Array.from(cbs).map(cb => parseInt(cb.dataset.policyId));
    if (ids.length === 0) { showToast("No policies selected", "info"); return; }
    if (!confirm("Delete " + ids.length + " selected " + (ids.length === 1 ? "policy" : "policies") + "? This cannot be undone.")) return;
    try {
        const resp = await apiFetch("/api/policies", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ policy_ids: ids }),
        });
        const result = await resp.json();
        if (result.ok) {
            showToast("Deleted " + result.deleted + " " + (result.deleted === 1 ? "policy" : "policies"), "info");
            exitPolicySelectMode();
        } else {
            showToast(result.error || "Delete failed", "error");
        }
    } catch (e) {
        showToast("Delete failed: " + e.message, "error");
    }
}

async function deleteSinglePolicy() {
    if (!_policyDetailId) return;
    if (!confirm("Delete policy #" + _policyDetailId + "? This cannot be undone.")) return;
    try {
        const resp = await apiFetch("/api/policies", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ policy_ids: [_policyDetailId] }),
        });
        const result = await resp.json();
        if (result.ok) {
            showToast("Policy deleted", "info");
            closeModal("policyDetailModal");
            searchPolicies();
        } else {
            showToast(result.error || "Delete failed", "error");
        }
    } catch (e) {
        showToast("Delete failed: " + e.message, "error");
    }
}

// ─── QID Select / Bulk Export Mode ───────────────────────────────────────
let _qidSelectMode = false;

function enterQidSelectMode() {
    _qidSelectMode = true;
    document.getElementById("qidSelectBar").style.display = "flex";
    document.getElementById("qidSelectBtn").style.display = "none";
    document.getElementById("qidSelectAll").checked = false;
    _updateQidSelectedCount();
    document.querySelectorAll("#qidResults .qid-card").forEach(card => {
        const m = card.getAttribute("onclick")?.match(/showQidDetail\((\d+)\)/);
        if (!m) return;
        card.removeAttribute("onclick");
        card.style.cursor = "default";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.className = "qid-select-cb";
        cb.dataset.qid = m[1];
        cb.addEventListener("change", _updateQidSelectedCount);
        cb.addEventListener("click", e => e.stopPropagation());
        card.insertBefore(cb, card.firstChild);
        card.addEventListener("click", () => { cb.checked = !cb.checked; _updateQidSelectedCount(); });
    });
}

function exitQidSelectMode() {
    _qidSelectMode = false;
    document.getElementById("qidSelectBar").style.display = "none";
    document.getElementById("qidSelectBtn").style.display = "";
    searchQids();
}

function toggleAllQids(checked) {
    document.querySelectorAll("#qidResults .qid-select-cb").forEach(cb => cb.checked = checked);
    _updateQidSelectedCount();
}

function _updateQidSelectedCount() {
    const count = document.querySelectorAll("#qidResults .qid-select-cb:checked").length;
    document.getElementById("qidSelectedCount").textContent = count + " selected";
}

async function exportSelectedQids(format) {
    const ids = Array.from(document.querySelectorAll("#qidResults .qid-select-cb:checked")).map(cb => parseInt(cb.dataset.qid));
    if (ids.length === 0) { showToast("No QIDs selected", "info"); return; }
    try {
        showLoading("Exporting " + ids.length + " QIDs...");
        const resp = await apiFetch("/api/qids/export-details", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ids, format }),
        });
        if (!resp.ok) { const e = await resp.json(); showToast(e.error || "Export failed", "error"); hideLoading(); return; }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = "qkbe-qid-details." + format; a.click();
        URL.revokeObjectURL(url);
        hideLoading();
        showToast("Exported " + ids.length + " QIDs", "success");
    } catch (e) { hideLoading(); showToast("Export failed: " + e.message, "error"); }
}

// ─── CID Select / Bulk Export Mode ───────────────────────────────────────
let _cidSelectMode = false;

function enterCidSelectMode() {
    _cidSelectMode = true;
    document.getElementById("cidSelectBar").style.display = "flex";
    document.getElementById("cidSelectBtn").style.display = "none";
    document.getElementById("cidSelectAll").checked = false;
    _updateCidSelectedCount();
    document.querySelectorAll("#cidResults .cid-card").forEach(card => {
        const m = card.getAttribute("onclick")?.match(/showCidDetail\((\d+)\)/);
        if (!m) return;
        card.removeAttribute("onclick");
        card.style.cursor = "default";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.className = "cid-select-cb";
        cb.dataset.cid = m[1];
        cb.addEventListener("change", _updateCidSelectedCount);
        cb.addEventListener("click", e => e.stopPropagation());
        card.insertBefore(cb, card.firstChild);
        card.addEventListener("click", () => { cb.checked = !cb.checked; _updateCidSelectedCount(); });
    });
}

function exitCidSelectMode() {
    _cidSelectMode = false;
    document.getElementById("cidSelectBar").style.display = "none";
    document.getElementById("cidSelectBtn").style.display = "";
    searchCids();
}

function toggleAllCids(checked) {
    document.querySelectorAll("#cidResults .cid-select-cb").forEach(cb => cb.checked = checked);
    _updateCidSelectedCount();
}

function _updateCidSelectedCount() {
    const count = document.querySelectorAll("#cidResults .cid-select-cb:checked").length;
    document.getElementById("cidSelectedCount").textContent = count + " selected";
}

async function exportSelectedCids(format) {
    const ids = Array.from(document.querySelectorAll("#cidResults .cid-select-cb:checked")).map(cb => parseInt(cb.dataset.cid));
    if (ids.length === 0) { showToast("No CIDs selected", "info"); return; }
    try {
        showLoading("Exporting " + ids.length + " CIDs...");
        const resp = await apiFetch("/api/cids/export-details", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ids, format }),
        });
        if (!resp.ok) { const e = await resp.json(); showToast(e.error || "Export failed", "error"); hideLoading(); return; }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = "qkbe-cid-details." + format; a.click();
        URL.revokeObjectURL(url);
        hideLoading();
        showToast("Exported " + ids.length + " CIDs", "success");
    } catch (e) { hideLoading(); showToast("Export failed: " + e.message, "error"); }
}

function _criticalityColor(label) {
    const l = (label || "").toLowerCase();
    if (l === "critical") return "#e74c3c";
    if (l === "urgent") return "#e67e22";
    if (l === "serious") return "#f1c40f";
    if (l === "medium") return "#3498db";
    return "#95a5a6"; // minimal / unknown
}

let _activeTechFilter = null;
let _policyDetailCache = null;

function togglePolicyTechFilter(techName) {
    _activeTechFilter = (_activeTechFilter === techName) ? null : techName;
    showPolicyDetail(_policyDetailId, true);
}

function openPolicyTechPopup() {
    const techs = window._policyTechList || [];
    const source = window._policyTechSource === "xml" ? "Policy Export" : "Derived from Controls";
    if (!techs.length) return;
    const content = document.getElementById("policyTechPopupContent");
    content.innerHTML = `
        <p style="font-size:12px;color:var(--text-2);margin-bottom:12px;">Source: ${escapeHtml(source)} &bull; Click a technology to filter controls</p>
        <div class="policy-tech-badges">
            ${techs.map(t => `<span class="badge-tech${_activeTechFilter === t.tech_name ? ' badge-tech-active' : ''}" onclick="togglePolicyTechFilter('${escapeHtml(t.tech_name).replace(/'/g, "\\'")}');openPolicyTechPopup();" title="Click to filter controls">${escapeHtml(t.tech_name)}</span>`).join("")}
            ${_activeTechFilter ? `<span class="badge-tech-clear" onclick="togglePolicyTechFilter(null);openPolicyTechPopup();">Clear filter</span>` : ""}
        </div>`;
    document.getElementById("policyTechPopupTitle").textContent = "Technologies (" + techs.length + ")";
    openModal("policyTechPopupModal");
}

async function showPolicyDetail(id, useCache = false) {
    try {
        // Reset filter when switching to a different policy
        if (_policyDetailId !== id) _activeTechFilter = null;
        _policyDetailId = id;

        let p;
        if (useCache && _policyDetailCache && _policyDetailCache.policy_id === id) {
            p = _policyDetailCache;
        } else {
            const resp = await apiFetch("/api/policies/" + id);
            p = await resp.json();
            if (p.error) { showToast(p.error, "error"); return; }
            _policyDetailCache = p;
        }

        document.getElementById("policyDetailTitle").textContent = "Policy " + p.policy_id + " — " + (p.title || "");
        const content = document.getElementById("policyDetailContent");

        // ── Meta grid ──
        let metaHtml = `
            <div class="detail-meta-grid">
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Status</span>
                    <span class="detail-meta-value">${escapeHtml(p.status || "N/A")}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Locked</span>
                    <span class="detail-meta-value">${p.is_locked ? "Yes" : "No"}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Created</span>
                    <span class="detail-meta-value">${p.created_datetime ? new Date(p.created_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Last Modified</span>
                    <span class="detail-meta-value">${p.last_modified_datetime ? new Date(p.last_modified_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Last Evaluated</span>
                    <span class="detail-meta-value">${p.last_evaluated_datetime ? new Date(p.last_evaluated_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                ${p.created_by ? `<div class="detail-meta-item"><span class="detail-meta-label">Created By</span><span class="detail-meta-value">${escapeHtml(p.created_by)}</span></div>` : ""}
                ${p.last_modified_by ? `<div class="detail-meta-item"><span class="detail-meta-label">Modified By</span><span class="detail-meta-value">${escapeHtml(p.last_modified_by)}</span></div>` : ""}
                ${p.source ? `<div class="detail-meta-item"><span class="detail-meta-label">Source</span><span class="detail-meta-value">${escapeHtml(p.source)}</span></div>` : ""}
                ${p.export_date ? `<div class="detail-meta-item"><span class="detail-meta-label">Export Date</span><span class="detail-meta-value">${new Date(p.export_date).toLocaleDateString()}</span></div>` : ""}
            </div>`;

        // ── Technologies summary (compact — click to open full list popup) ──
        let techHtml = "";
        if (p.technologies && p.technologies.length) {
            // Store on window for the popup to access
            window._policyTechList = p.technologies;
            window._policyTechSource = p.technology_source;
            const preview = p.technologies.slice(0, 3).map(t => escapeHtml(t.tech_name)).join(", ");
            const more = p.technologies.length > 3 ? ` +${p.technologies.length - 3} more` : "";
            const filterNote = _activeTechFilter
                ? ` — <span style="color:var(--accent);font-weight:600;">Filtered: ${escapeHtml(_activeTechFilter)}</span> <a href="#" onclick="event.preventDefault();togglePolicyTechFilter(null)" style="color:var(--red);font-size:11px;">clear</a>`
                : "";
            techHtml = `
                <div class="detail-section policy-tech-summary">
                    <h4>Technologies (${p.technologies.length})${filterNote}</h4>
                    <div class="policy-tech-preview">
                        <span class="policy-tech-preview-text">${preview}${more}</span>
                        <button class="btn-sm" onclick="openPolicyTechPopup()" style="margin-left:auto;white-space:nowrap;">View All &amp; Filter</button>
                    </div>
                </div>`;
        }

        // ── View Report button (only if XML is stored) ──
        let reportBtnHtml = "";
        if (p.has_export) {
            reportBtnHtml = `<div style="margin-bottom:16px;">
                <button class="btn-sm" onclick="showPolicyReport(${p.policy_id})" style="display:inline-flex;align-items:center;gap:6px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                    View Report
                </button>
            </div>`;
        }

        // ── Controls section (grouped by category, filtered by technology) ──
        let controlsHtml = "";
        if (p.controls && p.controls.length) {
            // Filter controls by active technology filter
            let filteredControls = p.controls;
            if (_activeTechFilter) {
                filteredControls = p.controls.filter(c =>
                    c.technologies && c.technologies.some(t => t.tech_name === _activeTechFilter)
                );
            }

            // Group filtered controls by category
            const groups = {};
            filteredControls.forEach(c => {
                const cat = c.category || "Uncategorized";
                if (!groups[cat]) groups[cat] = [];
                groups[cat].push(c);
            });
            const categoryNames = Object.keys(groups).sort();
            const totalFiltered = filteredControls.length;
            const totalAll = p.controls.length;
            const filterLabel = _activeTechFilter
                ? `${totalFiltered} of ${totalAll} (filtered by ${escapeHtml(_activeTechFilter)})`
                : `${totalAll}`;

            if (totalFiltered === 0 && _activeTechFilter) {
                controlsHtml = `
                    <div class="detail-section">
                        <h4>Controls &mdash; 0 of ${totalAll} match "${escapeHtml(_activeTechFilter)}"</h4>
                        <p style="color:var(--text-2);font-size:13px;">No controls match the selected technology filter. <a href="#" onclick="event.preventDefault();togglePolicyTechFilter(null)" style="color:var(--accent);">Clear filter</a></p>
                    </div>`;
            } else {
                controlsHtml = `
                    <div class="detail-section">
                        <h4>Controls &mdash; ${filterLabel} across ${categoryNames.length} ${categoryNames.length === 1 ? "category" : "categories"}</h4>
                        ${categoryNames.map(cat => `
                            <div style="margin-bottom:16px;">
                                <div style="font-size:12px;font-weight:600;color:var(--text-2);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;padding-bottom:4px;border-bottom:1px solid var(--border);">${escapeHtml(decodeHtmlEntities(cat))} (${groups[cat].length})</div>
                                <table style="width:100%;border-collapse:collapse;font-size:13px;">
                                    <thead>
                                        <tr style="text-align:left;color:var(--text-2);font-size:11px;text-transform:uppercase;">
                                            <th style="padding:4px 8px;width:80px;">CID</th>
                                            <th style="padding:4px 8px;width:90px;">Criticality</th>
                                            <th style="padding:4px 8px;width:100px;">Check Type</th>
                                            <th style="padding:4px 8px;">Statement</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${groups[cat].map(c => `
                                            <tr style="border-bottom:1px solid var(--border);">
                                                <td style="padding:6px 8px;"><a href="#" onclick="event.preventDefault();showCidDetail(${c.cid}, window._policyTechList)" style="color:var(--accent);text-decoration:none;font-weight:600;">${c.cid}</a>${c.deprecated ? ' <span style="color:var(--red);font-size:10px;font-weight:600;" title="Deprecated">DEP</span>' : ""}</td>
                                                <td style="padding:6px 8px;"><span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;background:${_criticalityColor(c.criticality_label)}">${escapeHtml(decodeHtmlEntities(c.criticality_label || "?"))}</span></td>
                                                <td style="padding:6px 8px;color:var(--text-2);">${escapeHtml(decodeHtmlEntities(c.check_type || ""))}</td>
                                                <td style="padding:6px 8px;">${escapeHtml(decodeHtmlEntities(c.statement || ""))}</td>
                                            </tr>
                                        `).join("")}
                                    </tbody>
                                </table>
                            </div>
                        `).join("")}
                    </div>`;
            }
        }

        let mandatesHtml = "";
        if (p.linked_mandates && p.linked_mandates.length) {
            mandatesHtml = `<div class="detail-section"><h4>Related Mandates (${p.linked_mandates.length})</h4><ul class="detail-ref-list">${p.linked_mandates.map(m => `<li><a href="#" onclick="event.preventDefault();showMandateDetail(${m.mandate_id})">${escapeHtml(m.title || "Mandate " + m.mandate_id)}${m.version ? " v" + escapeHtml(m.version) : ""}</a> <span style="color:var(--text-2);font-size:11px;">${escapeHtml(m.publisher || "")}</span></li>`).join("")}</ul></div>`;
        }

        content.innerHTML = metaHtml + techHtml + reportBtnHtml + controlsHtml + mandatesHtml;
        openModal("policyDetailModal");
    } catch (e) {
        showToast("Failed to load policy detail", "error");
    }
}

// ─── Policy Report View ─────────────────────────────────────────────────
async function showPolicyReport(id) {
    try {
        const content = document.getElementById("policyReportContent");
        content.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-2);">Loading report...</div>';
        document.getElementById("policyReportTitle").textContent = "Policy Report";
        openModal("policyReportModal");

        const resp = await apiFetch("/api/policies/" + id + "/report");
        const r = await resp.json();
        if (r.error) { content.innerHTML = '<div class="empty-state"><p>' + escapeHtml(r.error) + '</p></div>'; return; }

        window._reportPolicyId = id;
        document.getElementById("policyReportTitle").textContent = "Policy " + r.policy_id + " Report";

        let html = '<div class="report-page">';

        // Report header
        html += `<h1 class="report-title">${escapeHtml(r.title || "Untitled Policy")}</h1>`;
        html += `<div class="report-subtitle">Policy ID: ${r.policy_id} &mdash; Generated: ${new Date().toLocaleDateString()}</div>`;

        // Meta summary
        html += '<div class="report-meta">';
        if (r.status) html += `<span><strong>Status:</strong> ${escapeHtml(r.status)}</span>`;
        if (r.created_datetime) html += `<span><strong>Created:</strong> ${new Date(r.created_datetime).toLocaleDateString()}</span>`;
        if (r.last_modified_datetime) html += `<span><strong>Modified:</strong> ${new Date(r.last_modified_datetime).toLocaleDateString()}</span>`;
        html += `<span><strong>Sections:</strong> ${r.total_sections}</span>`;
        html += `<span><strong>Controls:</strong> ${r.total_controls}</span>`;
        html += '</div>';

        // Technologies summary
        if (r.technologies && r.technologies.length) {
            html += `<div class="report-tech-summary"><strong>Technologies:</strong> ${r.technologies.map(t => escapeHtml(t.name)).join(", ")}</div>`;
        }

        // Sections
        (r.sections || []).forEach(section => {
            html += '<div class="report-section">';
            html += `<h2 class="report-section-heading">Section ${escapeHtml(section.number)}: ${escapeHtml(section.heading)}</h2>`;

            if (!section.controls || section.controls.length === 0) {
                html += '<p class="report-empty">No controls in this section.</p>';
            } else {
                html += `<table class="report-table">
                    <thead><tr>
                        <th style="width:90px;">Reference</th>
                        <th style="width:60px;">CID</th>
                        <th style="width:80px;">Criticality</th>
                        <th>Statement</th>
                        <th style="width:200px;">Technologies</th>
                    </tr></thead><tbody>`;

                section.controls.forEach(c => {
                    const critClass = "criticality-" + (c.criticality_label || "minimal").toLowerCase();
                    const techList = (c.technologies || []).map(t => escapeHtml(t.name)).join(", ");
                    html += `<tr${c.disabled ? ' style="opacity:0.5;"' : ""}>
                        <td>${escapeHtml(c.reference || "")}</td>
                        <td><a href="#" onclick="event.preventDefault();closeModal('policyReportModal');showCidDetail(${c.cid})" style="color:var(--accent);font-weight:600;">${c.cid || ""}</a></td>
                        <td><span class="report-criticality ${critClass}">${escapeHtml(c.criticality_label || "")}</span></td>
                        <td>${escapeHtml(c.statement || "")}</td>
                        <td class="report-tech-cell">${techList}</td>
                    </tr>`;
                });

                html += '</tbody></table>';
            }
            html += '</div>';
        });

        html += '</div>';
        content.innerHTML = html;
    } catch (e) {
        showToast("Failed to load policy report: " + e.message, "error");
    }
}

function downloadPolicyReportPdf() {
    if (!window._reportPolicyId) return;
    window.open("/api/policies/" + window._reportPolicyId + "/report-pdf", "_blank");
}

// ─── Migration ──────────────────────────────────────────────────────────
function selectAllMigration() {
    document.querySelectorAll('#migrationPolicyList input[type="checkbox"]').forEach(cb => cb.checked = true);
}

function deselectAllMigration() {
    document.querySelectorAll('#migrationPolicyList input[type="checkbox"]').forEach(cb => cb.checked = false);
}

/** Auto-check a policy's checkbox when the rename field is actually changed. */
function onMigrationTitleChange(input, policyId) {
    const original = input.getAttribute("data-original-title") || "";
    const current = input.value;
    if (current !== original) {
        const cb = document.querySelector(`#migrationPolicyList input[type="checkbox"][data-policy-id="${policyId}"]`);
        if (cb && !cb.checked) cb.checked = true;
    }
}

function getSelectedMigrationPolicies() {
    const checkboxes = document.querySelectorAll('#migrationPolicyList input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => ({
        id: parseInt(cb.dataset.policyId),
        title: cb.dataset.policyTitle || "Policy " + cb.dataset.policyId,
        controlCount: parseInt(cb.dataset.controlCount) || 0,
    }));
}

function _formatSize(bytes) {
    if (bytes > 1048576) return (bytes / 1048576).toFixed(1) + " MB";
    if (bytes > 1024) return (bytes / 1024).toFixed(0) + " KB";
    return bytes + " B";
}

/**
 * IMPORT XML — File browser to import local Qualys policy XML files into the tool.
 */
async function handlePolicyXmlImport(input) {
    const files = Array.from(input.files);
    if (files.length === 0) return;

    const total = files.length;
    const jobStart = new Date();
    showLoading("Importing " + total + " XML " + (total === 1 ? "file" : "files") + "...");
    const progress = document.getElementById("migrationProgress");
    progress.style.display = "block";
    progress.innerHTML = `<div class="migration-log-header">Import XML — ${total} ${total === 1 ? "file" : "files"} — Started ${jobStart.toLocaleTimeString()}</div>`;

    let successCount = 0;
    let failCount = 0;
    let totalBytes = 0;

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const step = i + 1;
        const stepStart = new Date();
        const label = `[${step}/${total}] "${file.name}"`;
        const rowId = "import-xml-row-" + i;
        progress.innerHTML += `<div class="migration-progress-item" id="${rowId}"><span class="status-dot pending"></span> ${escapeHtml(label)} — reading file...</div>`;
        progress.scrollTop = progress.scrollHeight;

        try {
            const formData = new FormData();
            formData.append("file", file);
            const resp = await apiFetch("/api/policies/import-xml", {
                method: "POST",
                body: formData,
            });
            const result = await resp.json();
            const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
            const row = document.getElementById(rowId);
            if (result.error) {
                failCount++;
                if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>FAILED</strong>: ${escapeHtml(result.error)} (${elapsed}s)`;
            } else {
                successCount++;
                const size = result.xml_size || 0;
                totalBytes += size;
                if (row) row.innerHTML = `<span class="status-dot success"></span> ${escapeHtml(label)} — Stored as policy #${result.policy_id} "${escapeHtml(result.title || "")}" (${_formatSize(size)}) in ${elapsed}s`;
            }
        } catch (e) {
            failCount++;
            const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
            const row = document.getElementById(rowId);
            if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>ERROR</strong>: ${escapeHtml(e.message)} (${elapsed}s)`;
        }
    }

    const jobElapsed = ((new Date() - jobStart) / 1000).toFixed(1);
    progress.innerHTML += `<div class="migration-log-summary">Import Complete — ${successCount} succeeded, ${failCount} failed — ${_formatSize(totalBytes)} total — ${jobElapsed}s elapsed</div>`;
    progress.scrollTop = progress.scrollHeight;

    hideLoading();
    input.value = ""; // Reset file input so the same file can be re-imported
    if (successCount > 0) loadMigrationPolicies(); // Refresh list to show updated export status
    if (failCount === 0) showToast("All " + total + " XML files imported successfully", "success");
    else showToast(successCount + " imported, " + failCount + " failed", failCount === total ? "error" : "info");
}

/**
 * EXPORT XML — Download selected policies as a single ZIP file.
 * Phase 1: Ensure all XMLs are stored (fetch from source if needed).
 * Phase 2: Request server-side ZIP bundle and trigger single download.
 */
async function exportSelectedPolicies() {
    const selected = getSelectedMigrationPolicies();
    if (selected.length === 0) { showToast("Select policies to export", "error"); return; }

    const total = selected.length;
    const jobStart = new Date();
    showLoading("Exporting " + total + " " + (total === 1 ? "policy" : "policies") + " as ZIP...");
    const progress = document.getElementById("migrationProgress");
    progress.style.display = "block";
    progress.innerHTML = `<div class="migration-log-header">Export XML → ZIP — ${total} ${total === 1 ? "policy" : "policies"} — Started ${jobStart.toLocaleTimeString()}</div>`;

    // Phase 1 — Ensure all selected policies have XML stored
    let readyCount = 0;
    let failCount = 0;
    const readyIds = [];

    for (let i = 0; i < selected.length; i++) {
        const p = selected[i];
        const step = i + 1;
        const stepStart = new Date();
        const titleInput = document.querySelector(`#migration-title-${p.id}`);
        const displayTitle = (titleInput ? titleInput.value.trim() : "") || p.title;
        const label = `[${step}/${total}] #${p.id} "${displayTitle}"`;
        const rowId = "export-row-" + p.id;
        progress.innerHTML += `<div class="migration-progress-item" id="${rowId}"><span class="status-dot pending"></span> ${escapeHtml(label)} — checking XML...</div>`;
        progress.scrollTop = progress.scrollHeight;

        try {
            const checkResp = await apiFetch("/api/policies/" + p.id + "/download-xml");
            if (checkResp.status === 404 && activeCredentialId) {
                const row = document.getElementById(rowId);
                if (row) row.innerHTML = `<span class="status-dot pending"></span> ${escapeHtml(label)} — fetching from source Qualys...`;
                const auth = getApiAuth();
                const fetchResp = await apiFetch("/api/policies/" + p.id + "/export", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(auth),
                });
                const fetchResult = await fetchResp.json();
                if (fetchResult.error) {
                    failCount++;
                    const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
                    if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>FAILED</strong>: ${escapeHtml(fetchResult.error)} (${elapsed}s)`;
                    continue;
                }
                readyIds.push(p.id);
                readyCount++;
                const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
                if (row) row.innerHTML = `<span class="status-dot success"></span> ${escapeHtml(label)} — XML ready (fetched from source, ${elapsed}s)`;
            } else if (checkResp.ok) {
                readyIds.push(p.id);
                readyCount++;
                const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
                const row = document.getElementById(rowId);
                if (row) row.innerHTML = `<span class="status-dot success"></span> ${escapeHtml(label)} — XML ready (${elapsed}s)`;
            } else {
                failCount++;
                const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
                const row = document.getElementById(rowId);
                if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>FAILED</strong>: No stored XML (connect to source and try again) (${elapsed}s)`;
            }
        } catch (e) {
            failCount++;
            const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
            const row = document.getElementById(rowId);
            if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>ERROR</strong>: ${escapeHtml(e.message)} (${elapsed}s)`;
        }
    }

    // Phase 2 — Download ZIP bundle
    if (readyIds.length > 0) {
        const zipRowId = "export-row-zip";
        progress.innerHTML += `<div class="migration-progress-item" id="${zipRowId}"><span class="status-dot pending"></span> Bundling ${readyIds.length} ${readyIds.length === 1 ? "policy" : "policies"} into ZIP...</div>`;
        progress.scrollTop = progress.scrollHeight;

        try {
            const zipResp = await apiFetch("/api/policies/export-zip", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ policy_ids: readyIds }),
            });
            if (!zipResp.ok) {
                const err = await zipResp.json();
                const row = document.getElementById(zipRowId);
                if (row) row.innerHTML = `<span class="status-dot error"></span> ZIP bundle — <strong>FAILED</strong>: ${escapeHtml(err.error || "Unknown error")}`;
            } else {
                const blob = await zipResp.blob();
                // Extract filename from Content-Disposition header or use default
                const cd = zipResp.headers.get("Content-Disposition") || "";
                const fnMatch = cd.match(/filename="(.+)"/);
                const filename = fnMatch ? fnMatch[1] : "policy_export.zip";
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                const row = document.getElementById(zipRowId);
                if (row) row.innerHTML = `<span class="status-dot success"></span> ZIP downloaded — ${_formatSize(blob.size)} (${readyIds.length} ${readyIds.length === 1 ? "policy" : "policies"})`;
            }
        } catch (e) {
            const row = document.getElementById(zipRowId);
            if (row) row.innerHTML = `<span class="status-dot error"></span> ZIP bundle — <strong>ERROR</strong>: ${escapeHtml(e.message)}`;
        }
    }

    const jobElapsed = ((new Date() - jobStart) / 1000).toFixed(1);
    progress.innerHTML += `<div class="migration-log-summary">Export Complete — ${readyCount} bundled into ZIP, ${failCount} failed — ${jobElapsed}s elapsed</div>`;
    progress.scrollTop = progress.scrollHeight;

    hideLoading();
    if (failCount === 0) showToast("All " + total + " policies exported as ZIP", "success");
    else showToast(readyCount + " exported, " + failCount + " failed", failCount === total ? "error" : "info");
}

/** Trigger browser file download from blob. Uses rename field for filename. */
function _triggerDownload(blob, resp, title) {
    // Sanitize title for filename: keep word chars, spaces, hyphens
    let safeName = title.replace(/[^\w\s\-]/g, '').trim().replace(/\s+/g, '_');
    if (!safeName) safeName = "policy";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = safeName + ".xml";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * UPLOAD TO DESTINATION — Push selected policies (from stored XML) to a Qualys subscription.
 * If a policy has no stored XML, it first fetches from the source Qualys API.
 */
async function uploadSelectedPolicies() {
    const destCred = document.getElementById("migrationDestCred").value;
    if (!destCred) { showToast("Select destination environment", "error"); return; }
    const selected = getSelectedMigrationPolicies();
    if (selected.length === 0) { showToast("Select policies to upload", "error"); return; }

    // Resolve source credential — the one that originally synced the policies
    let sourceCredId = null;
    try {
        const syncResp = await apiFetch("/api/sync/status");
        const syncStatus = await syncResp.json();
        sourceCredId = syncStatus.policies && syncStatus.policies.credential_id;
    } catch (e) { /* fallback to activeCredentialId below */ }

    // Resolve destination credential label for logging
    const destOption = document.querySelector(`#migrationDestCred option[value="${destCred}"]`);
    const destLabel = destOption ? destOption.textContent.trim() : destCred;

    const total = selected.length;
    const jobStart = new Date();
    showLoading("Uploading " + total + " " + (total === 1 ? "policy" : "policies") + " to destination...");
    const progress = document.getElementById("migrationProgress");
    progress.style.display = "block";
    progress.innerHTML = `<div class="migration-log-header">Upload Job — ${total} ${total === 1 ? "policy" : "policies"} → ${escapeHtml(destLabel)} — Started ${jobStart.toLocaleTimeString()}</div>`;

    let successCount = 0;
    let failCount = 0;
    let skipCount = 0;

    for (let i = 0; i < selected.length; i++) {
        const p = selected[i];
        const step = i + 1;
        const stepStart = new Date();

        const titleInput = document.querySelector(`#migration-title-${p.id}`);
        const lockSelect = document.querySelector(`#migration-lock-${p.id}`);
        const newTitle = titleInput ? titleInput.value.trim() : "";
        const lockPref = lockSelect ? lockSelect.value : "";
        const displayName = newTitle || p.title;
        const label = `[${step}/${total}] #${p.id} "${displayName}"`;

        // Build status detail for logging
        let opDetail = "uploading";
        if (newTitle) opDetail += `, rename → "${newTitle}"`;
        if (lockPref) opDetail += `, set ${lockPref}`;

        const rowId = "upload-row-" + p.id;
        progress.innerHTML += `<div class="migration-progress-item" id="${rowId}"><span class="status-dot pending"></span> ${escapeHtml(label)} — ${escapeHtml(opDetail)}...</div>`;
        progress.scrollTop = progress.scrollHeight;

        // Skip policies with no sections/controls — Qualys rejects these with error 1910
        if (p.controlCount === 0) {
            skipCount++;
            const row = document.getElementById(rowId);
            if (row) row.innerHTML = `<span class="status-dot skipped"></span> ${escapeHtml(label)} — <strong>SKIPPED</strong>: Policy has no sections/controls (would be rejected by Qualys)`;
            continue;
        }

        try {
            // First ensure XML is stored — export from SOURCE subscription if needed
            const xmlCheck = await apiFetch("/api/policies/" + p.id + "/download-xml");
            const srcCred = sourceCredId || activeCredentialId;
            if (xmlCheck.status === 404 && srcCred) {
                const row = document.getElementById(rowId);
                if (row) row.innerHTML = `<span class="status-dot pending"></span> ${escapeHtml(label)} — exporting XML from source...`;
                const auth = { credential_id: srcCred };
                const fetchResp = await apiFetch("/api/policies/" + p.id + "/export", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(auth),
                });
                const fetchResult = await fetchResp.json();
                if (fetchResult.error) {
                    failCount++;
                    const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
                    if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>FAILED</strong>: Could not fetch XML — ${escapeHtml(fetchResult.error)} (${elapsed}s)`;
                    continue;
                }
                if (row) row.innerHTML = `<span class="status-dot pending"></span> ${escapeHtml(label)} — ${escapeHtml(opDetail)}...`;
            } else if (xmlCheck.status === 404) {
                failCount++;
                const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
                const row = document.getElementById(rowId);
                if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>FAILED</strong>: No stored XML. Import XML or connect to source first. (${elapsed}s)`;
                continue;
            }

            // Now upload to destination
            const body = {
                credential_id: destCred,
                source_policy_id: p.id,
            };
            if (newTitle) body.title = newTitle;
            if (lockPref) body.lock = lockPref;

            const resp = await apiFetch("/api/policies/upload", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            const result = await resp.json();
            const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
            const row = document.getElementById(rowId);

            if (result.error) {
                failCount++;
                if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>FAILED</strong>: ${escapeHtml(result.error)} (${elapsed}s)`;
            } else {
                successCount++;
                let detail = "Uploaded successfully";
                if (result.imported_policy_id) detail += ` → new ID #${result.imported_policy_id}`;
                if (newTitle) detail += ` as "${escapeHtml(newTitle)}"`;
                if (result.lock_result) detail += ` | ${escapeHtml(result.lock_result)}`;
                if (row) row.innerHTML = `<span class="status-dot success"></span> ${escapeHtml(label)} — ${detail} (${elapsed}s)`;
            }
        } catch (e) {
            failCount++;
            const elapsed = ((new Date() - stepStart) / 1000).toFixed(1);
            const row = document.getElementById(rowId);
            if (row) row.innerHTML = `<span class="status-dot error"></span> ${escapeHtml(label)} — <strong>ERROR</strong>: ${escapeHtml(e.message)} (${elapsed}s)`;
        }
    }

    const jobElapsed = ((new Date() - jobStart) / 1000).toFixed(1);
    const skipNote = skipCount ? `, ${skipCount} skipped (empty)` : "";
    progress.innerHTML += `<div class="migration-log-summary">Upload Complete — ${successCount} succeeded, ${failCount} failed${skipNote} — ${jobElapsed}s elapsed</div>`;
    progress.scrollTop = progress.scrollHeight;

    hideLoading();
    const uploadAttempted = total - skipCount;
    if (failCount === 0 && skipCount === 0) showToast("All " + total + " policies uploaded successfully", "success");
    else if (failCount === 0) showToast(successCount + " uploaded, " + skipCount + " skipped (empty)", "success");
    else showToast(successCount + " uploaded, " + failCount + " failed" + (skipCount ? ", " + skipCount + " skipped" : ""), failCount === uploadAttempted ? "error" : "info");
}

// ─── Pagination ─────────────────────────────────────────────────────────
function renderPagination(prefix, data) {
    const container = document.getElementById(prefix + "Pagination");
    if (!data.pages || data.pages <= 1) {
        container.style.display = "none";
        return;
    }
    container.style.display = "flex";
    let html = `<button ${data.page <= 1 ? "disabled" : ""} onclick="navigatePage('${prefix}', ${data.page - 1})">&laquo; Prev</button>`;
    html += `<span class="page-info">Page ${data.page} of ${data.pages} (${data.total} total)</span>`;
    html += `<button ${data.page >= data.pages ? "disabled" : ""} onclick="navigatePage('${prefix}', ${data.page + 1})">Next &raquo;</button>`;
    container.innerHTML = html;
}

function navigatePage(prefix, page) {
    if (prefix === "qid") { searchQidsPage(page); }
    else if (prefix === "cid") { searchCidsPage(page); }
    else if (prefix === "policy") { searchPoliciesPage(page); }
    else if (prefix === "mandate") { searchMandatesPage(page); }
}

async function searchQidsPage(page) {
    try {
        const resp = await apiFetch("/api/qids?" + _qidSearchParams(page).toString());
        const data = await resp.json();
        renderQidResults(data);
    } catch (e) { showToast("Search failed", "error"); }
}

async function searchCidsPage(page) {
    try {
        const resp = await apiFetch("/api/cids?" + _cidSearchParams(page).toString());
        const data = await resp.json();
        renderCidResults(data);
    } catch (e) { showToast("Search failed", "error"); }
}

async function searchPoliciesPage(page) {
    try {
        const resp = await apiFetch("/api/policies?" + _policySearchParams(page).toString());
        const data = await resp.json();
        renderPolicyResults(data);
    } catch (e) { showToast("Search failed", "error"); }
}

// ─── Help ─────────────────────────────────────────────────────────────
function showHelpModal() {
    switchTab("help");
    // Populate shortcuts table on first visit
    if (!_tabLoaded.help) {
        _tabLoaded.help = true;
        const el = document.getElementById("helpShortcutsBody");
        if (el) {
            el.innerHTML = Object.entries(_SHORTCUTS).map(([key, s]) =>
                `<tr><td><kbd class="kbd">${escapeHtml(key)}</kbd></td><td>${escapeHtml(s.desc)}</td></tr>`
            ).join("");
        }
    }
}

// ─── Utilities ──────────────────────────────────────────────────────────
function decodeHtmlEntities(str) {
    if (!str) return "";
    // Decode XML/HTML entities left over from double-encoded Qualys API responses.
    // Order matters: &amp; last because earlier replacements may produce '&'.
    return str.replace(/&apos;/g, "'")
              .replace(/&quot;/g, '"')
              .replace(/&lt;/g, '<')
              .replace(/&gt;/g, '>')
              .replace(/&amp;/g, '&');
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderRefList(title, refs) {
    if (!refs || refs.length === 0) return "";
    const idKey = Object.keys(refs[0]).find(k => k.endsWith("_id") || k === "cve_id" || k === "bugtraq_id" || k === "vendor_ref_id") || "id";
    return `
        <div class="detail-section">
            <h4>${escapeHtml(title)} (${refs.length})</h4>
            <ul class="detail-ref-list">
                ${refs.map(r => `<li>${r.url ? `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r[idKey] || "")}</a>` : escapeHtml(r[idKey] || "")}</li>`).join("")}
            </ul>
        </div>
    `;
}

// ─── Scheduled Delta Sync ───────────────────────────────────────────────
let _deltaSyncType = null; // Tracks which data type the modal is open for

const _dataTypeLabels = {
    qids: "QIDs (Knowledge Base)",
    cids: "CIDs (Controls)",
    policies: "Policies",
    mandates: "Mandates",
};

async function showDeltaSyncModal(type) {
    if (!activeCredentialId) {
        showToast("Save credentials first in Settings", "error");
        switchTab("settings");
        return;
    }
    _deltaSyncType = type;
    const label = _dataTypeLabels[type] || type;
    document.getElementById("deltaSyncModalTitle").textContent = "Delta Sync — " + label;

    // Reset to "Run once" mode
    const radios = document.querySelectorAll('input[name="deltaSyncMode"]');
    radios.forEach(r => { r.checked = r.value === "once"; });
    document.getElementById("scheduleOptions").style.display = "none";

    // Set date input min to today, default to today
    const dateInput = document.getElementById("schedStartDate");
    const today = new Date().toISOString().split("T")[0];
    dateInput.min = today;
    dateInput.value = today;

    // Default time to 02:00
    document.getElementById("schedStartTime").value = "02:00";

    // Show user's timezone
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    document.getElementById("schedTzDisplay").textContent = "Timezone: " + tz;

    // Reset frequency to "Once a week"
    const freqRadios = document.querySelectorAll('input[name="schedFreq"]');
    freqRadios.forEach(r => { r.checked = r.value === "1x_week"; });

    // Check if schedule already exists for this type
    const existingDiv = document.getElementById("deltaSyncExisting");
    const existingInfo = document.getElementById("deltaSyncExistingInfo");
    try {
        const resp = await apiFetch("/api/schedules");
        const schedules = await resp.json();
        const sched = schedules.find(s => s.data_type === type);
        if (sched) {
            existingInfo.textContent = sched.frequency_label + " · Next: " + (sched.next_run_local || "—");
            existingDiv.style.display = "block";
            // Pre-fill with existing values
            const modeRadio = document.querySelector('input[name="deltaSyncMode"][value="schedule"]');
            if (modeRadio) { modeRadio.checked = true; toggleScheduleOptions(); }
            if (sched.start_date) dateInput.value = sched.start_date;
            if (sched.start_time) document.getElementById("schedStartTime").value = sched.start_time;
            const existFreqRadio = document.querySelector('input[name="schedFreq"][value="' + sched.frequency + '"]');
            if (existFreqRadio) existFreqRadio.checked = true;
        } else {
            existingDiv.style.display = "none";
        }
    } catch (e) {
        existingDiv.style.display = "none";
    }

    openModal("deltaSyncModal");
}

function toggleScheduleOptions() {
    const mode = document.querySelector('input[name="deltaSyncMode"]:checked');
    const opts = document.getElementById("scheduleOptions");
    opts.style.display = mode && mode.value === "schedule" ? "block" : "none";
}

async function confirmDeltaSync() {
    const type = _deltaSyncType;
    if (!type) return;

    const mode = document.querySelector('input[name="deltaSyncMode"]:checked');
    if (!mode) return;

    if (mode.value === "once") {
        // Run once immediately
        closeModal("deltaSyncModal");
        _executeSyncInternal(type, false);
        return;
    }

    // Schedule recurring
    const startDate = document.getElementById("schedStartDate").value;
    const startTime = document.getElementById("schedStartTime").value;
    const freq = document.querySelector('input[name="schedFreq"]:checked');
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

    if (!startDate) { showToast("Select a start date", "error"); return; }
    if (!startTime) { showToast("Select a start time", "error"); return; }
    if (!freq) { showToast("Select a frequency", "error"); return; }

    // Validate start date is today or later
    const today = new Date().toISOString().split("T")[0];
    if (startDate < today) { showToast("Start date must be today or later", "error"); return; }

    const auth = getApiAuth();
    try {
        const resp = await apiFetch("/api/schedules/" + type, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                credential_id: auth.credential_id,
                platform: auth.platform,
                frequency: freq.value,
                start_date: startDate,
                start_time: startTime,
                timezone: tz,
            }),
        });
        const result = await resp.json();
        if (result.error) {
            showToast(result.error, "error");
            return;
        }
        closeModal("deltaSyncModal");
        showToast("Schedule saved for " + (_dataTypeLabels[type] || type), "success");
        // Refresh schedule badges
        loadScheduleBadges();
    } catch (e) {
        showToast("Failed to save schedule: " + e.message, "error");
    }
}

async function cancelSchedule(type) {
    try {
        const resp = await apiFetch("/api/schedules/" + type, { method: "DELETE" });
        const result = await resp.json();
        if (result.ok) {
            showToast("Schedule removed", "info");
            loadScheduleBadges();
        } else {
            showToast(result.error || "Failed to remove schedule", "error");
        }
    } catch (e) {
        showToast("Failed to remove schedule: " + e.message, "error");
    }
}

async function loadScheduleBadges() {
    try {
        const resp = await apiFetch("/api/schedules");
        const schedules = await resp.json();
        updateScheduleBadges(schedules);
    } catch (e) { /* ignore */ }
}

function updateScheduleBadges(schedules) {
    const badgeIds = {
        qids: "schedBadgeQids",
        cids: "schedBadgeCids",
        policies: "schedBadgePolicies",
        mandates: "schedBadgeMandates",
    };

    // Hide all badges first
    Object.values(badgeIds).forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.style.display = "none"; el.innerHTML = ""; }
    });

    if (!schedules || !Array.isArray(schedules)) return;

    schedules.forEach(sched => {
        const badgeId = badgeIds[sched.data_type];
        if (!badgeId) return;
        const el = document.getElementById(badgeId);
        if (!el) return;

        const freqLabel = sched.frequency_label || sched.frequency;
        const nextRun = sched.next_run_local || "—";
        const lastRun = sched.last_run_local ? " · Last: " + sched.last_run_local : "";
        const credLabel = sched.credential_id ? " · Cred: " + sched.credential_id : "";

        el.innerHTML =
            '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> ' +
            '<span>' + escapeHtml(freqLabel) + credLabel + ' · Next: ' + escapeHtml(nextRun) + lastRun + '</span> ' +
            '<a onclick="cancelSchedule(\'' + sched.data_type + '\')" title="Cancel schedule">Cancel</a>';
        el.style.display = "flex";
    });
}

// ─── Global Keyboard Shortcuts ──────────────────────────────────────────
document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    const isInput = tag === "input" || tag === "textarea" || tag === "select" || e.target.isContentEditable;
    // Escape always works (close modal or exit select mode)
    if (e.key === "Escape") {
        _closeAllRecentDropdowns();
        if (_modalStack.length) { closeTopModal(); return; }
        if (_qidSelectMode) { exitQidSelectMode(); return; }
        if (_cidSelectMode) { exitCidSelectMode(); return; }
        if (_policySelectMode) { exitPolicySelectMode(); return; }
        return;
    }
    // Skip shortcuts when typing in inputs
    if (isInput) return;
    // Close recent dropdowns on any key press
    _closeAllRecentDropdowns();
    const shortcut = _SHORTCUTS[e.key];
    if (shortcut) {
        e.preventDefault();
        shortcut.action();
    }
});


// ═══════════════════════════════════════════════════════════════════════════
// Dashboard & Analytics
// ═══════════════════════════════════════════════════════════════════════════

const _SEV_COLORS = { 5: "#f87171", 4: "#fb923c", 3: "#fbbf24", 2: "#4a7cff", 1: "#34d399" };
const _SEV_LABELS = { 5: "Urgent", 4: "Critical", 3: "Serious", 2: "Medium", 1: "Minimal" };
const _CRIT_COLORS = { URGENT: "#f87171", CRITICAL: "#fb923c", SERIOUS: "#fbbf24", MEDIUM: "#4a7cff", MINIMAL: "#34d399" };
const _CRIT_ORDER = ["URGENT", "CRITICAL", "SERIOUS", "MEDIUM", "MINIMAL"];

async function loadDashboard() {
    try {
        const [statsResp, syncResp] = await Promise.all([
            apiFetch("/api/dashboard/stats"),
            apiFetch("/api/sync/status"),
        ]);
        const stats = await statsResp.json();
        const sync = await syncResp.json();
        renderDataOverview(sync);
        renderSeverityChart(stats.severity || {});
        renderCriticalityChart(stats.criticality || {});
        renderCategoriesChart(stats.categories_top15 || []);
        renderPatchable(stats.patchable || {});
        renderComplianceSummary(stats.compliance || {});
        renderSyncHealth(sync);
        _tabLoaded.dashboard = true;
    } catch (e) {
        console.error("Dashboard load failed:", e);
    }
}

function renderDataOverview(sync) {
    const types = [
        { key: "qids", elCount: "dashQidCount", elSync: "dashQidSync" },
        { key: "cids", elCount: "dashCidCount", elSync: "dashCidSync" },
        { key: "policies", elCount: "dashPolicyCount", elSync: "dashPolicySync" },
        { key: "mandates", elCount: "dashMandateCount", elSync: "dashMandateSync" },
    ];
    types.forEach(t => {
        const s = sync[t.key] || {};
        document.getElementById(t.elCount).textContent = (s.record_count || 0).toLocaleString();
        if (s.last_sync) {
            const d = new Date(s.last_sync);
            document.getElementById(t.elSync).textContent = "Synced " + _timeAgo(d);
        } else {
            document.getElementById(t.elSync).textContent = "Not synced";
        }
    });
}

function _timeAgo(date) {
    const secs = Math.floor((Date.now() - date.getTime()) / 1000);
    if (secs < 60) return "just now";
    if (secs < 3600) return Math.floor(secs / 60) + "m ago";
    if (secs < 86400) return Math.floor(secs / 3600) + "h ago";
    return Math.floor(secs / 86400) + "d ago";
}

function _getChartTextColor() {
    return getComputedStyle(document.documentElement).getPropertyValue("--text-1").trim() || "#b0b8cc";
}

function _getChartGridColor() {
    return getComputedStyle(document.documentElement).getPropertyValue("--border").trim() || "#2a2f3e";
}

function renderSeverityChart(severity) {
    if (_charts.severity) { _charts.severity.destroy(); _charts.severity = null; }
    const canvas = document.getElementById("severityChart");
    if (!canvas) return;
    const labels = [5, 4, 3, 2, 1];
    const data = labels.map(l => severity[l] || 0);
    const colors = labels.map(l => _SEV_COLORS[l]);
    const total = data.reduce((a, b) => a + b, 0);

    _charts.severity = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: labels.map(l => _SEV_LABELS[l]),
            datasets: [{ data, backgroundColor: colors, borderWidth: 0 }],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: ctx => ctx.label + ": " + ctx.raw.toLocaleString() } },
            },
            cutout: "65%",
        },
    });

    // Custom legend
    const legend = document.getElementById("severityLegend");
    if (legend) {
        legend.innerHTML = labels.map(l => {
            const cnt = severity[l] || 0;
            const pct = total > 0 ? ((cnt / total) * 100).toFixed(1) : "0.0";
            return `<div class="chart-legend-item"><span class="chart-legend-dot" style="background:${_SEV_COLORS[l]}"></span>${_SEV_LABELS[l]}: ${cnt.toLocaleString()} (${pct}%)</div>`;
        }).join("");
    }
}

function renderCriticalityChart(criticality) {
    if (_charts.criticality) { _charts.criticality.destroy(); _charts.criticality = null; }
    const canvas = document.getElementById("criticalityChart");
    if (!canvas) return;
    const data = _CRIT_ORDER.map(k => criticality[k] || 0);
    const colors = _CRIT_ORDER.map(k => _CRIT_COLORS[k]);
    const total = data.reduce((a, b) => a + b, 0);

    _charts.criticality = new Chart(canvas, {
        type: "doughnut",
        data: {
            labels: _CRIT_ORDER.map(k => k.charAt(0) + k.slice(1).toLowerCase()),
            datasets: [{ data, backgroundColor: colors, borderWidth: 0 }],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: ctx => ctx.label + ": " + ctx.raw.toLocaleString() } },
            },
            cutout: "65%",
        },
    });

    const legend = document.getElementById("criticalityLegend");
    if (legend) {
        legend.innerHTML = _CRIT_ORDER.map(k => {
            const cnt = criticality[k] || 0;
            const pct = total > 0 ? ((cnt / total) * 100).toFixed(1) : "0.0";
            const label = k.charAt(0) + k.slice(1).toLowerCase();
            return `<div class="chart-legend-item"><span class="chart-legend-dot" style="background:${_CRIT_COLORS[k]}"></span>${label}: ${cnt.toLocaleString()} (${pct}%)</div>`;
        }).join("");
    }
}

function renderCategoriesChart(categories) {
    if (_charts.categories) { _charts.categories.destroy(); _charts.categories = null; }
    const canvas = document.getElementById("categoriesChart");
    if (!canvas) return;
    const labels = categories.map(c => c.name.length > 35 ? c.name.substring(0, 32) + "..." : c.name);
    const data = categories.map(c => c.count);
    const textColor = _getChartTextColor();
    const gridColor = _getChartGridColor();

    _charts.categories = new Chart(canvas, {
        type: "bar",
        data: {
            labels,
            datasets: [{ data, backgroundColor: "rgba(74,124,255,0.7)", borderRadius: 3 }],
        },
        options: {
            indexAxis: "y",
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: textColor }, grid: { color: gridColor } },
                y: { ticks: { color: textColor, font: { size: 11 } }, grid: { display: false } },
            },
        },
    });
}

function renderPatchable(patchable) {
    const total = (patchable.yes || 0) + (patchable.no || 0);
    const pct = total > 0 ? Math.round((patchable.yes / total) * 100) : 0;
    const el = document.getElementById("patchablePct");
    if (el) el.textContent = pct + "%";
}

function renderComplianceSummary(compliance) {
    const mc = compliance.mandate_count || 0;
    const tc = compliance.total_controls || 0;
    const cim = compliance.controls_in_mandates || 0;
    const tp = compliance.total_policies || 0;
    const pwc = compliance.policies_with_controls || 0;

    document.getElementById("compMandateCount").textContent = mc.toLocaleString();

    const ctrlPct = tc > 0 ? Math.round((cim / tc) * 100) : 0;
    document.getElementById("compControlCoverage").textContent = cim.toLocaleString() + " / " + tc.toLocaleString();
    const ctrlBar = document.getElementById("compControlBar");
    if (ctrlBar) ctrlBar.style.width = ctrlPct + "%";

    const polPct = tp > 0 ? Math.round((pwc / tp) * 100) : 0;
    document.getElementById("compPolicyCoverage").textContent = pwc.toLocaleString() + " / " + tp.toLocaleString();
    const polBar = document.getElementById("compPolicyBar");
    if (polBar) polBar.style.width = polPct + "%";
}

function renderSyncHealth(sync) {
    const tbody = document.getElementById("syncHealthBody");
    if (!tbody) return;
    const types = [
        { key: "qids", label: "QIDs (Knowledge Base)" },
        { key: "cids", label: "CIDs (Controls)" },
        { key: "policies", label: "Policies" },
        { key: "mandates", label: "Mandates (Frameworks)" },
    ];
    tbody.innerHTML = types.map(t => {
        const s = sync[t.key] || {};
        const count = (s.record_count || 0).toLocaleString();
        const lastSync = s.last_sync ? new Date(s.last_sync).toLocaleString() : "Never";
        const lastFull = s.last_full_sync ? new Date(s.last_full_sync).toLocaleString() : "Never";
        const health = _syncHealthStatus(s);
        return `<tr>
            <td>${escapeHtml(t.label)}</td>
            <td>${count}</td>
            <td>${lastSync}</td>
            <td>${lastFull}</td>
            <td><span class="health-dot ${health.cls}"></span>${health.label}</td>
        </tr>`;
    }).join("");
}

function _syncHealthStatus(syncState) {
    if (!syncState.last_sync) return { cls: "health-red", label: "Never synced" };
    const age = Date.now() - new Date(syncState.last_sync).getTime();
    const days = age / (1000 * 60 * 60 * 24);
    if (days < 7) return { cls: "health-green", label: "Healthy" };
    if (days < 30) return { cls: "health-orange", label: "Aging" };
    return { cls: "health-red", label: "Stale" };
}


// ═══════════════════════════════════════════════════════════════════════════
// Export (CSV & PDF)
// ═══════════════════════════════════════════════════════════════════════════

function getFilterParams(type) {
    const p = new URLSearchParams();
    if (type === "qids") {
        const q = document.getElementById("qidSearchInput").value.trim();
        if (q) p.set("q", q);
        const sev = document.getElementById("qidSeverityFilter").value;
        if (sev) p.set("severity", sev);
        const patch = document.getElementById("qidPatchableFilter").value;
        if (patch) p.set("patchable", patch);
        if (qidCveMs) {
            const vals = qidCveMs.getValues();
            if (vals.length) { p.set("cve", vals.join(",")); p.set("cve_mode", qidCveMs.getMode()); }
        }
        if (qidCategoryMs) {
            const vals = qidCategoryMs.getValues();
            if (vals.length) p.set("category", vals.join(","));
        }
        // Advanced filters
        const vulnType = document.getElementById("qidVulnTypeFilter").value;
        if (vulnType) p.set("vuln_type", vulnType);
        const pci = document.getElementById("qidPciFilter").value;
        if (pci) p.set("pci_flag", pci);
        const disc = document.getElementById("qidDiscoveryFilter").value;
        if (disc) p.set("discovery_method", disc);
        const cvssBase = document.getElementById("qidCvssBaseMin").value;
        if (cvssBase) p.set("cvss_base_min", cvssBase);
        const cvss3Base = document.getElementById("qidCvss3BaseMin").value;
        if (cvss3Base) p.set("cvss3_base_min", cvss3Base);
        const pubAfter = document.getElementById("qidPublishedAfter").value;
        if (pubAfter) p.set("published_after", pubAfter);
        const modAfter = document.getElementById("qidModifiedAfter").value;
        if (modAfter) p.set("modified_after", modAfter);
        const rti = ["qidRtiExploit","qidRtiMalware","qidRtiActiveAttack","qidRtiRansomware","qidRtiCisaKev"]
            .filter(id => document.getElementById(id).checked)
            .map(id => document.getElementById(id).value);
        if (rti.length) p.set("rti", rti.join(","));
        if (qidSupportedModulesMs) {
            const mods = qidSupportedModulesMs.getValues();
            if (mods.length) p.set("supported_modules", mods.join(","));
        }
    } else if (type === "cids") {
        const q = document.getElementById("cidSearchInput").value.trim();
        if (q) p.set("q", q);
        const crit = document.getElementById("cidCriticalityFilter").value;
        if (crit) p.set("criticality", crit);
        if (cidCategoryMs) {
            const vals = cidCategoryMs.getValues();
            if (vals.length) p.set("category", vals.join(","));
        }
        if (cidTechnologyMs) {
            const vals = cidTechnologyMs.getValues();
            if (vals.length) { p.set("technology", vals.join(",")); p.set("technology_mode", cidTechnologyMs.getMode()); }
        }
    } else if (type === "policies") {
        const q = document.getElementById("policySearchInput").value.trim();
        if (q) p.set("q", q);
        const status = document.getElementById("policyStatusFilter").value;
        if (status) p.set("status", status);
        if (policyCtrlCatMs) {
            const vals = policyCtrlCatMs.getValues();
            if (vals.length) { p.set("control_category", vals.join(",")); p.set("control_category_mode", policyCtrlCatMs.getMode()); }
        }
        if (policyTechMs) {
            const vals = policyTechMs.getValues();
            if (vals.length) { p.set("technology", vals.join(",")); p.set("technology_mode", policyTechMs.getMode()); }
        }
        if (policyCidMs) {
            const vals = policyCidMs.getValues();
            if (vals.length) { p.set("cid", vals.join(",")); p.set("cid_mode", policyCidMs.getMode()); }
        }
    } else if (type === "mandates") {
        const q = document.getElementById("mandateSearchInput").value.trim();
        if (q) p.set("q", q);
        if (mandatePublisherMs) {
            const vals = mandatePublisherMs.getValues();
            if (vals.length) p.set("publisher", vals.join(","));
        }
    }
    return p.toString();
}

function exportCSV(type) {
    const params = getFilterParams(type);
    window.open("/api/export/" + type + "/csv" + (params ? "?" + params : ""), "_blank");
}

function exportPDF(type) {
    const params = getFilterParams(type);
    window.open("/api/export/" + type + "/pdf" + (params ? "?" + params : ""), "_blank");
}

function exportMandateMap(mandateId) {
    const url = "/api/export/mandate-map/csv" + (mandateId ? "?mandate_id=" + mandateId : "");
    window.open(url, "_blank");
}

function _showExportButtons(type, total) {
    const el = document.getElementById(type + "ExportActions");
    if (el) el.style.display = total > 0 ? "inline-flex" : "none";
}
