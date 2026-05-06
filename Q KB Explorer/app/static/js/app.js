/* ─── Q KB Explorer — Frontend Logic ─── */
/* Adapted from Qualys API Engine by netsecops-76 */

let platforms = {};
let activeCredentialId = null;
let apiVersionPref = "v5";
let _savedCredentialCount = 0;
// Snapshot of {username, password, platform} for which testConnection
// last returned success. Cleared when any of those three change. Save
// is gated on this matching the current form to prevent saving creds
// that weren't actually verified against Qualys.
let _lastTestPassed = null;
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

// ── Server Health Detection ─────────────────────────────────────────────
let _serverUnresponsive = false;
const _API_TIMEOUT_MS = 30000; // 30s request timeout

function _showUnresponsiveBanner() {
    if (_serverUnresponsive) return;
    _serverUnresponsive = true;
    let banner = document.getElementById("serverUnresponsiveBanner");
    if (!banner) {
        banner = document.createElement("div");
        banner.id = "serverUnresponsiveBanner";
        banner.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:10000;background:#d32f2f;color:#fff;padding:10px 20px;display:flex;align-items:center;gap:12px;font-size:13px;font-weight:500;justify-content:center;";
        banner.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
            + '<span>Server is not responding. It may be restarting.</span>'
            + '<button onclick="_retryHealth()" style="background:#fff;color:#d32f2f;border:none;padding:4px 14px;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px;">Retry</button>'
            + '<button onclick="_dismissBanner()" style="background:transparent;color:#fff;border:1px solid rgba(255,255,255,0.5);padding:4px 14px;border-radius:4px;cursor:pointer;font-size:12px;">Dismiss</button>';
        document.body.prepend(banner);
    }
    banner.style.display = "flex";
}

function _dismissBanner() {
    const banner = document.getElementById("serverUnresponsiveBanner");
    if (banner) banner.style.display = "none";
    _serverUnresponsive = false;
}

async function _retryHealth() {
    try {
        const resp = await fetch("/api/health", { signal: AbortSignal.timeout(5000) });
        if (resp.ok) {
            _dismissBanner();
            showToast("Server is back online", "success");
            loadSyncStatus();
        }
    } catch (_) {
        showToast("Server still unresponsive — it may be restarting", "error");
    }
}

function _isAuthError(e) { return e && e._authRequired; }

async function apiFetch(url, options = {}) {
    // Merge CSRF header into all requests
    options.headers = Object.assign({ "X-Requested-With": "QKBE" }, options.headers || {});
    // Add timeout unless caller provides their own signal
    if (!options.signal) {
        options.signal = AbortSignal.timeout(_API_TIMEOUT_MS);
    }
    let resp;
    try {
        resp = await fetch(url, options);
    } catch (e) {
        if (e.name === "TimeoutError" || e.name === "AbortError") {
            _showUnresponsiveBanner();
        }
        throw e;
    }
    // Server responded — clear any unresponsive state
    if (_serverUnresponsive) _dismissBanner();
    if (resp.status === 401) {
        // /api/credentials/verify returns 401 on a wrong password — that's
        // an expected flow (the user mistyped, show them an error), not
        // a session-expired event. Don't re-show the auth modal for it,
        // or it'll clear the password input before the caller can render
        // its own error message. Same for the logout endpoint.
        const isAuthEndpoint = (
            url.indexOf("/api/credentials/verify") === 0 ||
            url.indexOf("/api/auth/") === 0
        );
        if (!isAuthEndpoint) {
            clearVaultState();
            try {
                const creds = await fetch("/api/credentials").then(r => r.json());
                if (Array.isArray(creds) && creds.length > 0) showVaultAuth(creds);
            } catch (e) { /* ignore */ }
            const authErr = new Error("Authentication required");
            authErr._authRequired = true;  // flag so callers can suppress toasts
            throw authErr;
        }
        // Auth endpoint returned 401 — let the caller handle it.
    }
    return resp;
}

// ── Total record counts per data type (updated from sync status) ────────
let _totalCounts = { qids: 0, cids: 0, policies: 0, mandates: 0, tags: 0, pm_patches: 0 };

// ── Track whether each tab has auto-loaded its first page ───────────────
let _tabLoaded = { dashboard: false, qids: false, cids: false, policies: false, mandates: false, intel: false, tags: false, help: false };

// ── In-flight request abort controllers for type-ahead ──────────────────
const _searchAbort = { qids: null, cids: null, policies: null, mandates: null, tags: null, pm_patches: null };

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
    tags: "tagSearchInput",
};
const _SHORTCUTS = {
    "1": { action: () => switchTab("dashboard"), desc: "Dashboard tab" },
    "2": { action: () => switchTab("qids"), desc: "QIDs tab" },
    "3": { action: () => switchTab("cids"), desc: "CIDs tab" },
    "4": { action: () => switchTab("policies"), desc: "Policies tab" },
    "5": { action: () => switchTab("mandates"), desc: "Mandates tab" },
    "6": { action: () => switchTab("intel"), desc: "Intelligence tab" },
    "7": { action: () => switchTab("tags"), desc: "Tags tab" },
    "8": { action: () => switchTab("settings"), desc: "Settings tab" },
    "9": { action: () => switchTab("help"), desc: "Help tab" },
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
    else if (type === "tags") { searchTags(); loadTagExports(); loadLibrary(); }
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
        // Opt-in callback fired after every selection change (select,
        // deselect, clear). Used by filters that should re-query on
        // pill change without a Search-button click. Mode toggles also
        // fire it so swapping AND/OR refreshes results.
        this.onChange = typeof opts.onChange === "function" ? opts.onChange : null;
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
            this._fireChange();
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
        this._fireChange();
    }

    _deselect(value) {
        this.selected = this.selected.filter(v => v !== value);
        // Auto-reset to OR when fewer than 2 items remain
        if (this.selected.length < 2) this.mode = "or";
        this._renderPills();
        this._updateToggle();
        this._renderDropdown();
        this._fireChange();
    }

    _fireChange() {
        if (!this.onChange) return;
        try { this.onChange(this.getValues(), this.getMode()); }
        catch (e) { console.error("MultiSelect onChange handler threw:", e); }
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

    clear(silent = false) {
        const had = this.selected.length > 0;
        this.selected = [];
        this.mode = "or";
        this.inputEl.value = "";
        this._renderPills();
        this._updateToggle();
        if (had && !silent) this._fireChange();
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
    // Await sync status so _totalCounts is populated BEFORE tab restore
    // triggers the active tab's data load — otherwise the count badge
    // shows 'Total: 0 | Found: N | 0.00%' for the brief window between
    // the search response and the sync_status response.
    await loadSyncStatus();
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
                _invalidateTestResult();
            }
        });
        pwField.addEventListener("input", function() {
            this.removeAttribute("data-vault-masked");
            activeCredentialId = null;
            _invalidateTestResult();
        });
    }
    const userField = document.getElementById("username");
    if (userField) {
        userField.addEventListener("input", function() {
            activeCredentialId = null;
            _invalidateTestResult();
        });
    }
    // Initial state — disable Save until a successful test or a vault
    // credential is loaded.
    _updateSaveButtonState();

    // Restore tab on refresh; on a fresh install (no saved credentials)
    // land on Settings so the user is pointed straight at the welcome tip.
    const savedTab = sessionStorage.getItem("qkbe_active_tab");
    if (savedTab && document.getElementById("tab-" + savedTab)) {
        switchTab(savedTab);
    } else if (_savedCredentialCount === 0) {
        switchTab("settings");
    } else {
        loadDashboard();
    }
    window.scrollTo(0, 0);

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

    // Tag filters — auto-apply on selection like the user/system
    // dropdown next to it, no Search-button click required.
    tagRuleTypeMs = new MultiSelect("tagRuleTypeMs", {
        placeholder: "Rule type...",
        showModeToggle: false,
        onChange: () => searchTags(),
    });

    // Load preloaded (non-server-search) filter values
    loadFilterOptions();
}

async function loadFilterOptions() {
    try {
        const [qidCats, cidCats, polCats, mandatePublishers, qidModules, tagRuleTypes] = await Promise.all([
            apiFetch("/api/qids/filter-values?field=categories").then(r => r.json()),
            apiFetch("/api/cids/filter-values?field=categories").then(r => r.json()),
            apiFetch("/api/policies/filter-values?field=control_categories").then(r => r.json()),
            apiFetch("/api/mandates/filter-values?field=publishers").then(r => r.json()),
            apiFetch("/api/qids/filter-values?field=supported_modules").then(r => r.json()),
            apiFetch("/api/tags/filter-values?field=rule_types").then(r => r.json()),
        ]);
        if (qidCategoryMs) qidCategoryMs.setItems(qidCats);
        if (qidSupportedModulesMs) qidSupportedModulesMs.setItems(qidModules);
        if (cidCategoryMs) cidCategoryMs.setItems(cidCats);
        if (policyCtrlCatMs) policyCtrlCatMs.setItems(polCats);
        if (mandatePublisherMs) mandatePublisherMs.setItems(mandatePublishers);
        if (tagRuleTypeMs) tagRuleTypeMs.setItems(Array.isArray(tagRuleTypes) ? tagRuleTypes : []);
        // Populate Intelligence category dropdown from QID categories
        const intelCat = document.getElementById("intelCategory");
        if (intelCat && Array.isArray(qidCats)) {
            intelCat.innerHTML = '<option value="">All Categories</option>'
                + qidCats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
        }
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
    // Changing platform changes the auth target, so any prior test result
    // no longer applies. loadCredential() also calls this when restoring a
    // saved credential — that's fine, the masked-password branch in
    // _updateSaveButtonState keeps Save enabled in that case.
    _invalidateTestResult();
}

// ─── Tab Switching ──────────────────────────────────────────────────────
function switchTab(tabName) {
    document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
    const content = document.getElementById("tab-" + tabName);
    const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (content) content.classList.add("active");
    if (btn) btn.classList.add("active");
    sessionStorage.setItem("qkbe_active_tab", tabName);
    window.scrollTo(0, 0);

    // Always reload data on tab visit so counters and cards reflect the
    // current DB state (e.g. after a sync completed in the background, or
    // when the user lands on a tab before the initial sync_status response
    // populates _totalCounts). Each loader handles its own empty state if
    // there's no data yet.
    _refreshActiveTab(tabName);
}

function _refreshActiveTab(tabName) {
    if (tabName === "dashboard") {
        _tabLoaded.dashboard = true;
        loadDashboard();
    } else if (tabName === "qids") {
        _tabLoaded.qids = true;
        searchQids();
    } else if (tabName === "cids") {
        _tabLoaded.cids = true;
        searchCids();
    } else if (tabName === "policies") {
        _tabLoaded.policies = true;
        searchPolicies();
    } else if (tabName === "mandates") {
        _tabLoaded.mandates = true;
        searchMandates();
    } else if (tabName === "tags") {
        _tabLoaded.tags = true;
        searchTags();
    } else if (tabName === "intel") {
        _tabLoaded.intel = true;
        runIntel();
    }
}

// ─── Tag Sub-tabs ───────────────────────────────────────────────────────
function switchTagSubTab(subtab) {
    document.querySelectorAll(".tag-subtab").forEach(el => el.classList.remove("active"));
    document.querySelectorAll("#tab-tags .sub-tab-btn").forEach(el => el.classList.remove("active"));
    const content = document.getElementById("tag-subtab-" + subtab);
    const btn = document.querySelector(`#tab-tags .sub-tab-btn[data-tagsubtab="${subtab}"]`);
    if (content) content.classList.add("active");
    if (btn) btn.classList.add("active");
    if (subtab === "library") loadLibrary();
    if (subtab === "migration") loadTagExports();
}

// ─── Policy Sub-tabs ────────────────────────────────────────────────────
function switchPolicySubTab(subtab) {
    document.querySelectorAll(".policy-subtab").forEach(el => el.classList.remove("active"));
    document.querySelectorAll("#tab-policies .sub-tab-btn").forEach(el => el.classList.remove("active"));
    const content = document.getElementById("policy-subtab-" + subtab);
    const btn = document.querySelector(`#tab-policies .sub-tab-btn[data-subtab="${subtab}"]`);
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
    // Suppress error toasts that are just "auth required" — the login
    // modal is already showing, a toast is redundant and confusing.
    if (type === "error" && typeof message === "string" &&
        message.toLowerCase().includes("authentication required")) return;
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = "toast " + type;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = "0"; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ─── Themed Confirm / Prompt (replaces native browser dialogs) ──────────
function themedConfirm(message) {
    return new Promise(resolve => {
        const overlay = document.createElement("div");
        overlay.className = "modal-overlay";
        overlay.style.zIndex = "99998";
        overlay.innerHTML = `<div class="modal-box" style="max-width:440px;">
            <div class="modal-header"><h2>Confirm</h2></div>
            <div style="padding:18px;font-size:13px;line-height:1.6;white-space:pre-wrap;color:var(--text-1);">${escapeHtml(message)}</div>
            <div class="modal-footer">
                <button class="btn-sm btn-outline" id="_tcCancel">Cancel</button>
                <button class="btn-sm btn-primary" id="_tcOk">OK</button>
            </div>
        </div>`;
        document.body.appendChild(overlay);
        overlay.querySelector("#_tcOk").onclick = () => { overlay.remove(); resolve(true); };
        overlay.querySelector("#_tcCancel").onclick = () => { overlay.remove(); resolve(false); };
        overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); resolve(false); } };
        overlay.querySelector("#_tcOk").focus();
    });
}

function themedPrompt(message, defaultValue = "") {
    return new Promise(resolve => {
        const overlay = document.createElement("div");
        overlay.className = "modal-overlay";
        overlay.style.zIndex = "99998";
        overlay.innerHTML = `<div class="modal-box" style="max-width:440px;">
            <div class="modal-header"><h2>Input</h2></div>
            <div style="padding:18px;">
                <p style="font-size:13px;color:var(--text-1);margin:0 0 10px 0;">${escapeHtml(message)}</p>
                <input type="text" id="_tpInput" value="${escapeHtml(defaultValue)}" style="width:100%;">
            </div>
            <div class="modal-footer">
                <button class="btn-sm btn-outline" id="_tpCancel">Cancel</button>
                <button class="btn-sm btn-primary" id="_tpOk">OK</button>
            </div>
        </div>`;
        document.body.appendChild(overlay);
        const input = overlay.querySelector("#_tpInput");
        input.focus();
        input.select();
        overlay.querySelector("#_tpOk").onclick = () => { overlay.remove(); resolve(input.value); };
        overlay.querySelector("#_tpCancel").onclick = () => { overlay.remove(); resolve(null); };
        input.onkeydown = (e) => { if (e.key === "Enter") { overlay.remove(); resolve(input.value); } };
        overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); resolve(null); } };
    });
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
    _savedCredentialCount = count;
    const el = document.getElementById("credVaultCount");
    el.textContent = count === 0 ? "No saved credentials" : count + " saved credential" + (count > 1 ? "s" : "");
    const tip = document.getElementById("settingsWelcomeTip");
    if (tip) tip.style.display = count === 0 ? "" : "none";
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

function _credSnapshot() {
    return {
        username: (document.getElementById("username").value || "").trim(),
        password: document.getElementById("password").value || "",
        platform: document.getElementById("platformSelect").value || "",
    };
}

function _credsMatchLastTest() {
    if (!_lastTestPassed) return false;
    const cur = _credSnapshot();
    return cur.username === _lastTestPassed.username
        && cur.password === _lastTestPassed.password
        && cur.platform === _lastTestPassed.platform;
}

function _invalidateTestResult() {
    _lastTestPassed = null;
    setConnected(false);
    _updateSaveButtonState();
}

function _updateSaveButtonState() {
    const btn = document.querySelector('button[onclick="saveCredential()"]');
    if (!btn) return;
    const pwField = document.getElementById("password");
    const isMasked = pwField && pwField.getAttribute("data-vault-masked") === "true";
    // Allow save if (a) editing an existing vaulted credential (masked
    // password — server already verified it), or (b) a successful test
    // exists for the exact values currently in the form.
    const allow = isMasked || _credsMatchLastTest();
    btn.disabled = !allow;
    btn.title = allow ? "" : "Test Connection must succeed for the current values before saving";
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
    // New-credential path: require a successful Test Connection against
    // the exact values currently in the form. Without this, a typo in
    // the username (or any other field) gets persisted to the vault and
    // every subsequent sync fails with confusing Qualys errors.
    if (!_credsMatchLastTest()) {
        showToast("Run Test Connection and have it succeed before saving", "error");
        _updateSaveButtonState();
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
        _updateSaveButtonState();
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
    _invalidateTestResult();
    saveSettings();
    showToast("Credentials cleared", "info");
}

// ─── Vault Auth Gate ────────────────────────────────────────────────────
function showVaultAuth(creds) {
    const modal = document.getElementById("vaultAuthModal");
    const select = document.getElementById("vaultAuthSelect");
    const pwField = document.getElementById("vaultAuthPassword");
    const wasOpen = modal && modal.style.display === "flex";
    // Repopulate the account list (safe — selects the same option by value)
    const prevSelected = select ? select.value : "";
    select.innerHTML = creds.map(c =>
        `<option value="${c.id}">${escapeHtml(formatCredLabelMasked(c))}</option>`
    ).join("");
    if (prevSelected && Array.from(select.options).some(o => o.value === prevSelected)) {
        select.value = prevSelected;
    }
    // Don't blow away an in-flight password attempt if the modal is
    // already showing — only reset on a fresh open.
    if (!wasOpen) {
        pwField.value = "";
        document.getElementById("vaultAuthError").style.display = "none";
    }
    modal.style.display = "flex";
    // Restore focus + caret position so any background re-show doesn't
    // steal the user's typing rhythm.
    if (wasOpen && document.activeElement !== pwField) pwField.focus();
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
    _invalidateTestResult();
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
            // Capture the exact form state that was just verified, so save
            // can later confirm the user didn't edit anything after testing.
            _lastTestPassed = _credSnapshot();
            showToast(result.message || "Connection successful", "success");
        } else {
            setConnected(false);
            _lastTestPassed = null;
            showToast(result.error || "Connection failed", "error");
        }
    } catch (e) {
        _lastTestPassed = null;
        showToast("Connection test failed: " + e.message, "error");
    } finally {
        hideLoading();
        _updateSaveButtonState();
    }
}

// ─── Sync Status ────────────────────────────────────────────────────────
async function loadSyncStatus() {
    try {
        const resp = await apiFetch("/api/sync/status");
        const status = await resp.json();

        // Build credential lookup map for displaying usernames on sync cards
        let credMap = {};
        try {
            const credResp = await fetch("/api/credentials");
            const creds = await credResp.json();
            if (Array.isArray(creds)) creds.forEach(c => { credMap[c.id] = c; });
        } catch (_) {}

        updateSyncDisplay("Qid", status.qids, credMap);
        updateSyncDisplay("Cid", status.cids, credMap);
        updateSyncDisplay("Policy", status.policies, credMap);
        updateSyncDisplay("Tag", status.tags, credMap);
        updateSyncDisplay("Pm_patches", status.pm_patches, credMap);
        updateMandateSyncDisplay(status.mandates, status.cids, credMap);

        // Auto-attach to any sync that was already running on the
        // backend before the user landed on this page (e.g. after a
        // browser reload mid-sync, or after clicking Refresh while a
        // sync is in flight). Without this the progress bar stays
        // hidden and the user assumes the sync is dead, even though
        // the worker thread is still happily writing pages to SQLite.
        ["qids", "cids", "policies", "tags", "pm_patches"].forEach(t => {
            const s = status[t];
            if (s && s.syncing) _attachPoller(t);
        });

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

        // Refresh whichever data tab is currently active so its cards and
        // counters reflect the just-loaded totals. Handles two cases:
        //   1. Initial page load — user lands on a tab before the first
        //      sync_status response arrives, so the auto-load couldn't
        //      run with accurate _totalCounts.
        //   2. Sync completion — pollSyncProgress calls loadSyncStatus
        //      after a sync finishes; this picks up the fresh data on
        //      whichever tab the user is looking at.
        const activeTabBtn = document.querySelector(".tab-btn.active");
        const activeTabName = activeTabBtn ? activeTabBtn.dataset.tab : null;
        if (activeTabName) {
            _refreshActiveTab(activeTabName);
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
    // Load maintenance config
    loadMaintenanceConfig();
    // Load auto-update config
    loadAutoUpdateConfig();
    // Load build ID for About section
    _loadBuildId();
}

async function _loadBuildId() {
    try {
        const resp = await apiFetch("/api/update/version");
        const data = await resp.json();
        const el = document.getElementById("aboutBuildId");
        if (el) el.textContent = data.version ? data.version.slice(0, 8) : "dev";
    } catch (_) {
        const el = document.getElementById("aboutBuildId");
        if (el) el.textContent = "dev";
    }
}

// ── Database Maintenance Config ─────────────────────────────────────────
async function loadMaintenanceConfig() {
    try {
        const resp = await apiFetch("/api/maintenance/config");
        const config = await resp.json();

        // Populate UI
        const dayEl = document.getElementById("maintDay");
        const timeEl = document.getElementById("maintTime");
        const tzEl = document.getElementById("maintTzDisplay");
        const statusEl = document.getElementById("maintStatus");
        const nextEl = document.getElementById("maintNextRun");

        if (dayEl) dayEl.value = config.day_of_week || 0;
        const h = String(config.hour || 0).padStart(2, "0");
        const m = String(config.minute || 0).padStart(2, "0");
        if (timeEl) timeEl.value = h + ":" + m;

        const tz = config.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone;
        if (tzEl) tzEl.textContent = tz;

        // Last run status
        if (statusEl) {
            if (config.last_run && config.last_status) {
                const date = new Date(config.last_run).toLocaleString();
                const dur = config.last_duration_s ? " · " + config.last_duration_s + "s" : "";
                const statusText = config.last_status === "ok" ? "OK" : "ERROR";
                const statusColor = config.last_status === "ok" ? "var(--green)" : "var(--red, #d32f2f)";
                let info = "Last run: " + date + " · <span style='color:" + statusColor + ";font-weight:600;'>" + statusText + "</span>" + dur;
                if (config.backup) {
                    const bSize = (config.backup.size / 1048576).toFixed(1);
                    info += " · Backup: " + config.backup.path + " (" + bSize + " MB)";
                }
                statusEl.innerHTML = info;
            } else {
                statusEl.textContent = "No maintenance runs yet";
            }
        }

        // Next run
        if (nextEl && config.next_run && config.next_run.next_run_local) {
            nextEl.textContent = "Next run: " + config.next_run.next_run_local;
        } else if (nextEl) {
            nextEl.textContent = "";
        }

        // Show failure banner if last run failed
        if (config.last_status === "error") {
            _showMaintenanceFailureBanner(config.last_error || "Unknown error");
        }
    } catch (e) {
        // Maintenance endpoint may not exist yet
    }
}

function _showMaintenanceFailureBanner(error) {
    let banner = document.getElementById("maintenanceFailureBanner");
    if (banner) { banner.style.display = "flex"; return; }
    banner = document.createElement("div");
    banner.id = "maintenanceFailureBanner";
    banner.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;background:#e65100;color:#fff;padding:10px 20px;display:flex;align-items:center;gap:12px;font-size:13px;font-weight:500;justify-content:center;flex-wrap:wrap;";
    banner.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
        + '<span>Database maintenance failed: ' + error.replace(/</g, "&lt;") + '</span>'
        + '<button onclick="_restoreFromBackup()" style="background:#fff;color:#e65100;border:none;padding:4px 14px;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px;">Restore from Backup</button>'
        + '<button onclick="this.parentElement.style.display=\'none\'" style="background:transparent;color:#fff;border:1px solid rgba(255,255,255,0.5);padding:4px 14px;border-radius:4px;cursor:pointer;font-size:12px;">Dismiss</button>';
    document.body.prepend(banner);
}

async function _restoreFromBackup() {
    if (!await themedConfirm("Restore the database from the last backup? This will replace the current database.")) return;
    try {
        const resp = await apiFetch("/api/maintenance/restore", {
            method: "POST", headers: { "Content-Type": "application/json" },
        });
        const result = await resp.json();
        if (result.status === "ok") {
            showToast("Database restored from backup", "success");
            const banner = document.getElementById("maintenanceFailureBanner");
            if (banner) banner.style.display = "none";
            loadSyncStatus();
        } else {
            showToast("Restore failed: " + (result.error || "Unknown"), "error");
        }
    } catch (e) {
        showToast("Restore failed: " + e.message, "error");
    }
}

async function saveMaintenanceConfig() {
    const day = parseInt(document.getElementById("maintDay").value);
    const timeParts = (document.getElementById("maintTime").value || "00:00").split(":");
    const hour = parseInt(timeParts[0]) || 0;
    const minute = parseInt(timeParts[1]) || 0;
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    try {
        const resp = await apiFetch("/api/maintenance/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ day_of_week: day, hour, minute, timezone: tz }),
        });
        const config = await resp.json();
        showToast("Maintenance schedule saved", "success");
        loadMaintenanceConfig();
    } catch (e) {
        showToast("Failed to save: " + e.message, "error");
    }
}

// ── Application Updates ─────────────────────────────────────────────────
async function checkForUpdates() {
    const statusEl = document.getElementById("updateStatus");
    const actionsEl = document.getElementById("updateActions");
    const checkBtn = document.getElementById("updateCheckBtn");
    checkBtn.disabled = true;
    checkBtn.textContent = "Checking...";
    statusEl.innerHTML = '<span style="opacity:0.7;">Checking GitHub for updates...</span>';
    actionsEl.style.display = "none";

    try {
        const resp = await apiFetch("/api/update/check");
        const data = await resp.json();

        if (data.error) {
            statusEl.innerHTML = '<span style="color:var(--red,#d32f2f);">Check failed: ' + escapeHtml(data.error) + '</span>';
        } else if (data.update_available) {
            const date = new Date(data.latest_date).toLocaleString();
            const behind = data.commits_behind ? " (" + data.commits_behind + " commits behind)" : "";
            statusEl.innerHTML = '<span style="color:var(--orange,#e65100);font-weight:600;">Update available!</span>'
                + '<br><span style="font-size:12px;opacity:0.8;">Latest: ' + escapeHtml(data.latest_short)
                + ' — ' + escapeHtml(data.latest_message)
                + '<br>' + date + behind + '</span>';
            if (data.current) {
                statusEl.innerHTML += '<br><span style="font-size:12px;opacity:0.6;">Current: ' + data.current.slice(0, 8) + '</span>';
            }
            actionsEl.style.display = "";
        } else {
            statusEl.innerHTML = '<span style="color:var(--green);font-weight:600;">Up to date</span>'
                + '<span style="font-size:12px;opacity:0.7;margin-left:8px;">Version: '
                + (data.current ? data.current.slice(0, 8) : "unknown") + '</span>';
        }
    } catch (e) {
        statusEl.innerHTML = '<span style="color:var(--red,#d32f2f);">Check failed: ' + escapeHtml(e.message) + '</span>';
    }
    checkBtn.disabled = false;
    checkBtn.textContent = "Check for Updates";
}

async function applyUpdate() {
    if (!await themedConfirm("Apply the latest update? The application will restart after updating.")) return;
    const statusEl = document.getElementById("updateStatus");
    const actionsEl = document.getElementById("updateActions");
    const applyBtn = document.getElementById("updateApplyBtn");
    applyBtn.disabled = true;
    applyBtn.textContent = "Updating...";
    statusEl.innerHTML = '<span style="opacity:0.7;">Downloading and applying update... This may take a minute.</span>';

    try {
        const resp = await apiFetch("/api/update/apply", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            signal: AbortSignal.timeout(120000),  // 2 min timeout for update
        });
        const data = await resp.json();
        if (data.status === "ok") {
            statusEl.innerHTML = '<span style="color:var(--green);font-weight:600;">Update applied!</span>'
                + '<br><span style="font-size:12px;">Version: ' + (data.version_short || "—")
                + ' · ' + escapeHtml(data.message || "")
                + '<br>Duration: ' + (data.duration_s || "—") + 's'
                + '<br>The application is restarting. Refresh the page in a few seconds.</span>';
            actionsEl.style.display = "none";
            showToast("Update applied — waiting for server to restart...", "success");
            // Wait for server to come back, then hard reload
            const _waitForServer = async (attempt) => {
                if (attempt > 10) { statusEl.innerHTML += '<br>Server is taking longer than expected. Please refresh manually.'; return; }
                try {
                    const h = await fetch("/api/health", { signal: AbortSignal.timeout(3000) });
                    if (h.ok) { sessionStorage.removeItem("qkbe_active_tab"); window.location.reload(); return; }
                } catch (_) {}
                setTimeout(() => _waitForServer(attempt + 1), 2000);
            };
            setTimeout(() => _waitForServer(1), 3000);
        } else {
            statusEl.innerHTML = '<span style="color:var(--red,#d32f2f);font-weight:600;">Update failed</span>'
                + '<br><span style="font-size:12px;">' + escapeHtml(data.error || "Unknown error") + '</span>';
            showToast("Update failed: " + (data.error || "Unknown"), "error");
        }
    } catch (e) {
        statusEl.innerHTML = '<span style="color:var(--red,#d32f2f);">Update failed: ' + escapeHtml(e.message) + '</span>';
    }
    applyBtn.disabled = false;
    applyBtn.textContent = "Update Now";
}

// ── Auto-Update Schedule ─────────────────────────────────────────────────
function toggleAutoUpdateSettings() {
    const enabled = document.getElementById("autoUpdateEnabled").checked;
    const settings = document.getElementById("autoUpdateSettings");
    if (settings) settings.style.display = enabled ? "" : "none";
    if (!enabled) {
        // Save disabled state immediately
        saveAutoUpdateConfig();
    }
}

async function loadAutoUpdateConfig() {
    try {
        const resp = await apiFetch("/api/update/schedule");
        const config = await resp.json();

        const enabledEl = document.getElementById("autoUpdateEnabled");
        const dayEl = document.getElementById("autoUpdateDay");
        const timeEl = document.getElementById("autoUpdateTime");
        const tzEl = document.getElementById("autoUpdateTzDisplay");
        const statusEl = document.getElementById("autoUpdateStatus");
        const nextEl = document.getElementById("autoUpdateNextRun");
        const settingsEl = document.getElementById("autoUpdateSettings");

        const isEnabled = !!config.enabled;
        if (enabledEl) enabledEl.checked = isEnabled;
        if (settingsEl) settingsEl.style.display = isEnabled ? "" : "none";

        if (dayEl) dayEl.value = config.day_of_week ?? 6;
        const h = String(config.hour ?? 0).padStart(2, "0");
        const m = String(config.minute ?? 0).padStart(2, "0");
        if (timeEl) timeEl.value = h + ":" + m;

        const tz = config.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone;
        if (tzEl) tzEl.textContent = tz;

        // Last check status
        if (statusEl) {
            if (config.last_check && config.last_status) {
                const date = new Date(config.last_check).toLocaleString();
                const labels = { up_to_date: "Up to date", updated: "Updated", error: "Error" };
                const colors = { up_to_date: "var(--green)", updated: "var(--green)", error: "var(--red, #d32f2f)" };
                const label = labels[config.last_status] || config.last_status;
                const color = colors[config.last_status] || "inherit";
                let info = "Last check: " + date + " · <span style='color:" + color + ";font-weight:600;'>" + label + "</span>";
                if (config.last_error) info += " · " + escapeHtml(config.last_error);
                statusEl.innerHTML = info;
            } else {
                statusEl.textContent = "No automatic update checks yet";
            }
        }

        // Next run
        if (nextEl && config.next_run_local) {
            nextEl.textContent = "Next check: " + config.next_run_local;
        } else if (nextEl) {
            nextEl.textContent = "";
        }
    } catch (e) {
        // Auto-update schedule endpoint may not exist
    }
}

async function saveAutoUpdateConfig() {
    const enabled = document.getElementById("autoUpdateEnabled").checked;
    const day = parseInt(document.getElementById("autoUpdateDay").value);
    const timeParts = (document.getElementById("autoUpdateTime").value || "00:00").split(":");
    const hour = parseInt(timeParts[0]) || 0;
    const minute = parseInt(timeParts[1]) || 0;
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    try {
        const resp = await apiFetch("/api/update/schedule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled, day_of_week: day, hour, minute, timezone: tz }),
        });
        const config = await resp.json();
        showToast(enabled ? "Auto-update schedule saved" : "Auto-updates disabled", "success");
        loadAutoUpdateConfig();
    } catch (e) {
        showToast("Failed to save: " + e.message, "error");
    }
}

// ── GitHub Issue Submission ──────────────────────────────────────────────
function submitGitHubIssue() {
    const typeRadio = document.querySelector('input[name="issueType"]:checked');
    const type = typeRadio ? typeRadio.value : "bug";
    const title = document.getElementById("issueTitle").value.trim();
    const body = document.getElementById("issueBody").value.trim();
    const contact = (document.getElementById("issueContact") || {}).value || "";

    if (!title) { showToast("Please enter a title", "error"); return; }

    const label = type === "bug" ? "bug" : "enhancement";
    const prefix = type === "bug" ? "[Bug] " : "[Feature] ";
    const buildId = (document.getElementById("aboutBuildId") || {}).textContent || "unknown";

    let template = body;
    template += "\n\n---\n**Environment:**";
    template += "\n- Q KB Explorer build: `" + buildId + "`";
    template += "\n- Browser: " + navigator.userAgent.split(" ").slice(-2).join(" ");
    if (contact.trim()) {
        template += "\n\n**Contact:** " + contact.trim();
    }

    const params = new URLSearchParams({
        title: prefix + title,
        body: template,
        labels: label,
    });

    const url = "https://github.com/netsecops-76/Public-Security-Resources/issues/new?" + params.toString();
    window.open(url, "_blank");

    // Clear form
    document.getElementById("issueTitle").value = "";
    document.getElementById("issueBody").value = "";
    if (document.getElementById("issueContact")) document.getElementById("issueContact").value = "";
    showToast("GitHub issue page opened — submit in the new tab", "info");
}

// Map display type → data type key for _totalCounts
const _typeToDataKey = { "Qid": "qids", "Cid": "cids", "Policy": "policies", "Mandate": "mandates", "Tag": "tags", "Pm_patches": "pm_patches" };
// Reverse map: API data type → display key for updateSyncDisplay()
const _dataKeyToDisplay = { "qids": "Qid", "cids": "Cid", "policies": "Policy", "mandates": "Mandate", "tags": "Tag", "pm_patches": "Pm_patches" };

function updateSyncDisplay(type, state, credMap) {
    const metaEl = document.getElementById("sync" + type + "Meta");
    const countEl = document.getElementById(type.toLowerCase() + "Count");
    const dataKey = _typeToDataKey[type] || type.toLowerCase() + "s";
    // `syncing` is set by /api/sync/status whenever the worker thread
    // for this type is alive. last_sync is only populated AFTER a sync
    // completes, so during a long-running sync (e.g. a QID full sync
    // that takes 10–20 min) last_sync is null. Without this guard the
    // null branch below fires the misleading "watermark missing —
    // re-sync to refresh" message while the sync is happily progressing.
    //
    // Belt + suspenders: also fall back to the per-type _activePollers
    // set, which carries the local "we know a sync is in flight" signal
    // even if /api/sync/status's view of the worker thread is briefly
    // stale (e.g. during the tiny window between trigger_sync queueing
    // and the loadSyncStatus refetch).
    const dataType = _typeToDataKey[type] || type.toLowerCase() + "s";
    const isSyncingNow = !!(state && state.syncing)
                       || (typeof _activePollers !== "undefined"
                           && _activePollers && _activePollers.has(dataType));
    if (!state || !state.last_sync) {
        const liveCount = (state && state.record_count) || 0;
        _totalCounts[dataKey] = liveCount;
        if (metaEl) {
            if (isSyncingNow) {
                // Mid-sync (no completed sync yet, or full-sync purge
                // just cleared the watermark). Surface live count and
                // a clear "running" hint instead of asking the user
                // to re-sync.
                metaEl.textContent = (liveCount > 0
                    ? liveCount.toLocaleString() + " records loaded so far · Sync in progress…"
                    : "Sync in progress…");
            } else if (liveCount > 0) {
                // Records are present but no completed-sync watermark.
                // Most plausible explanation is "previous sync errored
                // mid-flight"; re-sync clears + repopulates. Soften
                // wording so it doesn't sound like data corruption.
                metaEl.textContent = liveCount.toLocaleString()
                    + " records · Last sync didn't finish — re-sync to refresh the watermark";
            } else {
                metaEl.textContent = "Not synced";
            }
        }
        if (countEl) countEl.textContent = "Total: " + liveCount.toLocaleString();
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
    // Show which credential (user) was used
    if (state.credential_id && credMap) {
        const cred = credMap[state.credential_id];
        if (cred) meta += " \u00B7 " + formatCredLabel(cred);
    }
    // Persisted missing count (from full-sync / backfill verification).
    // Skip when null \u2014 that means no verifying sync has run yet, so we
    // don't have a number to show. Skip when 0 to keep the row tidy.
    if (typeof state.last_missing_count === "number" && state.last_missing_count > 0) {
        meta += " \u00B7 " + state.last_missing_count.toLocaleString() + " missing";
    }
    // If a worker thread is currently running for this type (Delta or
    // Backfill on top of an existing watermark), suffix the meta so the
    // user sees "...syncing now" rather than wondering why the progress
    // bar is moving but the row says "Last sync: yesterday".
    if (isSyncingNow) {
        meta += " \u00B7 \u23F1 syncing now";
    }
    metaEl.textContent = meta;
    if (countEl) countEl.textContent = "Total: " + count.toLocaleString();

    // Backfill Missing button visibility (QIDs only). Hide it once we
    // know nothing is missing — otherwise users keep clicking a no-op.
    // Show on null (unknown) so the button is available before any
    // verifying sync has run.
    if (type === "Qid") {
        const btn = document.getElementById("backfillQidsBtn");
        if (btn) {
            const missing = state.last_missing_count;
            const hasFull = !!state.last_full_sync;
            const knownClean = missing === 0 && hasFull;
            btn.style.display = knownClean ? "none" : "";
            if (typeof missing === "number" && missing > 0) {
                btn.textContent = "Backfill Missing (" + missing.toLocaleString() + ")";
                btn.title = missing.toLocaleString() + " QIDs in Qualys are not in your local DB — click to fetch only those.";
            } else {
                btn.textContent = "Backfill Missing";
                btn.title = "Pull only QIDs the local DB is missing — no purge, no full re-pull";
            }
        }
    }
}

function updateMandateSyncDisplay(mandateState, cidState, credMap) {
    const metaEl = document.getElementById("syncMandateMeta");
    const countEl = document.getElementById("mandateCount");
    const count = (mandateState && mandateState.record_count) || 0;
    _totalCounts.mandates = count;

    // Mandates are extracted during CID sync (upsert_control → _extract_mandates_for_cid).
    // Use the more recent of CID sync or mandate sync as the "last updated" date,
    // since either operation updates mandate data.
    const mandateTs = mandateState && mandateState.last_sync ? new Date(mandateState.last_sync) : null;
    const cidTs = cidState && cidState.last_sync ? new Date(cidState.last_sync) : null;
    const lastUpdated = (mandateTs && cidTs) ? (cidTs > mandateTs ? cidTs : mandateTs)
                      : (cidTs || mandateTs);

    if (count > 0 && lastUpdated) {
        const date = lastUpdated.toLocaleString();
        let meta = count.toLocaleString() + " frameworks \u00B7 Last updated: " + date;
        // Show which credential was used (from CID sync since that's the source)
        const credId = cidState && cidState.credential_id ? cidState.credential_id
                     : (mandateState && mandateState.credential_id);
        if (credId && credMap) {
            const cred = credMap[credId];
            if (cred) meta += " \u00B7 " + formatCredLabel(cred);
        }
        metaEl.textContent = meta;
    } else if (cidState && cidState.last_sync && count === 0) {
        metaEl.textContent = "No frameworks found in CID data \u00B7 Try a CID Full Sync";
    } else if (!cidState || !cidState.last_sync) {
        metaEl.textContent = "Sync CIDs first \u2014 mandates are extracted from CID data";
    } else {
        metaEl.textContent = "Extracted automatically during CID sync";
    }
    if (countEl) countEl.textContent = "Total: " + count.toLocaleString();
}

function updateCountBadge(prefix, foundCount) {
    // prefix: "qid", "cid", "policy", "mandate", "tag"
    const dataKey = prefix === "qid" ? "qids" : prefix === "cid" ? "cids" : prefix === "mandate" ? "mandates" : prefix === "tag" ? "tags" : "policies";
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
const SYNC_TIMEOUTS = { qids: 600, cids: 300, policies: 300, mandates: 300, tags: 300, pm_patches: 600 };

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

async function triggerBackfill(type) {
    // Backfill = no purge, fetch only IDs the DB is missing.
    // Reuses _executeSyncInternal so progress bar / queue / mutex
    // semantics are identical to a normal sync.
    if (!activeCredentialId) {
        showToast("Save credentials first in Settings", "error");
        switchTab("settings");
        return;
    }
    showToast(type.toUpperCase() + " backfill started — only missing IDs will be fetched.", "info");
    _executeSyncInternal(type, false, /* backfill */ true);
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
        const labels = { qids: "QID (Knowledge Base)", cids: "CID (Controls)", policies: "Policy", mandates: "Mandate", tags: "Tag", pm_patches: "PM Patch Catalog" };
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

async function _executeSyncInternal(type, full, backfill) {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a Qualys platform first", "error"); return; }

    const label = backfill ? "Backfill" : (full ? "Full sync" : "Delta sync");

    // Full sync purges all data — clear the status card and browse tab
    // immediately so the user doesn't see stale data while re-downloading.
    // Pass a synthetic syncing state instead of null so the meta line
    // says "Sync in progress…" right away, before the first
    // /api/sync/status round-trip lands.
    if (full) {
        const displayKey = _dataKeyToDisplay[type];
        if (displayKey) updateSyncDisplay(displayKey, {syncing: true, record_count: 0});
        const containerMap = {qids: "qidResults", cids: "cidResults", policies: "policyResults", tags: "tagResults"};
        const badgeKeyMap = {qids: "qid", cids: "cid", policies: "policy", tags: "tag"};
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
            body: JSON.stringify({ ...auth, full, backfill: !!backfill }),
        });
        const result = await resp.json();
        if (result.error) {
            clearInterval(countdownInterval);
            showToast(result.error, "error");
            textEl.textContent = "Error: " + result.error;
            fillEl.className = "sync-progress-fill error";
            fillEl.style.width = "100%";
        } else if (result.queued) {
            // Another sync is running. Backend has enqueued this one and
            // will start it automatically when the current sync finishes.
            showToast(
                (result.message || (type.toUpperCase() + " queued — will start after the current sync finishes.")),
                "info"
            );
            textEl.textContent = "Queued — waiting for "
                + (result.running_now || "current sync")
                + " to finish (position " + (result.queue_position || "?") + ")";
            fillEl.className = "sync-progress-fill queued";
            fillEl.style.width = "100%";
            pollSyncProgress(type);
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

// Per-type poll-attached guard so loadSyncStatus()'s auto-resume can't
// spawn duplicate pollers when the user clicks Refresh repeatedly
// while a sync is in flight.
const _activePollers = new Set();

function _attachPoller(type) {
    if (_activePollers.has(type)) return;          // already polling
    const typeKey = type.charAt(0).toUpperCase() + type.slice(1);
    const progressEl = document.getElementById("syncProgress" + typeKey);
    if (!progressEl) return;
    // Make the progress bar visible — _executeSyncInternal would have
    // done this if the user clicked the button on this tab, but
    // auto-resume is exactly the case where they didn't.
    progressEl.style.display = "flex";
    const fillEl = document.getElementById("syncFill" + typeKey);
    if (fillEl && !fillEl.className) {
        fillEl.className = "sync-progress-fill indeterminate";
    }
    pollSyncProgress(type);
}

async function pollSyncProgress(type) {
    if (_activePollers.has(type)) return;
    _activePollers.add(type);
    const typeKey = type.charAt(0).toUpperCase() + type.slice(1);
    const progressEl = document.getElementById("syncProgress" + typeKey);
    const textEl = document.getElementById("syncText" + typeKey);
    const fillEl = document.getElementById("syncFill" + typeKey);
    const countdownId = parseInt(progressEl.dataset.countdownId || "0");

    // Stuck detection looks at *any* progress-relevant field, not just
    // items_synced. During the pre-count phase items_synced stays 0
    // while count_chunks_done climbs, and during a single big chunk
    // pages_fetched / expected_total may be the only things moving.
    // Watching the whole snapshot avoids false alarms during those
    // legitimate-but-slow phases.
    let _lastProgressKey = "";
    let _lastProgressTime = Date.now();
    // 10 minutes — large QID chunks plus rate-limit Retry-After waits
    // can legitimately exceed 5 min even on a healthy sync. The wording
    // also softens: "no recent progress, tool is still running" rather
    // than "may be stuck — restart container".
    const _STUCK_THRESHOLD_MS = 600000;
    let _stuckWarned = false;
    // Refresh the sync-row meta line every ~20s while a sync runs so
    // it stays in sync with the live state. Without this the row says
    // "Sync in progress…" until the sync completes — fine, but the
    // record_count under it stays stale until completion. A periodic
    // /api/sync/status fetch keeps the count moving in real time.
    const _META_REFRESH_EVERY_POLLS = 10;  // ~20s @ 2s poll interval
    let _metaRefreshCount = 0;

    const poll = async () => {
        try {
            const resp = await apiFetch("/api/sync/" + type + "/progress");
            const p = await resp.json();
            if (p.running) {
                // Make the progress label clickable while a sync is
                // running so users can open the live event ticker
                // ("peek under the hood"). Set once per poll cycle —
                // cheap idempotent reattach.
                textEl.classList.add("sync-progress-peek");
                textEl.title = "Click to see live activity";
                textEl.onclick = () => openSyncTicker(type);
                // Periodically refresh the sync-row meta line so the
                // record count + "Sync in progress…" hint reflects
                // current backend state, not the snapshot from when
                // the click happened.
                _metaRefreshCount++;
                if (_metaRefreshCount >= _META_REFRESH_EVERY_POLLS) {
                    _metaRefreshCount = 0;
                    loadSyncStatus();
                }
                // Queued — waiting on the global sync mutex. Show that
                // explicitly so the user doesn't think we're stalled.
                if (p.status === "queued") {
                    if (countdownId) { clearInterval(countdownId); progressEl.dataset.countdownId = "0"; }
                    fillEl.className = "sync-progress-fill queued";
                    fillEl.style.width = "100%";
                    const runningNow = p.running_now || "current sync";
                    const pos = p.queue_position || "?";
                    textEl.textContent = "Queued — waiting for " + runningNow
                                       + " to finish (position " + pos + ")";
                    setTimeout(poll, 2000);
                    return;
                }
                // Stuck detection: any progress-relevant field changing
                // is enough to count as live activity. Just watching
                // items_synced false-fires during the pre-count phase
                // (where count_chunks_done climbs but items_synced
                // stays 0) and during processing of a single large
                // chunk (where pages_fetched is the only thing moving).
                const progressKey = [
                    p.items_synced || 0,
                    p.pages_fetched || 0,
                    p.count_chunks_done || 0,
                    p.count_pages_done || 0,
                    p.expected_total || 0,
                    p.status || "",
                ].join("|");
                if (progressKey !== _lastProgressKey) {
                    _lastProgressKey = progressKey;
                    _lastProgressTime = Date.now();
                    _stuckWarned = false;
                } else if (!_stuckWarned && (Date.now() - _lastProgressTime) > _STUCK_THRESHOLD_MS) {
                    _stuckWarned = true;
                    // Soft wording — the most common cause is a large
                    // chunk being processed or a Retry-After rate-limit
                    // pause. The tool is still running; pushing users
                    // toward "restart the container" was wrong advice.
                    textEl.textContent += " ⓘ No recent progress event — sync still running, likely on a slow Qualys response or a rate-limit retry.";
                    showToast(
                        type.toUpperCase() + " sync hasn't emitted a progress event in 10 minutes. " +
                        "The tool is still running — large pages and rate-limit retries can each take several minutes. " +
                        "Check the sync log for details if you're concerned; only restart if the log is also silent.",
                        "info"
                    );
                }
                // Pre-count phase — applies to qids/cids/policies/tags/
                // pm_patches. The label and progress fraction adapt to
                // whichever shape the backend reports:
                //   - count_chunks_done / count_chunks_total (QIDs, paged)
                //   - count_pages_done (CIDs, Policies, Tags by paging)
                //   - just expected_total (Tags via single QPS count call)
                if (p.status === "counting") {
                    if (countdownId) { clearInterval(countdownId); progressEl.dataset.countdownId = "0"; }
                    fillEl.classList.remove("indeterminate");
                    const found = (p.expected_total || 0).toLocaleString();
                    const noun = type === "qids" ? "QIDs"
                              : type === "cids" ? "CIDs"
                              : type === "policies" ? "policies"
                              : type === "tags" ? "tags"
                              : type === "pm_patches" ? "PM patches"
                              : "records";
                    let detail = "";
                    let cpct = 7;  // default mid-progress for single-call counts
                    if (p.count_chunks_total) {
                        const cdone = p.count_chunks_done || 0;
                        const ctot = p.count_chunks_total;
                        detail = " in " + cdone + "/" + ctot + " chunks scanned";
                        cpct = Math.min(15, (cdone / ctot) * 15);
                    } else if (p.count_pages_done) {
                        detail = " across " + p.count_pages_done + " pages scanned";
                        cpct = Math.min(15, p.count_pages_done * 1.5);
                    } else if (p.expected_total) {
                        detail = " (count complete)";
                        cpct = 15;
                    }
                    textEl.textContent = "Counting " + noun + "... " + found + " found" + detail;
                    fillEl.style.width = cpct.toFixed(1) + "%";
                    setTimeout(poll, 2000);
                    return;
                }
                // Live progress update — data is flowing
                if (p.items_synced !== undefined && p.items_synced > 0) {
                    // Data arrived — stop countdown, show live counter
                    if (countdownId) { clearInterval(countdownId); progressEl.dataset.countdownId = "0"; }
                    const count = p.items_synced.toLocaleString();
                    const pages = p.pages_fetched || 0;
                    if (p.status === "enriching" && p.enrich_total) {
                        // Per-tag GET enrichment phase (Tags sync only)
                        const done = (p.enrich_done || 0).toLocaleString();
                        const tot = (p.enrich_total || 0).toLocaleString();
                        textEl.textContent = count + " tags synced — enriching details " + done + "/" + tot + "...";
                        fillEl.classList.remove("indeterminate");
                        const enrichPct = (p.enrich_done && p.enrich_total)
                            ? (p.enrich_done / p.enrich_total) * 100
                            : 0;
                        // Cap visual at 99% during enrichment so the bar
                        // hits 100% only when the sync truly completes.
                        fillEl.style.width = Math.min(99, enrichPct).toFixed(1) + "%";
                    } else if (p.status === "processing" && p.processing_item !== undefined) {
                        // Per-control processing phase
                        const procItem = p.processing_item.toLocaleString();
                        const procTotal = (p.processing_total || 0).toLocaleString();
                        textEl.textContent = count + " synced — processing " + procItem + "/" + procTotal + " on page " + pages;
                    } else if (p.expected_total && p.expected_total > 0) {
                        // We know the exact denominator from the pre-count
                        // pass — show real progress with both numerator and
                        // expected total.
                        const exp = p.expected_total.toLocaleString();
                        const realPct = (p.items_synced / p.expected_total * 100).toFixed(1);
                        textEl.textContent = count + " / " + exp
                            + " records synced (page " + pages + ") — " + realPct + "%";
                    } else {
                        textEl.textContent = count + " records synced (page " + pages + ") — waiting for API...";
                    }
                    fillEl.classList.remove("indeterminate");
                    let pct;
                    if (p.expected_total && p.expected_total > 0) {
                        // Map detail-fetch progress into 15-99% so the
                        // pre-count's 0-15% reservation isn't clobbered.
                        const ratio = p.items_synced / p.expected_total;
                        pct = 15 + Math.min(84, ratio * 84);
                    } else {
                        const est = type === "qids" ? 100000 : type === "cids" ? 30000 : type === "mandates" ? 500 : 500;
                        pct = Math.min(95, (p.items_synced / est) * 100);
                    }
                    if (p.status !== "enriching") {
                        // Enriching set its own width above; don't clobber it
                        fillEl.style.width = pct + "%";
                    }
                } else if (p.status === "started") {
                    // First request in-flight, no data yet
                    if (!countdownId) textEl.textContent = "Requesting data from Qualys API...";
                }
                // If items_synced is 0 or undefined, countdown timer handles the text
                setTimeout(poll, 2000);
            } else {
                // Sync complete — stop countdown and release the
                // per-type poller guard so the next sync click (or
                // auto-resume on Refresh) can attach a fresh poller.
                if (countdownId) clearInterval(countdownId);
                _activePollers.delete(type);
                // Strip the live-ticker affordance — sync is done,
                // event log is now historical.
                textEl.classList.remove("sync-progress-peek");
                textEl.onclick = null;
                textEl.title = "";
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
                    // CID sync also extracts mandates — show mandate count after refresh
                    if (type === "cids") {
                        setTimeout(async () => {
                            try {
                                const sr = await apiFetch("/api/sync/status");
                                const ss = await sr.json();
                                const mc = (ss.mandates && ss.mandates.record_count) || 0;
                                if (mc > 0) showToast(mc.toLocaleString() + " mandate frameworks extracted from CID data", "info");
                            } catch (_) {}
                        }, 500);
                    }
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
                    else if (type === "tags") { searchTags(); loadTagExports(); loadLibrary(); }
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

// ─── Live Sync Event Ticker (peek under the hood) ───────────────────────
// Polled-while-open viewer of recent sync_log_events for whichever type
// is currently in flight. Zero overhead when closed; ~one cheap query
// every 2s when open. Capped at 10 visible rows; new events animate in
// at the top, oldest drop off the bottom.

const _SYNC_TICKER_VISIBLE_CAP = 10;
let _syncTickerState = {
    open: false,
    type: null,
    sinceId: 0,        // last event id we've already shown (server returns id > sinceId)
    rows: [],          // [{id, ts, event_type, detail}]
    timer: null,       // setTimeout handle for next poll
};

// Event-type → row class for color cues. Keep narrow — every other
// event renders neutral so the colored ones actually stand out.
const _SYNC_TICKER_CLASS = {
    SYNC_ERROR: "evt-error",
    PAGE_ERROR: "evt-error",
    CHUNK_ERROR: "evt-error",
    BACKFILL_BATCH_ERROR: "evt-error",
    COUNT_ERROR: "evt-error",
    RATE_LIMIT_RETRY: "evt-warn",
    VERIFY_MISSING: "evt-warn",
    VERIFY_OK: "evt-success",
    SYNC_COMPLETE: "evt-success",
    CHUNK_COMPLETE: "evt-success",
};

function openSyncTicker(type) {
    const modal = document.getElementById("syncTickerModal");
    if (!modal) return;
    // Reset state for a fresh open. since_id=0 so the first poll
    // returns the most recent batch.
    _syncTickerState = { open: true, type, sinceId: 0, rows: [], timer: null };
    document.getElementById("syncTickerTitle").textContent =
        type.toUpperCase() + " — live activity";
    document.getElementById("syncTickerList").innerHTML = "";
    document.getElementById("syncTickerStatus").textContent = "Connecting…";
    openModal("syncTickerModal");
    _syncTickerPoll();
}

function closeSyncTicker() {
    if (_syncTickerState.timer) {
        clearTimeout(_syncTickerState.timer);
        _syncTickerState.timer = null;
    }
    _syncTickerState.open = false;
    closeModal("syncTickerModal");
}

async function _syncTickerPoll() {
    if (!_syncTickerState.open) return;
    const type = _syncTickerState.type;
    try {
        const url = "/api/sync/" + type + "/events/tail?since_id="
                  + _syncTickerState.sinceId + "&limit=25";
        const resp = await apiFetch(url);
        if (resp.ok) {
            const data = await resp.json();
            _syncTickerApply(data);
        }
    } catch (e) {
        // Transient network error — keep retrying. Don't surface a
        // toast; the ticker is best-effort.
    }
    if (_syncTickerState.open) {
        _syncTickerState.timer = setTimeout(_syncTickerPoll, 2000);
    }
}

function _syncTickerApply(data) {
    const list = document.getElementById("syncTickerList");
    const status = document.getElementById("syncTickerStatus");
    if (!list || !status) return;
    if (!data || !Array.isArray(data.events)) return;
    if (data.events.length) {
        // Server returns newest-first; we prepend in newest-last order
        // so each newer event ends up on top in the DOM after the loop.
        const newest = [...data.events].reverse();
        for (const e of newest) {
            _syncTickerState.rows.unshift(e);
            if (e.id > _syncTickerState.sinceId) _syncTickerState.sinceId = e.id;
        }
        // Cap visible rows; oldest fall off the bottom.
        if (_syncTickerState.rows.length > _SYNC_TICKER_VISIBLE_CAP) {
            _syncTickerState.rows.length = _SYNC_TICKER_VISIBLE_CAP;
        }
        list.innerHTML = _syncTickerState.rows.map(_syncTickerRowHtml).join("");
    }
    // Status footer: run state + a heartbeat so the user can tell the
    // poller is alive even when no new events have arrived.
    const stamp = new Date().toLocaleTimeString();
    const runStatus = data.run_status || "no run yet";
    status.textContent = "Run status: " + runStatus
                       + " · last poll " + stamp
                       + (data.events.length ? "" : " · waiting for new events…");
}

function _syncTickerRowHtml(e) {
    const cls = _SYNC_TICKER_CLASS[e.event_type] || "";
    // Truncate timestamp to HH:MM:SS — full ISO is overkill for a ticker.
    const ts = (e.ts || "").slice(11, 19) || "—";
    // Compact detail: pick the most informative pair of (key,value).
    // Prefer human-meaningful keys; fall back to whatever's first.
    let detailText = "";
    const d = e.detail || {};
    const preferred = [
        "items", "items_on_page", "items_synced", "expected_total",
        "id_min", "id_max", "page", "missing_count", "received_total",
        "platform", "target", "status", "retry_after", "error",
    ];
    for (const k of preferred) {
        if (d[k] !== undefined && d[k] !== null && d[k] !== "") {
            detailText = k + ": " + String(d[k]);
            break;
        }
    }
    if (!detailText) {
        const keys = Object.keys(d);
        if (keys.length) {
            const k = keys[0];
            const v = d[k];
            const s = (typeof v === "object") ? JSON.stringify(v) : String(v);
            detailText = k + ": " + (s.length > 80 ? s.slice(0, 77) + "…" : s);
        }
    }
    return '<div class="sync-ticker-row ' + cls + '">'
         + '<span class="sync-ticker-ts">' + escapeHtml(ts) + '</span>'
         + '<span class="sync-ticker-evt">' + escapeHtml(e.event_type) + '</span>'
         + '<span class="sync-ticker-detail">' + escapeHtml(detailText) + '</span>'
         + '</div>';
}


// ─── Sync Details Modal ─────────────────────────────────────────────────
// ── Sync history state ──
let _syncHistoryType = null;
let _syncHistoryCache = null;
let _syncHistoryExpanded = false;

async function showSyncDetails(type) {
    const labels = { qids: "QIDs (Knowledge Base)", cids: "CIDs (Controls)", policies: "Policies", mandates: "Mandates", tags: "Tags", pm_patches: "PM Patch Catalog" };
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
    const _disabledEl = document.getElementById("qidDisabledFilter");
    if (_disabledEl && _disabledEl.value) count++;
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
    const disabledEl = document.getElementById("qidDisabledFilter");
    const disabled = disabledEl ? disabledEl.value : "";
    if (disabled !== "") params.set("disabled", disabled);
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
                    ${v.threat_active_attacks ? '<span class="threat-badge threat-badge-critical">Active Attacks</span>' : ""}
                    ${v.threat_cisa_kev ? '<span class="threat-badge threat-badge-critical">CISA KEV</span>' : ""}
                    ${v.threat_exploit_public ? '<span class="threat-badge threat-badge-high">Public Exploit</span>' : ""}
                    ${v.threat_rce ? '<span class="threat-badge threat-badge-high">RCE</span>' : ""}
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

        // Patchable status with color
        const patchableHtml = v.patchable
            ? `<span style="color:var(--success, #22c55e);font-weight:600;">Yes</span>`
            : `<span style="color:var(--text-2);">No</span>`;
        const patchDateHtml = v.patch_published_date
            ? `<div class="detail-meta-item"><span class="detail-meta-label">Patch Published</span><span class="detail-meta-value">${new Date(v.patch_published_date).toLocaleDateString()}</span></div>`
            : "";
        // Threat intelligence badges
        const threatHtml = _renderThreatBadges(v);

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
                    <span class="detail-meta-value">${patchableHtml}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Published</span>
                    <span class="detail-meta-value">${v.published_datetime ? new Date(v.published_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Last Modified</span>
                    <span class="detail-meta-value">${v.last_service_modification_datetime ? new Date(v.last_service_modification_datetime).toLocaleDateString() : "N/A"}</span>
                </div>
                ${patchDateHtml}
                ${v.cvss3_base ? `<div class="detail-meta-item"><span class="detail-meta-label">CVSS v3</span><span class="detail-meta-value">${v.cvss3_base}</span></div>` : ""}
                ${v.cvss_base ? `<div class="detail-meta-item"><span class="detail-meta-label">CVSS v2</span><span class="detail-meta-value">${v.cvss_base}</span></div>` : ""}
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Supported Modules</span>
                    <span class="detail-meta-value">${(v.supported_modules && v.supported_modules.length) ? v.supported_modules.map(m => escapeHtml(m)).join(', ') : 'N/A'}</span>
                </div>
            </div>

            ${threatHtml}
            ${_renderThreatDetailsSection(v)}
            ${_renderRemediationSection(v)}

            ${v.diagnosis ? `<div class="detail-section"><h4>Diagnosis</h4><div class="detail-content">${v.diagnosis}</div></div>` : ""}
            ${v.consequence ? `<div class="detail-section"><h4>Consequence</h4><div class="detail-content">${v.consequence}</div></div>` : ""}
            ${renderRefList("CVEs", v.cves)}
            ${renderRefList("Bugtraq References", v.bugtraqs)}
            ${renderRefList("Vendor References", v.vendor_refs)}

            <div class="detail-section" id="qidDetailPmPatches">
                <h4>Patch Management Catalog</h4>
                <div class="detail-content"><span class="tag-export-progress">Loading patches…</span></div>
            </div>
        `;
        openModal("qidDetailModal");

        // Load PM patches asynchronously
        _loadQidPmPatches(v.qid);
    } catch (e) {
        showToast("Failed to load QID detail", "error");
    }
}

function _renderThreatBadges(v) {
    const badges = [];
    if (v.threat_active_attacks) badges.push('<span class="threat-badge threat-badge-critical">Active Attacks</span>');
    if (v.threat_cisa_kev) badges.push('<span class="threat-badge threat-badge-critical">CISA KEV</span>');
    if (v.threat_exploit_public) badges.push('<span class="threat-badge threat-badge-high">Public Exploit</span>');
    if (v.threat_easy_exploit) badges.push('<span class="threat-badge threat-badge-high">Easy Exploit</span>');
    if (v.threat_rce) badges.push('<span class="threat-badge threat-badge-high">RCE</span>');
    if (v.threat_priv_escalation) badges.push('<span class="threat-badge threat-badge-medium">Priv Escalation</span>');
    if (v.threat_malware) badges.push('<span class="threat-badge threat-badge-medium">Malware</span>');
    if (v.exploit_count > 0) badges.push(`<span class="threat-badge threat-badge-info">${v.exploit_count} Exploit${v.exploit_count > 1 ? "s" : ""}</span>`);
    if (v.malware_count > 0) badges.push(`<span class="threat-badge threat-badge-info">${v.malware_count} Malware</span>`);
    if (badges.length === 0) return "";
    return `<div class="threat-badges-row">${badges.join("")}</div>`;
}

function _renderThreatDetailsSection(v) {
    // Parse threat_intelligence_json and correlation_json for full details
    const ti = v.threat_intelligence_json;
    const corr = v.correlation_json;
    if (!ti && !corr) return "";

    let html = '<div class="detail-section threat-details-section"><h4>Threat Intelligence</h4>';

    // Threat tags
    if (ti && ti.THREAT_INTEL) {
        const tags = Array.isArray(ti.THREAT_INTEL) ? ti.THREAT_INTEL : [ti.THREAT_INTEL];
        const tagNames = tags.map(t => typeof t === "object" ? (t["#text"] || "") : t).filter(Boolean);
        if (tagNames.length) {
            html += `<div class="threat-tags">${tagNames.map(t =>
                `<span class="threat-tag">${escapeHtml(t.replace(/_/g, " "))}</span>`
            ).join("")}</div>`;
        }
    }

    // Exploits from correlation
    if (corr && corr.EXPLOITS) {
        const srcs = corr.EXPLOITS.EXPLT_SRC || [];
        const srcList = Array.isArray(srcs) ? srcs : [srcs];
        let exploits = [];
        for (const src of srcList) {
            const expltList = (src.EXPLT_LIST || {}).EXPLT || [];
            const items = Array.isArray(expltList) ? expltList : [expltList];
            for (const e of items) {
                if (e.REF || e.DESC) exploits.push(e);
            }
        }
        if (exploits.length) {
            html += `<div class="threat-subsection"><strong>Known Exploits (${exploits.length})</strong>`;
            html += '<div class="threat-exploit-list">';
            for (const e of exploits.slice(0, 10)) {
                const link = e.LINK ? `<a href="${escapeHtml(e.LINK)}" target="_blank" rel="noopener">${escapeHtml(e.DESC || e.REF || "View")}</a>` : escapeHtml(e.DESC || e.REF || "");
                html += `<div class="threat-exploit-row"><span class="threat-exploit-ref">${escapeHtml(e.REF || "")}</span> ${link}</div>`;
            }
            if (exploits.length > 10) html += `<div class="muted-small">+ ${exploits.length - 10} more</div>`;
            html += '</div></div>';
        }
    }

    // Malware from correlation
    if (corr && corr.MALWARE) {
        const srcs = corr.MALWARE.MW_SRC || [];
        const srcList = Array.isArray(srcs) ? srcs : [srcs];
        let malware = [];
        for (const src of srcList) {
            const mwList = (src.MW_LIST || {}).MW_INFO || [];
            const items = Array.isArray(mwList) ? mwList : [mwList];
            for (const m of items) {
                if (m.MW_ID || m.MW_TYPE) malware.push(m);
            }
        }
        if (malware.length) {
            html += `<div class="threat-subsection"><strong>Associated Malware (${malware.length})</strong>`;
            html += '<div class="threat-malware-list">';
            for (const m of malware.slice(0, 10)) {
                html += `<div class="threat-malware-row">
                    <span class="threat-malware-id">${escapeHtml(m.MW_ID || "")}</span>
                    <span class="threat-malware-type">${escapeHtml(m.MW_TYPE || "")}</span>
                    <span class="muted-small">${escapeHtml(m.MW_PLATFORM || "")}</span>
                </div>`;
            }
            if (malware.length > 10) html += `<div class="muted-small">+ ${malware.length - 10} more</div>`;
            html += '</div></div>';
        }
    }

    html += '</div>';
    return html;
}

function _renderRemediationSection(v) {
    if (!v.solution && !v.patchable) return "";

    let html = `<div class="detail-section qid-remediation-section">
        <h4>Remediation</h4>`;

    if (v.patchable) {
        html += `<div class="qid-remediation-status qid-remediation-available">
            <strong>Vendor fix available</strong>`;
        if (v.patch_published_date) {
            html += ` <span class="muted-small">(published ${new Date(v.patch_published_date).toLocaleDateString()})</span>`;
        }
        html += `</div>`;
    }

    if (v.solution) {
        html += `<div class="detail-content qid-solution-content">${v.solution}</div>`;
    }

    html += `</div>`;
    return html;
}

async function _loadQidPmPatches(qid) {
    const container = document.getElementById("qidDetailPmPatches");
    if (!container) return;
    try {
        const resp = await apiFetch("/api/qids/" + qid + "/patches");
        const data = await resp.json();
        const patches = data.patches || [];

        if (patches.length === 0) {
            container.innerHTML = `<h4>Patch Management Catalog</h4>
                <div class="detail-content muted-small">No PM catalog patches linked to this QID.
                ${data.has_pm === false ? " (Sync the PM Patch Catalog in Settings to populate this data.)" : ""}</div>`;
            return;
        }

        const winPatches = patches.filter(p => p.platform === "Windows");
        const linPatches = patches.filter(p => p.platform === "Linux");

        let html = `<h4>Patch Management Catalog <span class="muted-small">(${patches.length} patch${patches.length === 1 ? "" : "es"})</span></h4>`;

        if (winPatches.length) {
            html += `<div class="pm-patch-group">
                <strong class="pm-patch-platform">Windows (${winPatches.length})</strong>
                ${winPatches.map(_pmPatchRowHtml).join("")}
            </div>`;
        }
        if (linPatches.length) {
            html += `<div class="pm-patch-group">
                <strong class="pm-patch-platform">Linux (${linPatches.length})</strong>
                ${linPatches.map(_pmPatchRowHtml).join("")}
            </div>`;
        }

        container.innerHTML = html;
    } catch (e) {
        container.innerHTML = `<h4>Patch Management Catalog</h4>
            <div class="detail-content muted-small">Failed to load patches.</div>`;
    }
}

function _pmPatchRowHtml(p) {
    const sevClass = (p.vendor_severity || "").toLowerCase();
    const sevBadge = p.vendor_severity && p.vendor_severity !== "None"
        ? `<span class="pm-sev pm-sev-${sevClass}">${escapeHtml(p.vendor_severity)}</span>`
        : "";
    const secBadge = p.is_security ? '<span class="badge-pill badge-pill-preferred">Security</span>' : "";
    const kbLink = p.kb_article
        ? `<a href="https://support.microsoft.com/help/${p.kb_article.replace('KB','')}" target="_blank" rel="noopener">${escapeHtml(p.kb_article)}</a>`
        : "";
    const reboot = p.reboot_required ? '<span class="muted-small" title="Reboot required">↻</span>' : "";
    const packages = p.package_names
        ? `<div class="pm-patch-packages muted-small">${escapeHtml(p.package_names.split(";").slice(0, 3).join(", "))}${p.package_names.split(";").length > 3 ? "…" : ""}</div>`
        : "";

    return `<div class="pm-patch-row">
        <div class="pm-patch-title">${escapeHtml(p.title || "")} ${reboot}</div>
        <div class="pm-patch-meta">${sevBadge} ${secBadge} ${kbLink} <span class="muted-small">${escapeHtml(p.download_method || "")}</span></div>
        ${packages}
    </div>`;
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
    const _disClearEl = document.getElementById("qidDisabledFilter");
    if (_disClearEl) _disClearEl.value = "";
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

// ─── Search: Tags ────────────────────────────────────────────────────────
let tagRuleTypeMs;

function _tagSearchParams(page) {
    const params = new URLSearchParams();
    const q = document.getElementById("tagSearchInput").value;
    if (q) params.set("q", q);
    const ruleTypes = tagRuleTypeMs ? tagRuleTypeMs.getValues() : [];
    if (ruleTypes.length) params.set("rule_type", ruleTypes.join(","));
    const ownership = document.getElementById("tagOwnership").value;
    if (ownership === "user") params.set("only_user", "1");
    else if (ownership === "system") params.set("only_system", "1");
    if (page) params.set("page", page);
    return params;
}

async function searchTags(signal) {
    try {
        const opts = signal ? { signal } : {};
        const resp = await apiFetch("/api/tags?" + _tagSearchParams().toString(), opts);
        const data = await resp.json();
        if (data.error) { showToast(data.error, "error"); return; }
        renderTagResults(data);
        _saveRecentSearch("tags", document.getElementById("tagSearchInput").value.trim(), data.total || 0);
    } catch (e) {
        if (e.name === "AbortError") return;
        showToast("Search failed: " + e.message, "error");
    }
}

function clearTagFilters() {
    document.getElementById("tagSearchInput").value = "";
    document.getElementById("tagOwnership").value = "";
    // silent clear — we call searchTags() ourselves below, no need
    // for the MultiSelect's onChange to also fire it.
    if (tagRuleTypeMs) tagRuleTypeMs.clear(true);
    searchTags();
}

function toggleTagsReferences() {
    const body = document.getElementById("tagsReferencesBody");
    const toggle = document.getElementById("tagsRefToggle");
    if (!body) return;
    const collapsed = body.style.display === "none";
    body.style.display = collapsed ? "" : "none";
    if (toggle) toggle.textContent = collapsed ? "▾" : "▸";
}

function _tagCardHtml(t) {
    const isSystem = t.tag_origin === "system";
    const swatch = t.color ? `<span class="tag-swatch" style="background:${escapeHtml(t.color)};" title="${escapeHtml(t.color)}"></span>` : "";
    const sysPill = isSystem ? `<span class="tag-system-pill" title="Qualys-provisioned system tag. Read-only — cannot be migrated or deleted."><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="vertical-align:-1px;"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg> SYSTEM</span>` : "";
    const ruleType = t.rule_type ? `<span class="badge-pill">${escapeHtml(t.rule_type)}</span>` : "";
    const desc = t.description ? escapeHtml(t.description.length > 120 ? t.description.substring(0, 120) + "…" : t.description) : "";
    const childCount = t.child_count > 0
        ? `<span class="tag-child-count" title="${t.child_count} child tag(s) — may use different rule types">${t.child_count} child${t.child_count === 1 ? "" : "ren"}</span>`
        : "";
    const parentName = t.parent_name
        ? `<span class="tag-parent-ref" title="Child of ${escapeHtml(t.parent_name)}">↳ ${escapeHtml(t.parent_name)}</span>`
        : "";
    const originBadge = t.tag_origin && t.tag_origin !== "rule_based"
        ? `<span class="tag-origin-badge tag-origin-${t.tag_origin}" title="Origin: ${t.tag_origin}">${t.tag_origin}</span>`
        : "";
    const selectChildrenBtn = (_tagSelectMode && t.child_count > 0)
        ? `<button class="btn-sm btn-outline tag-card-select-children" onclick="event.stopPropagation();selectTagWithChildren(${t.tag_id})" title="Select this tag + all ${t.child_count} children">+ children</button>`
        : "";
    return `
    <div class="tag-card${isSystem ? ' tag-card-system' : ''}" onclick="showTagDetail(${t.tag_id})">
        <div class="tag-card-header">
            ${swatch}
            <span class="tag-card-title">${escapeHtml(t.name || "")}</span>
            ${sysPill}
        </div>
        ${desc ? `<div class="tag-card-desc">${desc}</div>` : ""}
        <div class="tag-card-meta">
            <span class="tag-id">#${t.tag_id}</span>
            ${ruleType}
            ${originBadge}
            ${parentName}
            ${childCount}
            ${selectChildrenBtn}
        </div>
    </div>`;
}

function _tagTreeNodeHtml(t, childrenOf) {
    const hasChildren = t.child_count > 0;

    if (!hasChildren) {
        return _tagCardHtml(t);
    }

    // This tag is a parent — render as collapsible group.
    // Always use "load on expand" for children so we get the complete
    // set from the DB regardless of pagination.
    const totalChildren = t.child_count;

    return `<div class="tag-tree-group collapsed">
        <div class="tag-tree-header" onclick="expandTagTreeNode(this, ${t.tag_id})">
            <svg class="tag-tree-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
            <span class="tag-tree-parent-name">${t.color ? `<span class="tag-swatch" style="background:${escapeHtml(t.color)};"></span>` : ""}${escapeHtml(t.name || "")}</span>
            <span class="muted-small">${totalChildren} child${totalChildren === 1 ? "" : "ren"}</span>
            <span class="tag-id">#${t.tag_id}</span>
            ${_tagSelectMode ? `<button class="btn-sm btn-outline tag-tree-select-children" onclick="event.stopPropagation();selectTagWithChildren(${t.tag_id})" title="Select this tag and all children">Select all</button>` : ""}
        </div>
        <div class="tag-tree-body-wrap" id="tag-tree-body-${t.tag_id}">
            <div class="tag-tree-parent-card">${_tagCardHtml(t)}</div>
            <div class="tag-tree-children" id="tag-tree-children-${t.tag_id}"></div>
        </div>
    </div>`;
}

function expandTagTreeNode(headerEl, tagId) {
    const group = headerEl.parentElement;
    const wasCollapsed = group.classList.contains("collapsed");
    group.classList.toggle("collapsed");

    // Load children on first expand
    if (wasCollapsed) {
        const childrenEl = document.getElementById("tag-tree-children-" + tagId);
        if (childrenEl && childrenEl.children.length === 0) {
            loadTagChildren(tagId, null);
        }
    }
}

async function loadTagChildren(parentId, btn) {
    const childrenEl = document.getElementById("tag-tree-children-" + parentId);
    if (!childrenEl) return;

    // Show loading indicator
    const loadingId = "tag-tree-loading-" + parentId;
    if (!document.getElementById(loadingId)) {
        childrenEl.insertAdjacentHTML("beforeend",
            `<div id="${loadingId}" class="tag-tree-loading"><span class="tag-export-progress">Loading children…</span></div>`
        );
    }
    if (btn) btn.disabled = true;

    try {
        const resp = await apiFetch(`/api/tags?parent_tag_id=${parentId}&per_page=500`);
        const data = await resp.json();
        const children = data.results || [];

        // Remove loading indicator
        const loader = document.getElementById(loadingId);
        if (loader) loader.remove();
        if (btn) btn.remove();

        if (children.length === 0) {
            childrenEl.insertAdjacentHTML("beforeend",
                '<div class="muted-small" style="padding:4px 0;">No children found.</div>'
            );
            return;
        }

        // Each child renders as its own node — sub-parents get their own
        // collapsible group with load-on-expand.
        const html = children.map(c => _tagTreeNodeHtml(c, {})).join("");
        childrenEl.insertAdjacentHTML("beforeend", html);

        // If select mode is active, add checkboxes to newly loaded cards
        if (_tagSelectMode) _addTagCheckboxes();
    } catch (e) {
        const loader = document.getElementById(loadingId);
        if (loader) loader.innerHTML = '<span class="muted-small" style="color:var(--danger);">Failed to load children.</span>';
        if (btn) btn.disabled = false;
    }
}

function _hasActiveTagFilters() {
    const q = (document.getElementById("tagSearchInput").value || "").trim();
    const ruleTypes = tagRuleTypeMs ? tagRuleTypeMs.getValues() : [];
    const ownership = document.getElementById("tagOwnership").value;
    return !!(q || ruleTypes.length || ownership);
}

function renderTagResults(data) {
    const container = document.getElementById("tagResults");
    const items = data.results || [];
    updateCountBadge("tag", data.total || 0);
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No tags found. Sync Tags in Settings or adjust your filters.</p></div>';
        document.getElementById("tagPagination").style.display = "none";
        return;
    }

    const filtersActive = _hasActiveTagFilters();

    if (filtersActive) {
        // Flat view — show only matching tags as cards, no tree expansion.
        // Child count still shows on each card for context.
        container.innerHTML = items.map(t => _tagCardHtml(t)).join("");
    } else {
        // Tree view — group by parent-child, collapsible on expand.
        const byId = new Set(items.map(t => t.tag_id));
        const topLevel = items.filter(t => !t.parent_tag_id || !byId.has(t.parent_tag_id));
        container.innerHTML = topLevel.map(t => _tagTreeNodeHtml(t, {})).join("");
    }

    _tagTotalCount = data.total || 0;
    renderPagination("tag", data);
    // If select mode is active, re-add checkboxes (preserves selections across pages)
    if (_tagSelectMode) {
        _addTagCheckboxes();
        _updateTagSelectCount();
    }
}

// ─── Tag Select/Export Mode ──────────────────────────────────────────────
let _tagSelectMode = false;
let _tagSelected = new Set();      // individual tag ids selected
let _tagSelectAllMode = false;     // "all tags" selected (across all pages)
let _tagTotalCount = 0;            // total tags from last search

function toggleTagSelectMode() {
    _tagSelectMode = !_tagSelectMode;
    const toolbar = document.getElementById("tagExportToolbar");
    const btn = document.getElementById("tagSelectModeBtn");
    if (_tagSelectMode) {
        toolbar.style.display = "flex";
        btn.classList.add("active");
        _tagSelected.clear();
        _tagSelectAllMode = false;
        document.getElementById("tagSelectAll").checked = false;
        _updateTagSelectCount();
        // Re-render results so tree headers and cards get the select buttons
        searchTags();
    } else {
        toolbar.style.display = "none";
        btn.classList.remove("active");
        _tagSelected.clear();
        _tagSelectAllMode = false;
        document.getElementById("tagSelectAll").checked = false;
        _removeTagCheckboxes();
        // Re-render to remove select buttons
        searchTags();
    }
}

function _addTagCheckboxes() {
    document.querySelectorAll("#tagResults .tag-card").forEach(card => {
        if (card.querySelector(".tag-select-cb")) return;
        const tagId = _extractTagIdFromCard(card);
        if (!tagId) return;
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.className = "tag-select-cb";
        cb.checked = _tagSelectAllMode || _tagSelected.has(tagId);
        cb.onclick = function(e) {
            e.stopPropagation();
            if (this.checked) {
                _tagSelected.add(tagId);
            } else {
                _tagSelected.delete(tagId);
                // If we uncheck one while "all" is active, switch to individual mode
                if (_tagSelectAllMode) {
                    _tagSelectAllMode = false;
                    document.getElementById("tagSelectAll").checked = false;
                    // Add all currently visible tags to the set (minus this one)
                    document.querySelectorAll("#tagResults .tag-card").forEach(c => {
                        const id = _extractTagIdFromCard(c);
                        if (id && id !== tagId) _tagSelected.add(id);
                    });
                }
            }
            _updateTagSelectCount();
        };
        card.style.position = "relative";
        card.insertBefore(cb, card.firstChild);
    });
}

function _removeTagCheckboxes() {
    document.querySelectorAll("#tagResults .tag-select-cb").forEach(cb => cb.remove());
}

function _extractTagIdFromCard(card) {
    const idEl = card.querySelector(".tag-id");
    if (!idEl) return null;
    const m = idEl.textContent.match(/#(\d+)/);
    return m ? parseInt(m[1]) : null;
}

async function selectTagWithChildren(parentId) {
    // Select the parent + all its children (recursive) from the API
    _tagSelected.add(parentId);
    try {
        const resp = await apiFetch(`/api/tags?parent_tag_id=${parentId}&per_page=500`);
        const data = await resp.json();
        const children = data.results || [];
        for (const c of children) {
            _tagSelected.add(c.tag_id);
            // If child is also a parent, recursively select its children too
            if (c.child_count > 0) {
                await selectTagWithChildren(c.tag_id);
            }
        }
    } catch (e) {
        // Best effort — at minimum the parent is selected
    }
    // Update checkboxes on visible cards
    document.querySelectorAll("#tagResults .tag-select-cb").forEach(cb => {
        const card = cb.closest(".tag-card");
        const tagId = _extractTagIdFromCard(card);
        if (tagId && _tagSelected.has(tagId)) cb.checked = true;
    });
    _updateTagSelectCount();
    showToast(`Selected tag #${parentId} + children (${_tagSelected.size} total)`, "info");
}

function toggleTagSelectAll(checked) {
    _tagSelectAllMode = checked;
    if (checked) {
        // Select all — don't just select visible, mark the "all" flag
        _tagSelected.clear();
        document.querySelectorAll("#tagResults .tag-select-cb").forEach(cb => {
            cb.checked = true;
        });
    } else {
        // Deselect all
        _tagSelected.clear();
        document.querySelectorAll("#tagResults .tag-select-cb").forEach(cb => {
            cb.checked = false;
        });
    }
    _updateTagSelectCount();
}

function _updateTagSelectCount() {
    const countEl = document.getElementById("tagSelectCount");
    const exportBtn = document.getElementById("tagExportBtn");
    const migrateBtn = document.getElementById("tagMigrateBtn");
    const deleteBtn = document.getElementById("tagDeleteLocalBtn");
    const deleteQualysBtn = document.getElementById("tagDeleteQualysBtn");
    const count = _tagSelectAllMode ? _tagTotalCount : _tagSelected.size;
    countEl.textContent = _tagSelectAllMode
        ? `All ${_tagTotalCount} tags selected`
        : `${_tagSelected.size} selected`;
    const empty = count === 0;
    exportBtn.disabled = empty;
    migrateBtn.disabled = empty;
    deleteBtn.disabled = empty;
    deleteQualysBtn.disabled = empty;
}

async function _getSelectedTagIds() {
    // If "select all" mode, fetch all tag ids from the local DB
    // using pagination (API caps at 500 per page)
    if (_tagSelectAllMode) {
        try {
            const allIds = [];
            let page = 1;
            while (true) {
                const params = new URLSearchParams();
                params.set("per_page", "500");
                params.set("page", page);
                const resp = await apiFetch("/api/tags?" + params.toString());
                const data = await resp.json();
                if (data.error) {
                    console.error("_getSelectedTagIds error:", data.error);
                    break;
                }
                const results = data.results || [];
                for (const t of results) allIds.push(t.tag_id);
                if (page >= (data.pages || 1)) break;
                page++;
            }
            return allIds;
        } catch (e) {
            console.error("_getSelectedTagIds exception:", e);
            return [];
        }
    }
    return Array.from(_tagSelected);
}

async function exportSelectedTagsToJson() {
    const btn = document.getElementById("tagExportBtn");
    btn.disabled = true;
    const countEl = document.getElementById("tagSelectCount");
    const origCount = countEl.textContent;
    countEl.innerHTML = `<span class="tag-export-progress">Preparing export…</span>`;

    try {
        // Build the tag_ids param — use 'all' if select-all mode, otherwise individual ids
        let idsParam;
        if (_tagSelectAllMode) {
            idsParam = "all";
        } else {
            const tagIds = Array.from(_tagSelected);
            if (tagIds.length === 0) return;
            idsParam = tagIds.join(",");
        }

        // Direct download from local DB — no Qualys API calls needed
        const resp = await apiFetch("/api/tags/export-local?tag_ids=" + idsParam);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `tags-export-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        showToast("Tags exported to JSON", "success");
        toggleTagSelectMode();
    } catch (e) {
        showToast("Export failed: " + e.message, "error");
    } finally {
        countEl.textContent = origCount;
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Export to JSON';
    }
}

async function deleteSelectedTagsLocal() {
    const count = _tagSelectAllMode ? _tagTotalCount : _tagSelected.size;
    if (count === 0) return;

    const confirmMsg = _tagSelectAllMode
        ? `Delete ALL ${_tagTotalCount} locally synced tags? This only removes them from the local cache — not from Qualys. You can re-sync them anytime.`
        : `Delete ${_tagSelected.size} selected tag(s) from local cache? This does not affect Qualys. You can re-sync them anytime.`;
    if (!await themedConfirm(confirmMsg)) return;

    const btn = document.getElementById("tagDeleteLocalBtn");
    btn.disabled = true;
    btn.textContent = "Deleting…";

    try {
        const body = _tagSelectAllMode
            ? { tag_ids: "all" }
            : { tag_ids: Array.from(_tagSelected) };

        const resp = await apiFetch("/api/tags/delete-local", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const result = await resp.json();
        if (result.error) {
            showToast(result.error, "error");
        } else {
            showToast(`Deleted ${result.deleted} tag(s) from local cache`, "success");
            toggleTagSelectMode();
            searchTags();
        }
    } catch (e) {
        showToast("Delete failed: " + e.message, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Delete local';
    }
}

async function deleteSelectedTagsFromQualys() {
    let tagIds = await _getSelectedTagIds();
    if (tagIds.length === 0) return;

    // Pre-filter: only user-created tags can be deleted from Qualys.
    // Fetch details to filter out system tags client-side before even asking.
    const btn = document.getElementById("tagDeleteQualysBtn");
    btn.disabled = true;
    btn.textContent = "Checking tags…";

    let userTagIds = [];
    let systemSkipped = 0;
    try {
        // Check each tag's is_user_created status from the local DB
        for (let i = 0; i < tagIds.length; i += 500) {
            const batch = tagIds.slice(i, i + 500);
            const resp = await apiFetch("/api/tags?" + new URLSearchParams({per_page: "500", page: "1"}).toString());
            const data = await resp.json();
            const allTags = data.results || [];
            const tagMap = {};
            for (const t of allTags) tagMap[t.tag_id] = t;
            for (const id of batch) {
                const t = tagMap[id];
                if (t && t.tag_origin === "system") systemSkipped++;
                else userTagIds.push(id);
            }
        }
    } catch (e) {
        // If check fails, proceed with all and let backend filter
        userTagIds = tagIds;
    }

    if (userTagIds.length === 0) {
        showToast(`All ${tagIds.length} selected tags are system/Qualys-managed and cannot be deleted.`, "warning");
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg> Delete from Qualys';
        return;
    }

    const skipNote = systemSkipped > 0 ? `\n\n(${systemSkipped} system tags will be skipped automatically.)` : "";
    const confirmMsg = `⚠️ DESTRUCTIVE ACTION\n\nThis will permanently delete ${userTagIds.length} user-created tag(s) from your Qualys subscription AND from the local cache.${skipNote}\n\nThis cannot be undone. Continue?`;
    if (!await themedConfirm(confirmMsg)) {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg> Delete from Qualys';
        return;
    }

    btn.textContent = `Deleting ${userTagIds.length} tag(s)…`;
    tagIds = userTagIds;

    const auth = getApiAuth();
    try {
        const resp = await apiFetch("/api/tags/delete-qualys", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                tag_ids: tagIds,
                credential_id: auth.credential_id || undefined,
                platform: auth.platform || undefined,
            }),
        });
        const result = await resp.json();
        if (result.error) {
            showToast(result.error, "error");
            return;
        }

        // Show results
        let msg = `Deleted ${result.deleted_count} tag(s) from Qualys`;
        if (result.skipped_count) msg += `, ${result.skipped_count} skipped (system)`;
        if (result.failed_count) msg += `, ${result.failed_count} failed`;
        showToast(msg, result.failed_count ? "warning" : "success");

        // Show detailed results if failures
        if (result.failed_count > 0) {
            const details = result.failed.map(f =>
                `#${f.tag_id} ${f.name || ""}: ${f.reason}`
            ).join("\n");
            console.warn("Tag deletion failures:\n" + details);
        }

        toggleTagSelectMode();
        searchTags();
    } catch (e) {
        showToast("Delete from Qualys failed: " + e.message, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg> Delete from Qualys';
    }
}

let _tagMigrateAuditPassed = false;

async function importTagsFromJsonFile(input) {
    const file = input.files[0];
    input.value = "";  // reset so same file can be re-selected
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
        const resp = await apiFetch("/api/tags/import-local", {
            method: "POST",
            body: formData,
        });
        const result = await resp.json();
        if (result.error) {
            showToast(result.error, "error");
            return;
        }
        showToast(
            `Imported ${result.imported} tag(s) from ${file.name}` +
            (result.skipped ? ` (${result.skipped} skipped)` : ""),
            "success"
        );
        searchTags();
    } catch (e) {
        showToast("Import failed: " + e.message, "error");
    }
}

let _tagMigrateTagIds = null; // cached tag IDs for migration

async function openTagMigrateModal() {
    const count = _tagSelectAllMode ? _tagTotalCount : _tagSelected.size;
    if (count === 0) {
        showToast("No tags selected", "error");
        return;
    }

    // Pre-fetch the tag IDs now (while select mode is still active)
    _tagMigrateTagIds = await _getSelectedTagIds();

    // Fallback: if select-all mode but fetch returned empty,
    // grab IDs from the currently visible page cards
    if (_tagMigrateTagIds.length === 0 && _tagSelectAllMode) {
        // Try getting all visible tag IDs from the DOM
        const visibleIds = [];
        document.querySelectorAll("#tagResults .tag-id").forEach(el => {
            const m = el.textContent.match(/#(\d+)/);
            if (m) visibleIds.push(parseInt(m[1]));
        });
        if (visibleIds.length > 0) {
            _tagMigrateTagIds = visibleIds;
        }
    }

    if (_tagMigrateTagIds.length === 0) {
        showToast("Could not determine selected tags — try selecting individually", "error");
        return;
    }

    _tagMigrateAuditPassed = false;
    document.getElementById("tagMigrateResults").style.display = "none";
    document.getElementById("tagMigrateResults").innerHTML = "";
    document.getElementById("tagMigrateAuditWarning").style.display = "none";
    document.getElementById("tagMigrateAuditWarning").innerHTML = "";
    document.getElementById("tagMigrateGoBtn").disabled = false;

    // Build origin breakdown so user can include/exclude by category
    await _buildMigrateOriginBreakdown();
    _updateMigrateSummaryFromOrigin();
    // Set default parent name with today's date
    const today = new Date().toISOString().slice(0, 10);
    document.getElementById("tagMigrateParentName").value = `TAGs Imported ${today}`;
    document.getElementById("tagMigrateCreateParent").checked = false;
    // Populate destination credential dropdown
    try {
        const resp = await apiFetch("/api/credentials");
        const creds = await resp.json();
        const sel = document.getElementById("tagMigrateDestCred");
        sel.innerHTML = '<option value="">— Select Destination —</option>'
            + (Array.isArray(creds) ? creds.map(c =>
                `<option value="${c.id}" data-platform="${c.platform_id || ""}">${escapeHtml(formatCredLabel(c))}</option>`
            ).join("") : "");
    } catch (e) {}
    // Run audit pre-check
    _runMigrateAuditCheck();
    openModal("tagMigrateModal");
}

async function _runMigrateAuditCheck() {
    const warningEl = document.getElementById("tagMigrateAuditWarning");
    try {
        const resp = await apiFetch("/api/tags/audit");
        const data = await resp.json();
        const total = (data.summary && data.summary.total) || 0;
        if (total === 0) {
            _tagMigrateAuditPassed = true;
            return;
        }
        // Show warning
        const errors = data.summary.error || 0;
        const warns = data.summary.warn || 0;
        warningEl.style.display = "block";
        warningEl.innerHTML = `
            <div class="migrate-audit-warning">
                <div class="migrate-audit-warning-header">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <strong>Tag audit found issues</strong>
                </div>
                <p class="muted-small" style="margin:6px 0;">
                    Your local tag inventory has ${errors ? `<strong>${errors} error(s)</strong>` : ""}${errors && warns ? " and " : ""}${warns ? `<strong>${warns} warning(s)</strong>` : ""}
                    (e.g. duplicate names, duplicate rules, hierarchy problems).
                    Migrating tags with issues may replicate problems into the destination environment.
                </p>
                <div style="display:flex;gap:8px;margin-top:8px;">
                    <button class="btn-sm btn-outline" onclick="closeModal('tagMigrateModal');switchTagSubTab('audit');runTagAudit();">
                        Review in Audit tab
                    </button>
                    <button class="btn-sm btn-outline" onclick="_dismissMigrateAuditWarning()">
                        Ignore and proceed
                    </button>
                </div>
            </div>`;
        // Disable migrate button until they dismiss
        document.getElementById("tagMigrateGoBtn").disabled = true;
    } catch (e) {
        // If audit fails, allow migration anyway
        _tagMigrateAuditPassed = true;
    }
}

function _dismissMigrateAuditWarning() {
    _tagMigrateAuditPassed = true;
    document.getElementById("tagMigrateAuditWarning").style.display = "none";
    document.getElementById("tagMigrateGoBtn").disabled = false;
}

let _tagMigrateOriginData = {}; // {origin: [{tag_id, name}, ...]}

async function _buildMigrateOriginBreakdown() {
    const container = document.getElementById("tagMigrateOriginBreakdown");
    if (!container || !_tagMigrateTagIds || _tagMigrateTagIds.length === 0) return;

    // Fetch tag details in batches to get origin info
    _tagMigrateOriginData = {};
    const batchSize = 500;
    for (let i = 0; i < _tagMigrateTagIds.length; i += batchSize) {
        try {
            const resp = await apiFetch("/api/tags?" + new URLSearchParams({per_page: "500", page: String(Math.floor(i / batchSize) + 1)}).toString());
            const data = await resp.json();
            for (const t of (data.results || [])) {
                if (_tagMigrateTagIds.includes(t.tag_id)) {
                    const origin = t.tag_origin || "static";
                    if (!_tagMigrateOriginData[origin]) _tagMigrateOriginData[origin] = [];
                    _tagMigrateOriginData[origin].push({tag_id: t.tag_id, name: t.name});
                }
            }
        } catch (e) { break; }
    }

    const originMeta = {
        rule_based: {label: "Rule-based tags", desc: "Have detection logic — portable to any subscription", cls: "green", default: true},
        static:     {label: "Static tags", desc: "STATIC tags — no rule, used for grouping and hierarchy", cls: "blue", default: true},
        connector:  {label: "Connector tags", desc: "Created by cloud connectors — need matching connector in destination", cls: "amber", default: false},
    };

    // System tags are always excluded — remove them from the pool entirely
    const systemCount = (_tagMigrateOriginData["system"] || []).length;
    delete _tagMigrateOriginData["system"];

    let html = '<div class="migrate-origin-breakdown"><strong style="font-size:12px;">Select which tag types to include:</strong>';
    for (const [origin, meta] of Object.entries(originMeta)) {
        const tags = _tagMigrateOriginData[origin] || [];
        if (tags.length === 0) continue;
        const checked = meta.default ? "checked" : "";
        const warning = origin === "connector" ? ' <span class="muted-small" style="color:var(--warning);">(review before including)</span>' : "";
        html += `<label class="migrate-origin-row migrate-origin-${meta.cls}">
            <input type="checkbox" data-origin="${origin}" ${checked} onchange="_updateMigrateSummaryFromOrigin()">
            <span class="migrate-origin-label">
                <strong>${meta.label}</strong> (${tags.length})${warning}
                <span class="migrate-origin-desc">${meta.desc}</span>
            </span>
        </label>`;
    }
    if (systemCount > 0) {
        html += `<div class="migrate-origin-row migrate-origin-gray" style="cursor:default;">
            <span class="migrate-origin-label">
                <strong>System tags</strong> (${systemCount}) — automatically excluded
                <span class="migrate-origin-desc">Qualys-managed tags already exist in every subscription</span>
            </span>
        </div>`;
    }
    html += '</div>';
    container.innerHTML = html;
    container.style.display = "block";
}

function _updateMigrateSummaryFromOrigin() {
    // Count how many tags will be migrated based on checked origins
    let total = 0;
    document.querySelectorAll("#tagMigrateOriginBreakdown input[data-origin]").forEach(cb => {
        if (cb.checked) {
            const origin = cb.dataset.origin;
            total += (_tagMigrateOriginData[origin] || []).length;
        }
    });
    document.getElementById("tagMigrateSummary").textContent = `${total} tag(s) will be migrated.`;
    const btn = document.getElementById("tagMigrateGoBtn");
    if (btn) btn.disabled = total === 0;
}

function _getFilteredMigrateTagIds() {
    // Return only tag IDs for checked origins
    const ids = [];
    document.querySelectorAll("#tagMigrateOriginBreakdown input[data-origin]").forEach(cb => {
        if (cb.checked) {
            const origin = cb.dataset.origin;
            for (const t of (_tagMigrateOriginData[origin] || [])) {
                ids.push(t.tag_id);
            }
        }
    });
    // If no origin breakdown was built (e.g. fetch failed), use all
    return ids.length > 0 ? ids : (_tagMigrateTagIds || []);
}

let _migrateRenames = {};   // {tag_id: "new name"}
let _migrateSkipIds = [];   // [tag_id, ...]

async function executeTagMigration() {
    if (!_tagMigrateAuditPassed) {
        showToast("Please review or dismiss the audit warnings first", "warning");
        return;
    }

    const sel = document.getElementById("tagMigrateDestCred");
    const destCredId = sel.value;
    if (!destCredId) { showToast("Select a destination credential", "error"); return; }
    const destPlatform = sel.options[sel.selectedIndex]?.dataset.platform || "";

    const createParent = document.getElementById("tagMigrateCreateParent").checked;
    const parentName = document.getElementById("tagMigrateParentName").value.trim();

    const tagIds = _getFilteredMigrateTagIds();
    if (tagIds.length === 0) { showToast("No tags selected — check the origin categories above", "error"); return; }

    const btn = document.getElementById("tagMigrateGoBtn");
    btn.disabled = true;
    const resultsEl = document.getElementById("tagMigrateResults");
    resultsEl.style.display = "block";

    // Step 1: Pre-flight collision check
    btn.textContent = "Checking for name collisions…";
    resultsEl.innerHTML = '<span class="tag-export-progress">Checking destination for existing tag names…</span>';
    _migrateRenames = {};
    _migrateSkipIds = [];

    const auth = getApiAuth();
    try {
        const preResp = await apiFetch("/api/tags/migrate-preflight", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                tag_ids: tagIds,
                dest_credential_id: destCredId,
                dest_platform: destPlatform,
            }),
        });
        const preflight = await preResp.json();
        const collisions = preflight.collisions || [];

        if (collisions.length > 0) {
            // Show collision resolution UI and wait for user
            const proceed = await _showCollisionResolution(collisions);
            if (!proceed) {
                btn.disabled = false;
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><polyline points="12 5 19 12 12 19"/></svg> Migrate';
                return;
            }
        }

        // Step 2: Start migration
        btn.textContent = `Starting migration…`;
        resultsEl.innerHTML = '<span class="tag-export-progress">Starting migration…</span>';

        const resp = await apiFetch("/api/tags/migrate-direct", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                tag_ids: tagIds,
                source_credential_id: auth.credential_id || undefined,
                source_platform: auth.platform || undefined,
                dest_credential_id: destCredId,
                dest_platform: destPlatform,
                create_parent: createParent,
                parent_name: parentName || undefined,
                renames: _migrateRenames,
                skip_ids: _migrateSkipIds,
            }),
        });
        const startResult = await resp.json();
        if (startResult.error) {
            resultsEl.innerHTML = `<div style="color:var(--danger);font-weight:600;">Migration failed to start</div>
                <div class="muted-small">${escapeHtml(startResult.error)}</div>`;
            document.getElementById("tagMigrateSummary").textContent = "Error — see details below.";
            btn.disabled = false;
            btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><polyline points="12 5 19 12 12 19"/></svg> Migrate';
            return;
        }

        // Poll for progress
        const jobId = startResult.job_id;
        _pollMigrationProgress(jobId);
    } catch (e) {
        resultsEl.innerHTML = `<div style="color:var(--danger);font-weight:600;">Migration failed</div>
            <div class="muted-small">${escapeHtml(e.message)}</div>`;
        document.getElementById("tagMigrateSummary").textContent = "Error";
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><polyline points="12 5 19 12 12 19"/></svg> Migrate';
    }
}

function _showCollisionResolution(collisions) {
    return new Promise(resolve => {
        const resultsEl = document.getElementById("tagMigrateResults");
        let html = `<div class="migrate-collision-panel">
            <div style="font-weight:600;margin-bottom:8px;color:var(--warning);">
                ${collisions.length} tag name${collisions.length > 1 ? "s" : ""} already exist in the destination
            </div>
            <p class="muted-small" style="margin:0 0 12px 0;">Choose how to handle each collision. Renamed tags will be created with the new name. Skipped tags won't be migrated.</p>
            <div style="margin-bottom:10px;">
                <button class="btn-sm btn-outline" onclick="_collisionSkipAll()">Skip all collisions</button>
                <button class="btn-sm btn-outline" onclick="_collisionRenameAll()">Rename all with (migrated) suffix</button>
            </div>
            <div class="migrate-collision-list">`;

        for (const c of collisions) {
            html += `<div class="migrate-collision-row" data-tid="${c.tag_id}">
                <div class="migrate-collision-name">
                    <strong>${escapeHtml(c.name)}</strong>
                    <span class="muted-small">exists as #${c.dest_tag_id} in destination</span>
                </div>
                <div class="migrate-collision-actions">
                    <select class="migrate-collision-action" data-tid="${c.tag_id}" onchange="_onCollisionActionChange(this)">
                        <option value="rename">Rename</option>
                        <option value="skip">Skip</option>
                    </select>
                    <input type="text" class="migrate-collision-rename-input" data-tid="${c.tag_id}"
                           value="${escapeHtml(c.name)} (migrated)" style="font-size:12px;width:200px;">
                </div>
            </div>`;
        }

        html += `</div>
            <div style="margin-top:12px;display:flex;gap:8px;">
                <button class="btn-sm btn-primary" id="_collisionProceed">Proceed with migration</button>
                <button class="btn-sm btn-outline" id="_collisionCancel">Cancel</button>
            </div>
        </div>`;

        resultsEl.innerHTML = html;

        document.getElementById("_collisionProceed").onclick = () => {
            // Gather decisions
            _migrateRenames = {};
            _migrateSkipIds = [];
            document.querySelectorAll(".migrate-collision-action").forEach(sel => {
                const tid = sel.dataset.tid;
                if (sel.value === "skip") {
                    _migrateSkipIds.push(parseInt(tid));
                } else {
                    const input = document.querySelector(`.migrate-collision-rename-input[data-tid="${tid}"]`);
                    if (input && input.value.trim()) {
                        _migrateRenames[tid] = input.value.trim();
                    }
                }
            });
            resolve(true);
        };
        document.getElementById("_collisionCancel").onclick = () => resolve(false);
    });
}

function _onCollisionActionChange(sel) {
    const tid = sel.dataset.tid;
    const input = document.querySelector(`.migrate-collision-rename-input[data-tid="${tid}"]`);
    if (input) input.style.display = sel.value === "rename" ? "" : "none";
}

function _collisionSkipAll() {
    document.querySelectorAll(".migrate-collision-action").forEach(sel => {
        sel.value = "skip";
        _onCollisionActionChange(sel);
    });
}

function _collisionRenameAll() {
    document.querySelectorAll(".migrate-collision-action").forEach(sel => {
        sel.value = "rename";
        _onCollisionActionChange(sel);
    });
}

let _migrationPollRetries = 0;

async function _pollMigrationProgress(jobId) {
    const resultsEl = document.getElementById("tagMigrateResults");
    const summaryEl = document.getElementById("tagMigrateSummary");
    const btn = document.getElementById("tagMigrateGoBtn");
    _migrationPollRetries = 0;

    const poll = async () => {
        try {
            const resp = await fetch(`/api/tags/migrate-status?job_id=${jobId}`);
            const s = await resp.json();
            _migrationPollRetries = 0; // reset on success

            if (s.status === "running") {
                const pct = s.total > 0 ? Math.round((s.processed / s.total) * 100) : 0;
                summaryEl.textContent = `Migrating… ${s.processed} / ${s.total} (${pct}%)`;
                const progressBar = `<div class="migrate-progress-bar"><div class="migrate-progress-fill" style="width:${pct}%"></div></div>`;
                resultsEl.innerHTML = `${progressBar}
                    <div class="tag-export-progress" style="margin-top:8px;">Processing tag #${s.current_tag || "…"}</div>
                    <div class="muted-small" style="margin-top:6px;">
                        <span style="color:var(--success);">✓ ${s.migrated.length} migrated</span> ·
                        <span>— ${s.skipped.length} skipped</span> ·
                        <span style="color:var(--danger);">✗ ${s.failed.length} failed</span>
                    </div>`;
                setTimeout(poll, 1500);
                return;
            }

            // Done or error — render full report
            _renderMigrationReport(s, resultsEl, summaryEl);

        } catch (e) {
            _migrationPollRetries++;
            if (_migrationPollRetries < 10) {
                // Retry — might be a transient auth issue
                setTimeout(poll, 3000);
                summaryEl.textContent = `Reconnecting… (attempt ${_migrationPollRetries})`;
                return;
            }
            resultsEl.innerHTML = `<div class="muted-small">Lost connection after ${_migrationPollRetries} retries.
                The migration may still be running in the background.
                <button class="btn-sm btn-outline" style="margin-top:8px;" onclick="_pollMigrationProgress('${jobId}')">Retry now</button></div>`;
            summaryEl.textContent = "Connection lost — migration may still be running.";
        }
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14"/><polyline points="12 5 19 12 12 19"/></svg> Migrate';
    };
    setTimeout(poll, 1000);
}

function _renderMigrationReport(s, resultsEl, summaryEl) {
    if (s.status === "error") {
        resultsEl.innerHTML = `<div style="color:var(--danger);font-weight:600;margin-bottom:8px;">Migration failed</div>
            <div class="muted-small">${escapeHtml(s.error || "Unknown error")}</div>`;
        summaryEl.textContent = "Error — see details below.";
        showToast("Migration failed", "error");
        return;
    }

    // Build detailed report
    let html = "";
    if (s.completed_at) {
        html += `<p class="muted-small" style="margin:0 0 10px 0;">Completed: ${new Date(s.completed_at).toLocaleString()}</p>`;
    }
    if (s.parent_tag_id) {
        html += `<p class="muted-small" style="margin:0 0 8px 0;">Parent tag created: <strong>${escapeHtml(s.parent_name || "")}</strong> (#${s.parent_tag_id})</p>`;
    }

    // Summary bar
    const mc = s.migrated_count || 0, sc = s.skipped_count || 0, fc = s.failed_count || 0;
    html += `<div class="migrate-report-summary">
        <span class="migrate-report-stat green">${mc} Migrated</span>
        <span class="migrate-report-stat gray">${sc} Skipped</span>
        <span class="migrate-report-stat ${fc > 0 ? "red" : "gray"}">${fc} Failed</span>
    </div>`;

    // Migrated section
    if (s.migrated && s.migrated.length) {
        html += `<details class="migrate-report-section" ${fc === 0 ? "open" : ""}>
            <summary style="color:var(--success);font-weight:600;cursor:pointer;">✓ ${mc} Migrated Successfully</summary>
            <div class="migrate-report-list">${s.migrated.map(m =>
                `<div class="migrate-report-row">
                    <span class="migrate-report-tag">${escapeHtml(m.name)}</span>
                    <span class="muted-small">→ dest #${m.dest_tag_id} (${m.operation || "create"})</span>
                </div>`
            ).join("")}</div>
        </details>`;
    }

    // Skipped section
    if (s.skipped && s.skipped.length) {
        html += `<details class="migrate-report-section">
            <summary style="color:var(--text-2);font-weight:600;cursor:pointer;">— ${sc} Skipped (System Tags)</summary>
            <div class="migrate-report-list">${s.skipped.map(sk =>
                `<div class="migrate-report-row">
                    <span class="migrate-report-tag">${escapeHtml(sk.name)}</span>
                    <span class="muted-small">${escapeHtml(sk.reason)}</span>
                </div>`
            ).join("")}</div>
        </details>`;
    }

    // Failed section — always open if there are failures
    if (s.failed && s.failed.length) {
        html += `<details class="migrate-report-section" open>
            <summary style="color:var(--danger);font-weight:600;cursor:pointer;">✗ ${fc} Failed</summary>
            <div class="migrate-report-list">${s.failed.map(f =>
                `<div class="migrate-report-row migrate-report-failed">
                    <span class="migrate-report-tag">#${f.tag_id} ${escapeHtml(f.name || "")}</span>
                    <span class="migrate-report-reason">${escapeHtml(f.reason)}</span>
                    ${f.operation ? `<span class="muted-small">(attempted: ${f.operation})</span>` : ""}
                </div>`
            ).join("")}</div>
        </details>`;
    }

    resultsEl.innerHTML = html;
    summaryEl.textContent = `Done — ${mc} migrated, ${sc} skipped, ${fc} failed.`;
    if (mc > 0) showToast(`Migration complete: ${mc} tag(s) migrated`, fc > 0 ? "warning" : "success");
    if (mc > 0) toggleTagSelectMode();
}

async function showTagDetail(id) {
    try {
        const resp = await apiFetch("/api/tags/" + id);
        const t = await resp.json();
        if (t.error) { showToast(t.error, "error"); return; }
        document.getElementById("tagDetailTitle").textContent = "Tag #" + t.tag_id + " — " + (t.name || "");
        const content = document.getElementById("tagDetailContent");
        const isSystem = t.tag_origin === "system";
        const isConnector = t.tag_origin === "connector";
        const isEditable = !!t.is_editable;
        let bannerHtml = "";
        if (isSystem) {
            bannerHtml = `<div class="tag-system-banner">
                 <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                 <span><strong>Qualys-provisioned system tag</strong>. This tag exists in every subscription and cannot be migrated or deleted.</span>
               </div>`;
        } else if (isConnector) {
            bannerHtml = `<div class="tag-system-banner tag-system-banner-editable">
                 <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                 <span><strong>Connector-dependent tag</strong>. Created by or dependent on a cloud connector. Migration requires the destination to have a matching connector configured.</span>
               </div>`;
        }
        const sysBanner = bannerHtml;
        const breadcrumb = (t.breadcrumb && t.breadcrumb.length)
            ? `<div class="tag-breadcrumb">${t.breadcrumb.map(b => `<a href="#" onclick="event.preventDefault();showTagDetail(${b.tag_id})">${escapeHtml(b.name)}</a>`).join(" / ")}<span> / ${escapeHtml(t.name || "")}</span></div>`
            : "";
        const swatch = t.color ? `<span class="tag-swatch" style="background:${escapeHtml(t.color)};display:inline-block;width:14px;height:14px;vertical-align:middle;border-radius:3px;margin-right:6px;"></span>` : "";

        let html = sysBanner + breadcrumb + `<div class="detail-meta-grid">
            <div class="detail-meta-item"><span class="detail-meta-label">Name</span><span class="detail-meta-value">${swatch}${escapeHtml(t.name || "—")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Rule Type</span><span class="detail-meta-value">${escapeHtml(t.rule_type || "—")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Color</span><span class="detail-meta-value">${escapeHtml(t.color || "—")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Criticality</span><span class="detail-meta-value">${t.criticality != null ? t.criticality : "—"}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Created</span><span class="detail-meta-value">${escapeHtml(t.created || "—")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Modified</span><span class="detail-meta-value">${escapeHtml(t.modified || "—")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Created By</span><span class="detail-meta-value">${escapeHtml(t.created_by || "—")}</span></div>
            <div class="detail-meta-item"><span class="detail-meta-label">Reserved Type</span><span class="detail-meta-value">${escapeHtml(t.reserved_type || "—")}</span></div>
        </div>`;
        if (t.description) html += `<div class="detail-section"><h4>Description</h4><div class="detail-content">${escapeHtml(t.description)}</div></div>`;
        if (t.rule_text) html += `<div class="detail-section"><h4>Rule Logic</h4><pre class="tag-rule-text">${escapeHtml(t.rule_text)}</pre></div>`;
        if (t.parent && t.parent.tag_id) {
            html += `<div class="detail-section"><h4>Parent</h4><ul class="detail-ref-list"><li><a href="#" onclick="event.preventDefault();showTagDetail(${t.parent.tag_id})">${escapeHtml(t.parent.name || "Tag " + t.parent.tag_id)}</a></li></ul></div>`;
        }
        if (t.children && t.children.length) {
            html += `<div class="detail-section"><h4>Children (${t.children.length})</h4><ul class="detail-ref-list">`;
            html += t.children.map(c => {
                const cIsSystem = !c.is_user_created;
                const cPill = cIsSystem ? ' <span class="tag-system-pill-inline">SYSTEM</span>' : '';
                const cSwatch = c.color ? `<span class="tag-swatch" style="background:${escapeHtml(c.color)};display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;"></span>` : "";
                return `<li>${cSwatch}<a href="#" onclick="event.preventDefault();showTagDetail(${c.tag_id})">${escapeHtml(c.name || "Tag " + c.tag_id)}</a>${c.rule_type ? ` <span style="color:var(--text-2);font-size:11px;">(${escapeHtml(c.rule_type)})</span>` : ""}${cPill}</li>`;
            }).join("");
            html += `</ul></div>`;
        }

        // Classification override controls — let the operator correct
        // misclassifications when the API metadata is ambiguous.
        const autoLabel = t.is_user_created_auto ? "User-created" : "System";
        const overrideVal = (t.classification_override || "").toLowerCase();
        const effectiveLabel = t.is_user_created ? "User-created" : "System";
        html += `<div class="detail-section"><h4>Classification</h4>
            <div class="detail-meta-grid">
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Auto (from API)</span>
                    <span class="detail-meta-value">${autoLabel}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Effective</span>
                    <span class="detail-meta-value">${effectiveLabel}${overrideVal ? ' <span class="badge-pill" style="font-size:10px;">manual override</span>' : ''}</span>
                </div>
            </div>
            <div style="display:flex;gap:8px;margin-top:10px;align-items:center;flex-wrap:wrap;">
                <label class="detail-meta-label" style="margin:0;">Override:</label>
                <select id="tagClassifyOverride_${t.tag_id}" onchange="setTagClassificationOverride(${t.tag_id}, this.value)" class="filter-select">
                    <option value=""${overrideVal === "" ? " selected" : ""}>Auto (use API metadata)</option>
                    <option value="user"${overrideVal === "user" ? " selected" : ""}>Force User-created</option>
                    <option value="system"${overrideVal === "system" ? " selected" : ""}>Force System (read-only)</option>
                </select>
            </div>
            <p class="muted-small" style="margin-top:8px;">If auto-classification is wrong for this tag, override it. Stored locally — does not affect Qualys.</p>
        </div>`;

        // Editability override — independent of system/user.
        // Auto-derivation: user tags = editable; system tags whose
        // reservedType is in the locked taxonomy (OS, region, etc.)
        // = not editable; everything else = editable.
        const editAuto = t.is_editable_auto ? "Editable" : "Locked";
        const editOverrideVal = (t.editability_override || "").toLowerCase();
        const editEffective = isEditable ? "Editable" : "Locked";
        html += `<div class="detail-section"><h4>Editability</h4>
            <div class="detail-meta-grid">
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Auto (from API)</span>
                    <span class="detail-meta-value">${editAuto}</span>
                </div>
                <div class="detail-meta-item">
                    <span class="detail-meta-label">Effective</span>
                    <span class="detail-meta-value">${editEffective}${editOverrideVal ? ' <span class="badge-pill" style="font-size:10px;">manual override</span>' : ''}</span>
                </div>
            </div>
            <div style="display:flex;gap:8px;margin-top:10px;align-items:center;flex-wrap:wrap;">
                <label class="detail-meta-label" style="margin:0;">Override:</label>
                <select id="tagEditOverride_${t.tag_id}" onchange="setTagEditabilityOverride(${t.tag_id}, this.value)" class="filter-select">
                    <option value=""${editOverrideVal === "" ? " selected" : ""}>Auto (use API metadata)</option>
                    <option value="editable"${editOverrideVal === "editable" ? " selected" : ""}>Force Editable</option>
                    <option value="locked"${editOverrideVal === "locked" ? " selected" : ""}>Force Locked</option>
                </select>
            </div>
            <p class="muted-small" style="margin-top:8px;">Use Force Editable for system tags like Internet Facing Assets where customers customize the rule. Stored locally; the Qualys API still has the final say when edit support ships.</p>
        </div>`;

        // Phase 3 CRUD — Edit / Delete buttons gated on effective
        // is_editable. The form modal handles validation, Test on
        // Qualys preview, and Save. Locked tags get a hint pointing
        // at the Force Editable override.
        if (isEditable) {
            html += `<div class="detail-section"><h4>Edit this tag</h4>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    <button class="btn-sm" onclick="openTagEditForm(${t.tag_id})">Edit…</button>
                    <button class="btn-sm btn-danger" onclick="openTagDeleteConfirm(${t.tag_id})">Delete tag</button>
                </div>
                <p class="muted-small" style="margin-top:8px;">Edits and deletes go straight to Qualys. Use the form's <strong>Test on Qualys</strong> button to preview rule changes against the asset universe before saving.</p>
            </div>`;
        } else {
            html += `<div class="detail-section"><h4>Edit this tag</h4>
                <p class="muted-small">Editing is disabled because this tag is currently classified as locked. If Qualys actually allows edits to it (some system tags like Internet Facing Assets do), set the editability override to <strong>Force Editable</strong> above and the Edit / Delete buttons will appear.</p>
            </div>`;
        }

        // Phase 2 migration — Export pulls the tag's full JSON from
        // the source environment and stages it locally. From there the
        // operator can either download the file or upload it into a
        // different Qualys environment via the Tags Migration card.
        // System tags can't be migrated (Qualys rejects creates with
        // reservedType set) so the section is informational for them.
        const isSystemTag = !t.is_user_created;
        html += `<div class="detail-section"><h4>Migrate to another environment</h4>`;
        if (isSystemTag) {
            html += `<p class="muted-small">System tags exist by default in every Qualys environment, so no migration is needed. The Qualys API rejects create-tag requests with a reservedType set.</p>`;
        } else {
            html += `
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                    <button class="btn-sm btn-outline" onclick="exportTagToLocal(${t.tag_id})">
                        Export Tag
                    </button>
                    <button class="btn-sm btn-outline" onclick="window.location.href='/api/tags/${t.tag_id}/export-download'">
                        Download JSON
                    </button>
                </div>
                <p class="muted-small" style="margin-top:8px;">Export captures this tag's full JSON from the source environment. Once exported, push it into a destination environment from the <strong>Migration</strong> card on the Tags tab.</p>`;
        }
        html += `</div>`;

        // Raw API payload — collapsed by default. Useful for debugging
        // mis-classifications and seeing which fields Qualys actually
        // returned for this tag.
        if (t.raw_json) {
            html += `<div class="detail-section">
                <h4 style="cursor:pointer;user-select:none;" onclick="(function(el){const b=el.nextElementSibling;b.style.display=b.style.display==='none'?'':'none';})(this)">
                    Raw API Payload <span class="muted-small">(click to toggle)</span>
                </h4>
                <pre class="tag-rule-text" style="display:none;max-height:400px;overflow:auto;">${escapeHtml(typeof t.raw_json === 'string' ? t.raw_json : JSON.stringify(t.raw_json, null, 2))}</pre>
            </div>`;
        }

        content.innerHTML = html;
        openModal("tagDetailModal");
    } catch (e) { showToast("Failed to load tag detail", "error"); }
}

async function setTagClassificationOverride(tagId, value) {
    try {
        const body = { classification: value === "" ? null : value };
        const resp = await apiFetch("/api/tags/" + tagId + "/classify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const result = await resp.json();
        if (result.error) { showToast(result.error, "error"); return; }
        showToast("Classification updated", "success");
        // Refresh the modal and the underlying list
        showTagDetail(tagId);
        searchTags();
    } catch (e) {
        showToast("Failed to update classification: " + e.message, "error");
    }
}

// ─── Tag Phase 5: Subscription audit ────────────────────────────────────
// Read-only inventory analysis. Backend does the heavy lifting in
// app/tag_audit.py; the UI just renders grouped findings with a
// severity-colored summary at the top and per-finding View Tag links.

const _AUDIT_SEV_LABELS = {
    error: { label: "Errors", color: "var(--danger, #ef4444)" },
    warn:  { label: "Warnings", color: "var(--warning, #f59e0b)" },
    info:  { label: "Informational", color: "var(--text-2)" },
};

const _AUDIT_RULE_LABELS = {
    HIERARCHY_ORPHAN:        "Orphaned parent reference",
    HIERARCHY_CYCLE:         "Hierarchy cycle",
    HIERARCHY_TOO_DEEP:      "Hierarchy depth exceeds Qualys limit",
    HIERARCHY_WIDE_ROOT:     "Wide root branch",
    NAMING_EMPTY:            "Empty name",
    NAMING_WHITESPACE:       "Whitespace in name",
    NAMING_TOO_LONG:         "Name exceeds Qualys hard limit",
    NAMING_LONG:             "Name longer than recommended",
    NAMING_SHORT:            "Name shorter than recommended",
    NAMING_DUPLICATE:        "Duplicate name (case-insensitive)",
    DUPLICATE_RULE:          "Duplicate rule text",
    CLASSIFICATION_OVERRIDE: "Classification overridden manually",
    EDITABILITY_OVERRIDE:    "Editability overridden manually",
};

async function runTagAudit() {
    const resultsEl = document.getElementById("tagAuditResults");
    const summaryEl = document.getElementById("tagAuditSummary");
    resultsEl.innerHTML = '<p class="muted-small">Running…</p>';
    summaryEl.textContent = "";
    try {
        const resp = await apiFetch("/api/tags/audit");
        const data = await resp.json();
        _renderAuditSummary(data.summary || {});
        _renderAuditGroups(data.groups || []);
    } catch (e) {
        resultsEl.innerHTML = `<p class="muted-small">Audit failed: ${escapeHtml(e.message)}</p>`;
    }
}

function _renderAuditSummary(summary) {
    const summaryEl = document.getElementById("tagAuditSummary");
    const total = summary.total || 0;
    const tags = summary.tag_count || 0;
    if (total === 0) {
        summaryEl.innerHTML = `<span style="color:var(--success, #22c55e);">✔ Clean — no findings</span> across ${tags.toLocaleString()} tag(s).`;
        return;
    }
    const parts = [];
    ["error", "warn", "info"].forEach(s => {
        const n = summary[s] || 0;
        if (n > 0) {
            const meta = _AUDIT_SEV_LABELS[s];
            parts.push(`<span style="color:${meta.color};font-weight:600;">${n} ${meta.label.toLowerCase()}</span>`);
        }
    });
    summaryEl.innerHTML = parts.join(" · ") + ` across ${tags.toLocaleString()} tag(s)`;
}

function _renderAuditGroups(groups) {
    const resultsEl = document.getElementById("tagAuditResults");
    if (groups.length === 0) {
        resultsEl.innerHTML = `<div class="audit-clean-state">
            <p style="color:var(--success, #22c55e);font-weight:600;font-size:14px;margin:0 0 10px 0;">All checks passed — your tag inventory is healthy.</p>
            <p class="muted-small" style="margin:0 0 8px 0;">The audit verified the following and found no issues:</p>
            <ul class="muted-small audit-checks-list">
                <li><strong>No orphaned parent references</strong> — every tag that references a parent points to a tag that exists</li>
                <li><strong>No hierarchy cycles</strong> — no tag is its own ancestor (which would break Qualys rendering)</li>
                <li><strong>Hierarchy depth within limits</strong> — no branch exceeds Qualys' maximum nesting depth</li>
                <li><strong>No duplicate names</strong> — each tag name is unique (case-insensitive), avoiding confusion in reports</li>
                <li><strong>No duplicate rule text</strong> — no two tags evaluate the same rule, which would waste processing</li>
                <li><strong>Naming standards met</strong> — no empty, excessively long, or whitespace-only names</li>
                <li><strong>No manual overrides</strong> — classification and editability settings are at defaults</li>
            </ul>
        </div>`;
        return;
    }
    resultsEl.innerHTML = groups.map(g => {
        const sevMeta = _AUDIT_SEV_LABELS[g.severity] || _AUDIT_SEV_LABELS.info;
        const label = _AUDIT_RULE_LABELS[g.rule_id] || g.rule_id;
        const description = _AUDIT_RULE_DESCRIPTIONS[g.rule_id] || "";
        const isDuplicate = g.rule_id === "NAMING_DUPLICATE" || g.rule_id === "DUPLICATE_RULE";
        const findings = isDuplicate
            ? _renderDuplicateFindings(g.findings, g.rule_id)
            : g.findings.map(_auditFindingHtml).join("");
        return `<details class="audit-group" data-severity="${g.severity}" open>
            <summary>
                <span class="audit-sev-pill" style="background:${sevMeta.color};">${escapeHtml(g.severity.toUpperCase())}</span>
                <strong>${escapeHtml(label)}</strong>
                <span class="muted-small">${g.count} finding${g.count === 1 ? "" : "s"}</span>
            </summary>
            ${description ? `<p class="audit-rule-desc">${escapeHtml(description)}</p>` : ""}
            <div class="audit-finding-list">${findings}</div>
        </details>`;
    }).join("");
}

const _AUDIT_RULE_DESCRIPTIONS = {
    HIERARCHY_ORPHAN: "These tags reference a parent_tag_id that doesn't exist in the local inventory. The parent may have been deleted or never synced.",
    HIERARCHY_CYCLE: "A tag references itself (directly or indirectly) as its own parent, creating an infinite loop that Qualys cannot render.",
    HIERARCHY_TOO_DEEP: "The tag's ancestry chain exceeds Qualys' maximum nesting depth (8 levels). Move it closer to root.",
    HIERARCHY_WIDE_ROOT: "A single root tag has an unusually large number of direct children — consider adding intermediate grouping tags.",
    NAMING_EMPTY: "Tags with no name are invisible in most Qualys UIs and can't be referenced by QQL.",
    NAMING_WHITESPACE: "Leading/trailing whitespace in tag names causes matching issues in reports and QQL queries.",
    NAMING_TOO_LONG: "Exceeds the Qualys 255-character hard limit — the API will reject updates.",
    NAMING_LONG: "Longer than recommended (80 chars) — may truncate in dashboards and reports.",
    NAMING_SHORT: "Very short names (1-2 chars) are ambiguous and hard to find.",
    NAMING_DUPLICATE: "Multiple tags share the same name (case-insensitive). This causes confusion in reports, QQL queries, and tag-based scan scoping since operators can't tell them apart.",
    DUPLICATE_RULE: "Multiple tags evaluate the identical rule text. Both tags will match the same assets, wasting Qualys processing and confusing operators about which tag to use.",
    CLASSIFICATION_OVERRIDE: "The auto-detected user/system classification has been manually overridden.",
    EDITABILITY_OVERRIDE: "The default editability has been manually overridden.",
};

function _renderDuplicateFindings(findings, ruleId) {
    // Group duplicate findings by their shared refs (cluster related tags together)
    const clusters = [];
    const seen = new Set();

    for (const f of findings) {
        if (seen.has(f.tag_id)) continue;
        const cluster = [f];
        seen.add(f.tag_id);
        if (f.refs && f.refs.length) {
            for (const refId of f.refs) {
                const refFinding = findings.find(x => x.tag_id === refId);
                if (refFinding && !seen.has(refId)) {
                    cluster.push(refFinding);
                    seen.add(refId);
                }
            }
        }
        clusters.push(cluster);
    }

    return clusters.map(cluster => {
        const isDuplicateName = ruleId === "NAMING_DUPLICATE";
        const sharedValue = isDuplicateName
            ? cluster[0].name || "(unknown)"
            : (cluster[0].message || "").match(/"([^"]+)"$/)?.[1] || "(same rule)";
        const label = isDuplicateName ? "Shared name" : "Shared rule";

        // Render each tag as a full card (same as Browse tab)
        const tagCards = cluster.map(f => {
            // Build a tag-like object from the finding for _tagCardHtml
            const t = {
                tag_id: f.tag_id,
                name: f.name || "",
                color: f.color || null,
                rule_type: f.rule_type || null,
                description: f.description || null,
                is_user_created: f.is_user_created !== undefined ? f.is_user_created : 1,
                reserved_type: f.reserved_type || null,
            };
            return _tagCardHtml(t);
        }).join("");

        return `<div class="audit-dup-cluster">
            <div class="audit-dup-header">
                <strong>${escapeHtml(label)}:</strong> <code>${escapeHtml(sharedValue)}</code>
                <span class="muted-small">(${cluster.length} tags)</span>
            </div>
            <div class="audit-dup-tags">${tagCards}</div>
            <div class="audit-hint muted-small">→ ${escapeHtml(cluster[0].hint || "Consider merging these or adding descriptions to explain why both exist.")}</div>
        </div>`;
    }).join("");
}

function _auditFindingHtml(f) {
    const tagLink = f.tag_id
        ? `<a href="#" onclick="event.preventDefault();showTagDetail(${f.tag_id});return false;">#${f.tag_id}${f.name ? ` · ${escapeHtml(f.name)}` : ""}</a>`
        : `<span class="muted-small">(no tag)</span>`;
    const refs = (f.refs && f.refs.length)
        ? `<div class="muted-small">Related: ${f.refs.map(id => `<a href="#" onclick="event.preventDefault();showTagDetail(${id});return false;">#${id}</a>`).join(", ")}</div>`
        : "";
    const hint = f.hint ? `<div class="muted-small audit-hint">→ ${escapeHtml(f.hint)}</div>` : "";
    return `<div class="audit-finding">
        <div class="audit-finding-head">${tagLink}</div>
        <div>${escapeHtml(f.message || "")}</div>
        ${refs}${hint}
    </div>`;
}


// ─── Tag Phase 4: Custom Library + Apply ────────────────────────────────
// A curated bank of tag definitions (built-in starter set + user
// entries) that the operator can apply into any Qualys environment.
// Reuses the Phase 3 create-tag plumbing on the server side; this
// module is the UI: list, filter, edit, apply, history.

let _libraryEntries = [];
let _libraryFilterTimer = null;
let _pendingLibraryApply = null;     // entry being applied
let _libraryFormState = { mode: "create", entryId: null };

function loadLibraryDebounced() {
    if (_libraryFilterTimer) clearTimeout(_libraryFilterTimer);
    _libraryFilterTimer = setTimeout(loadLibrary, 200);
}

async function loadLibrary() {
    const container = document.getElementById("libraryList");
    if (!container) return;
    const q = (document.getElementById("libraryFilterText").value || "").trim();
    const cat = document.getElementById("libraryFilterCategory").value || "";
    const showHidden = document.getElementById("libraryShowHidden").checked;
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (cat) params.set("category", cat);
    if (showHidden) params.set("include_hidden", "1");
    try {
        const resp = await apiFetch("/api/library?" + params.toString());
        const entries = await resp.json();
        _libraryEntries = Array.isArray(entries) ? entries : [];
        _renderLibraryList(_libraryEntries);
        _refreshLibraryCategoryDropdown(_libraryEntries);
    } catch (e) {
        container.innerHTML = `<p class="muted-small">Failed to load library: ${escapeHtml(e.message)}</p>`;
    }
}

function _refreshLibraryCategoryDropdown(entries) {
    const sel = document.getElementById("libraryFilterCategory");
    if (!sel) return;
    const current = sel.value;
    const cats = Array.from(new Set(entries.map(e => e.category).filter(Boolean))).sort();
    sel.innerHTML = '<option value="">All categories</option>'
        + cats.map(c => `<option value="${escapeHtml(c)}"${c === current ? " selected" : ""}>${escapeHtml(c)}</option>`).join("");
}

function _renderLibraryList(entries) {
    const container = document.getElementById("libraryList");
    if (!entries.length) {
        container.innerHTML = `<p class="muted-small">No library entries match.</p>`;
        return;
    }
    // Group by rule_type
    const groups = {};
    for (const e of entries) {
        const rt = e.rule_type || "UNKNOWN";
        if (!groups[rt]) groups[rt] = [];
        groups[rt].push(e);
    }
    // Sort groups: ASSET_INVENTORY first, then alphabetically
    const order = Object.keys(groups).sort((a, b) => {
        if (a === "ASSET_INVENTORY") return -1;
        if (b === "ASSET_INVENTORY") return 1;
        return a.localeCompare(b);
    });
    let html = "";
    for (const rt of order) {
        const items = groups[rt];
        const statusInfo = TAG_RULE_TYPE_STATUS[rt];
        const statusPill = statusInfo
            ? ` <span class="badge-pill badge-pill-${statusInfo.status}">${statusInfo.status}</span>`
            : "";
        html += `<div class="library-group collapsed">
            <div class="library-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <svg class="library-group-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                <strong>${escapeHtml(rt)}</strong>${statusPill}
                <span class="muted-small">(${items.length})</span>
            </div>
            <div class="library-group-body">
                ${items.map(_libraryRowHtml).join("")}
            </div>
        </div>`;
    }
    container.innerHTML = html;
}

function openLibraryDetail(libraryId) {
    const entry = _libraryEntries.find(e => e.library_id === libraryId);
    if (!entry) return;
    document.getElementById("libraryDetailTitle").textContent = entry.name;
    const notice = _libraryRuleNotice(entry);
    const sw = entry.color ? `<span class="tag-swatch" style="background:${escapeHtml(entry.color)};display:inline-block;width:14px;height:14px;border-radius:3px;vertical-align:middle;margin-right:6px;"></span>` : "";
    const sourceLink = entry.source_url
        ? `<a href="${escapeHtml(entry.source_url)}" target="_blank" rel="noopener">${escapeHtml(entry.source_url)}</a>`
        : '<span class="muted-small">None</span>';
    document.getElementById("libraryDetailContent").innerHTML = `
        ${notice}
        <table class="library-detail-table">
            <tr><th>Name</th><td>${sw}${escapeHtml(entry.name)}</td></tr>
            <tr><th>Category</th><td>${escapeHtml(entry.category || "")}</td></tr>
            <tr><th>Description</th><td>${escapeHtml(entry.description || "")}</td></tr>
            <tr><th>Rationale</th><td>${escapeHtml(entry.rationale || "")}</td></tr>
            <tr><th>Rule Type</th><td><code>${escapeHtml(entry.rule_type || "")}</code></td></tr>
            <tr><th>Rule Text</th><td><pre class="library-detail-pre">${escapeHtml(entry.rule_text || "(none)")}</pre></td></tr>
            <tr><th>Color</th><td>${entry.color ? `<span class="tag-swatch" style="background:${escapeHtml(entry.color)};display:inline-block;width:14px;height:14px;border-radius:3px;vertical-align:middle;"></span> ${escapeHtml(entry.color)}` : "None"}</td></tr>
            <tr><th>Criticality</th><td>${entry.criticality || "—"}</td></tr>
            <tr><th>Suggested Parent</th><td>${escapeHtml(entry.suggested_parent || "None")}</td></tr>
            <tr><th>Source</th><td>${sourceLink}</td></tr>
            <tr><th>Type</th><td>${entry.is_builtin ? "Built-in (read-only)" : "User-created"}</td></tr>
        </table>
    `;
    document.getElementById("libraryDetailCloneBtn").onclick = function() {
        closeModal("libraryDetailModal");
        cloneLibraryEntry(libraryId);
    };
    document.getElementById("libraryDetailApplyBtn").onclick = function() {
        closeModal("libraryDetailModal");
        openLibraryApply(libraryId);
    };
    openModal("libraryDetailModal");
}

function _libraryRuleNotice(e) {
    const status = TAG_RULE_TYPE_STATUS[e.rule_type];
    if (!status) return "";
    if (status.status === "legacy") {
        const alt = status.replacement || "GLOBAL_ASSET_VIEW";
        return `<div class="library-notice library-notice-legacy" title="${escapeHtml(status.notes || "")}">` +
            `<strong>Legacy rule type.</strong> Qualys now recommends <code>${escapeHtml(alt)}</code> for better performance and CSAM compatibility. ` +
            `Consider cloning this entry and rewriting the rule as a ${escapeHtml(alt)} query.` +
            `</div>`;
    }
    if (status.status === "restricted") {
        return `<div class="library-notice library-notice-restricted" title="${escapeHtml(status.notes || "")}">` +
            `<strong>Restricted rule type.</strong> GROOVY must be enabled by Qualys support/your TAM before use. ` +
            `Use "Test on Qualys" to verify your subscription supports it.` +
            `</div>`;
    }
    return "";
}

function _libraryRowHtml(e) {
    const builtinPill = e.is_builtin ? '<span class="badge-pill" title="Ships with the app">built-in</span>' : '';
    const hiddenPill = e.is_hidden ? '<span class="badge-pill" style="background:var(--bg-2);color:var(--text-2);">hidden</span>' : '';
    const cat = e.category ? `<span class="badge-pill">${escapeHtml(e.category)}</span>` : '';
    const sw = e.color ? `<span class="tag-swatch" style="background:${escapeHtml(e.color)};display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;"></span>` : '';
    const hideBtn = e.is_hidden
        ? `<button class="btn-sm btn-outline" onclick="event.stopPropagation();unhideLibraryEntry(${e.library_id})">Unhide</button>`
        : (e.is_builtin
            ? `<button class="btn-sm btn-outline" onclick="event.stopPropagation();hideLibraryEntry(${e.library_id})" title="Hide from default view">Hide</button>`
            : `<button class="btn-sm btn-outline btn-danger" onclick="event.stopPropagation();deleteLibraryEntry(${e.library_id})" title="Delete this user entry">×</button>`);
    return `<div class="library-row library-row-clickable" data-id="${e.library_id}" onclick="openLibraryDetail(${e.library_id})">
        <div class="library-meta">
            <strong>${sw}${escapeHtml(e.name)}</strong> ${cat} ${builtinPill} ${hiddenPill}
            <div class="muted-small">${escapeHtml(e.description || "")}</div>
        </div>
        <div class="library-actions">
            <button class="btn-sm btn-primary" onclick="event.stopPropagation();openLibraryApply(${e.library_id})">Apply</button>
            <button class="btn-sm btn-outline" onclick="event.stopPropagation();cloneLibraryEntry(${e.library_id})">Clone</button>
            ${hideBtn}
        </div>
    </div>`;
}

// ── Apply flow ──

function openLibraryApply(libraryId) {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a Qualys platform first", "error"); return; }
    const entry = _libraryEntries.find(e => e.library_id === libraryId);
    if (!entry) { showToast("Library entry not found in cache — refresh the list", "error"); return; }
    _pendingLibraryApply = entry;
    document.getElementById("libraryApplySourceName").textContent = entry.name;
    document.getElementById("libraryApplySourceMeta").textContent =
        " · " + entry.category + (entry.rule_type ? " · " + entry.rule_type : "");
    const rationaleEl = document.getElementById("libraryApplyRationale");
    const noticeHtml = _libraryRuleNotice(entry);
    if (entry.rationale || entry.source_url || noticeHtml) {
        rationaleEl.style.display = "";
        rationaleEl.innerHTML = noticeHtml
            + (entry.rationale ? `<p>${escapeHtml(entry.rationale)}</p>` : "")
            + (entry.source_url ? `<p class="muted-small">Source: <a href="${escapeHtml(entry.source_url)}" target="_blank" rel="noopener">${escapeHtml(entry.source_url)}</a></p>` : "");
    } else {
        rationaleEl.style.display = "none";
    }
    document.getElementById("libraryApplyNewName").value = "";
    document.getElementById("libraryApplyParent").value = "";
    document.getElementById("libraryApplyRuleText").value = "";
    if (entry.color) document.getElementById("libraryApplyColor").value = entry.color;
    document.getElementById("libraryApplyCriticality").value = "";
    document.getElementById("libraryApplyTestResult").style.display = "none";
    fetch("/api/credentials").then(r => r.json()).then(creds => {
        const sel = document.getElementById("libraryApplyCredSelect");
        sel.innerHTML = '<option value="">-- pick destination credential --</option>'
            + (Array.isArray(creds) ? creds.map(c =>
                `<option value="${c.id}" data-platform="${c.platform_id || ""}">${escapeHtml(formatCredLabel(c))}</option>`
            ).join("") : "");
    }).catch(() => {});
    openModal("libraryApplyModal");
}

function _gatherLibraryApplyForm() {
    const sel = document.getElementById("libraryApplyCredSelect");
    const credId = sel.value;
    const platform = sel.options[sel.selectedIndex]?.dataset.platform || "";
    const overrides = {};
    const rt = document.getElementById("libraryApplyRuleText").value.trim();
    if (rt) overrides.rule_text = rt;
    const color = document.getElementById("libraryApplyColor").value;
    if (color && _pendingLibraryApply && color !== _pendingLibraryApply.color) overrides.color = color;
    const crit = document.getElementById("libraryApplyCriticality").value.trim();
    if (crit) overrides.criticality = crit;
    return {
        credential_id: credId,
        platform: platform,
        new_name: document.getElementById("libraryApplyNewName").value.trim() || null,
        parent_tag_id: document.getElementById("libraryApplyParent").value.trim() || null,
        overrides,
    };
}

async function testLibraryApplyOnQualys() {
    if (!_pendingLibraryApply) return;
    const form = _gatherLibraryApplyForm();
    if (!form.credential_id) { showToast("Pick a destination credential first", "error"); return; }
    // Build the same form-shape Phase 3 test endpoint expects.
    const entry = _pendingLibraryApply;
    const overrides = form.overrides || {};
    const tagForm = {
        name: form.new_name || entry.name,
        color: overrides.color || entry.color,
        criticality: overrides.criticality !== undefined && overrides.criticality !== "" ? overrides.criticality : entry.criticality,
        description: entry.description,
        rule_type: entry.rule_type,
        rule_text: overrides.rule_text !== undefined ? overrides.rule_text : entry.rule_text,
        parent_tag_id: form.parent_tag_id,
        credential_id: form.credential_id,
        platform: form.platform,
    };
    const resultEl = document.getElementById("libraryApplyTestResult");
    resultEl.style.display = "";
    resultEl.className = "tag-form-test loading";
    resultEl.textContent = "Asking Qualys to evaluate the rule…";
    try {
        const resp = await apiFetch("/api/tags/test-rule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(tagForm),
        });
        const result = await resp.json();
        if (!resp.ok || result.ok === false) {
            resultEl.className = "tag-form-test error";
            resultEl.textContent = result.message || "Test failed";
            return;
        }
        if (result.stage === "fallback") {
            resultEl.className = "tag-form-test warn";
            resultEl.textContent = "Qualys preview not available on this tenant — relying on local validation.";
            return;
        }
        const count = result.asset_count;
        resultEl.className = "tag-form-test success";
        resultEl.textContent = (count != null
            ? "Qualys evaluated the rule against " + count.toLocaleString() + " matching asset(s)."
            : "Qualys accepted the rule.");
    } catch (e) {
        resultEl.className = "tag-form-test error";
        resultEl.textContent = "Test failed: " + e.message;
    }
}

async function confirmLibraryApply() {
    if (!_pendingLibraryApply) return;
    const form = _gatherLibraryApplyForm();
    if (!form.credential_id) { showToast("Pick a destination credential", "error"); return; }
    try {
        const resp = await apiFetch("/api/library/" + _pendingLibraryApply.library_id + "/apply", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(form),
        });
        const result = await resp.json();
        if (!resp.ok || result.error) {
            const detail = result.errors
                ? Object.entries(result.errors).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ")
                : "";
            showToast((result.error || "Apply failed") + (detail ? " — " + detail : ""), "error");
            return;
        }
        showToast("Applied — destination tag id " + (result.destination_tag_id || "?"), "success");
        closeModal("libraryApplyModal");
        _pendingLibraryApply = null;
        searchTags();
    } catch (e) {
        showToast("Apply failed: " + e.message, "error");
    }
}

// ── Entry CRUD ──

function openLibraryEntryForm(libraryId) {
    _libraryFormState = { mode: libraryId ? "edit" : "create", entryId: libraryId || null };
    document.getElementById("libraryEntryFormTitle").textContent =
        libraryId ? "Edit library entry" : "New library entry";
    _populateLibraryRuleType();
    if (!libraryId) {
        _resetLibraryEntryForm();
        openModal("libraryEntryFormModal");
        return;
    }
    apiFetch("/api/library/" + libraryId).then(r => r.json()).then(e => {
        if (e.error) { showToast(e.error, "error"); return; }
        document.getElementById("libEntryName").value = e.name || "";
        document.getElementById("libEntryCategory").value = e.category || "Custom";
        document.getElementById("libEntryColor").value = e.color || "#22c55e";
        document.getElementById("libEntryCriticality").value = e.criticality || "";
        document.getElementById("libEntryDescription").value = e.description || "";
        document.getElementById("libEntryRationale").value = e.rationale || "";
        document.getElementById("libEntrySourceUrl").value = e.source_url || "";
        document.getElementById("libEntrySuggestedParent").value = e.suggested_parent || "";
        document.getElementById("libEntryRuleType").value = e.rule_type || "";
        document.getElementById("libEntryRuleText").value = e.rule_text || "";
        _onLibEntryRuleTypeChange();
        openModal("libraryEntryFormModal");
    });
}

function _resetLibraryEntryForm() {
    ["libEntryName","libEntryCategory","libEntryCriticality","libEntryDescription","libEntryRationale","libEntrySourceUrl","libEntrySuggestedParent","libEntryRuleText"].forEach(id => {
        document.getElementById(id).value = id === "libEntryCategory" ? "Custom" : "";
    });
    document.getElementById("libEntryColor").value = "#22c55e";
    document.getElementById("libEntryRuleType").value = "";
    document.getElementById("libEntryRuleTextHelp").textContent = "";
    document.getElementById("libEntryFormSummary").style.display = "none";
}

function _populateLibraryRuleType() {
    const sel = document.getElementById("libEntryRuleType");
    if (!sel || sel.options.length > 1) return;
    sel.innerHTML = '<option value="">-- pick a rule type --</option>'
        + TAG_RULE_TYPES.map(t => `<option value="${t}">${_ruleTypeOptionLabel(t)}</option>`).join("");
    sel.onchange = _onLibEntryRuleTypeChange;
}

function _onLibEntryRuleTypeChange() {
    const rt = document.getElementById("libEntryRuleType").value;
    document.getElementById("libEntryRuleTextHelp").textContent =
        rt ? (TAG_RULE_TEXT_HELP[rt] || "") : "";
    _setRuleTypeStatusBanner("libEntryRuleTypeStatus", rt);
}

async function submitLibraryEntryForm() {
    const body = {
        name: document.getElementById("libEntryName").value,
        category: document.getElementById("libEntryCategory").value,
        color: document.getElementById("libEntryColor").value,
        criticality: document.getElementById("libEntryCriticality").value,
        description: document.getElementById("libEntryDescription").value,
        rationale: document.getElementById("libEntryRationale").value,
        source_url: document.getElementById("libEntrySourceUrl").value,
        suggested_parent: document.getElementById("libEntrySuggestedParent").value,
        rule_type: document.getElementById("libEntryRuleType").value,
        rule_text: document.getElementById("libEntryRuleText").value,
    };
    const isEdit = _libraryFormState.mode === "edit";
    const url = isEdit ? "/api/library/" + _libraryFormState.entryId : "/api/library";
    const method = isEdit ? "PATCH" : "POST";
    try {
        const resp = await apiFetch(url, {
            method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const result = await resp.json();
        if (!resp.ok || result.error) {
            const summary = document.getElementById("libEntryFormSummary");
            summary.style.display = "";
            summary.innerHTML = _summaryHtml(result);
            return;
        }
        showToast(isEdit ? "Library entry updated" : "Library entry created", "success");
        closeModal("libraryEntryFormModal");
        loadLibrary();
    } catch (e) {
        showToast("Save failed: " + e.message, "error");
    }
}

async function deleteLibraryEntry(libraryId) {
    if (!await themedConfirm("Delete this library entry? Removing a built-in just hides it; user entries are removed.")) return;
    try {
        const resp = await apiFetch("/api/library/" + libraryId, { method: "DELETE" });
        const result = await resp.json();
        if (!resp.ok || result.error) { showToast(result.error || "Delete failed", "error"); return; }
        showToast("Library entry removed", "success");
        loadLibrary();
    } catch (e) { showToast("Delete failed: " + e.message, "error"); }
}

async function hideLibraryEntry(libraryId) {
    deleteLibraryEntry(libraryId);  // delete on a built-in == hide
}

async function unhideLibraryEntry(libraryId) {
    try {
        const resp = await apiFetch("/api/library/" + libraryId + "/unhide", { method: "POST" });
        const result = await resp.json();
        if (!resp.ok || result.error) { showToast(result.error || "Unhide failed", "error"); return; }
        showToast("Library entry unhidden", "success");
        loadLibrary();
    } catch (e) { showToast("Unhide failed: " + e.message, "error"); }
}

async function cloneLibraryEntry(libraryId) {
    try {
        const resp = await apiFetch("/api/library/" + libraryId + "/clone", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
        const result = await resp.json();
        if (!resp.ok || result.error) { showToast(result.error || "Clone failed", "error"); return; }
        showToast("Cloned — opening edit form", "success");
        loadLibrary();
        if (result.library_id) openLibraryEntryForm(result.library_id);
    } catch (e) { showToast("Clone failed: " + e.message, "error"); }
}

// ── Apply history ──

async function openLibraryApplyHistory(libraryId) {
    document.getElementById("libraryHistoryTitle").textContent =
        libraryId ? "Apply history for entry #" + libraryId : "All library applies";
    const list = document.getElementById("libraryHistoryList");
    list.innerHTML = '<p class="muted-small">Loading…</p>';
    openModal("libraryHistoryModal");
    const url = libraryId ? `/api/library/${libraryId}/applies` : "/api/library/applies";
    try {
        const resp = await apiFetch(url);
        const rows = await resp.json();
        if (!Array.isArray(rows) || rows.length === 0) {
            list.innerHTML = '<p class="muted-small">No applies recorded yet.</p>';
            return;
        }
        list.innerHTML = '<table class="data-table" style="width:100%;font-size:12px;">'
            + '<thead><tr><th>When</th><th>Library entry</th><th>Destination</th><th>Tag id</th></tr></thead>'
            + '<tbody>' + rows.map(r =>
                `<tr>
                    <td>${escapeHtml(r.applied_at || "")}</td>
                    <td>${escapeHtml(r.library_name || ("entry " + r.library_id))}</td>
                    <td>${escapeHtml(r.destination_platform || "")} · ${escapeHtml(r.destination_credential_id || "")}</td>
                    <td>${escapeHtml(String(r.destination_tag_id || ""))}</td>
                </tr>`
            ).join("") + '</tbody></table>';
    } catch (e) {
        list.innerHTML = `<p class="muted-small">Failed to load: ${escapeHtml(e.message)}</p>`;
    }
}


// ─── Tag Phase 3: CRUD pushed to Qualys ─────────────────────────────────
// Edit / Delete / Create flows. The same form modal serves both Edit
// (preloaded with a current tag) and Create (blank). Validation runs:
//   - On every keystroke (debounced) → server-side /api/tags/validate
//   - On Test on Qualys click          → server-side /api/tags/test-rule
//   - On Save                          → server-side via the create /
//                                         update endpoint, which re-runs
//                                         validation as defense in depth
// Save button stays disabled until validation passes; warnings (vs.
// errors) don't gate Save.

// Canonical rule types + per-type help text. Mirrors
// app.tag_validation.RULE_TEXT_HELP intentionally — keeping the
// strings here means the form gives instant guidance without a
// network round-trip.
const TAG_RULE_TYPES = [
    "GLOBAL_ASSET_VIEW", "CLOUD_ASSET", "STATIC", "NETWORK_RANGE",
    "NETWORK_RANGE_ENHANCED", "VULN_EXIST", "VULN_DETECTION",
    "ASSET_SEARCH", "NAME_CONTAINS", "OPEN_PORTS", "INSTALLED_SOFTWARE",
    "ASSET_GROUP", "BUSINESS_INFORMATION", "BUSINESS_INFO", "TAG_SET",
    "OS_REGEX", "OPERATING_SYSTEM", "ASSET_INVENTORY", "GROOVY",
];
const TAG_RULE_TEXT_OPTIONAL = new Set(["STATIC", "ASSET_GROUP", "TAG_SET"]);

// Best-practice / availability metadata shown in the form. Mirrors
// app.tag_validation.RULE_TYPE_STATUS so the form gives the operator
// immediate guidance before they build the rule_text. Status pills
// appear next to the rule-type dropdown and in the dropdown options.
const TAG_RULE_TYPE_STATUS = {
    OS_REGEX: {
        status: "legacy",
        replacement: "GLOBAL_ASSET_VIEW",
        notes: "OS_REGEX still works but Qualys best practice is now GLOBAL_ASSET_VIEW — better performance and CSAM compatible.",
    },
    OPERATING_SYSTEM: {
        status: "legacy",
        replacement: "GLOBAL_ASSET_VIEW",
        notes: "Exact-match OS_NAME rules are legacy. Prefer GLOBAL_ASSET_VIEW queries so the rule survives Qualys OS-string normalisation changes.",
    },
    ASSET_INVENTORY: {
        status: "legacy",
        replacement: "GLOBAL_ASSET_VIEW",
        notes: "ASSET_INVENTORY has been replaced by GLOBAL_ASSET_VIEW. Existing rules still work but new tags should use GLOBAL_ASSET_VIEW.",
    },
    GROOVY: {
        status: "restricted",
        notes: "GROOVY rule support is disabled by default in most Qualys subscriptions and must be enabled by Qualys support. Use Test on Qualys to confirm your subscription accepts it.",
    },
};
const TAG_RULE_TEXT_HELP = {
    STATIC: "No rule needed — assets are assigned manually in the Qualys console.",
    NAME_CONTAINS: "Substring matched against the asset DNS or NetBIOS name (case-insensitive).",
    NETWORK_RANGE: 'Comma-separated IPv4 CIDRs or single IPs (e.g. "10.0.0.0/8, 192.168.1.10").',
    NETWORK_RANGE_ENHANCED: "CIDR syntax with extended range support — see Qualys docs.",
    OS_REGEX: 'Java regex matched against the asset OS string (e.g. "^Windows.*Server.*"). Legacy — prefer GLOBAL_ASSET_VIEW.',
    OPERATING_SYSTEM: "Exact OS name as Qualys reports it. Legacy — prefer GLOBAL_ASSET_VIEW.",
    INSTALLED_SOFTWARE: 'Software name pattern (e.g. "Apache HTTP Server" or wildcards).',
    OPEN_PORTS: 'Comma-separated ports or ranges (e.g. "22, 80, 443, 8080-8090").',
    VULN_EXIST: "QID number — assets with this QID detected get tagged.",
    VULN_DETECTION: "QID detection rule — similar to VULN_EXIST with extended match options.",
    ASSET_SEARCH: "Qualys asset search query language (QQL).",
    ASSET_GROUP: "Qualys asset group id — Qualys handles the membership.",
    ASSET_INVENTORY: "Asset inventory query (CSAM). Legacy — replaced by GLOBAL_ASSET_VIEW.",
    GLOBAL_ASSET_VIEW: "Global AssetView query (preferred) — CSAM-compatible, replaces ASSET_INVENTORY.",
    CLOUD_ASSET: "Cloud asset attribute query (AWS, Azure, GCP, OCI).",
    BUSINESS_INFORMATION: "Business-information field expression.",
    BUSINESS_INFO: "Business-info field expression (alias).",
    GROOVY: "Groovy script — full programmatic access to the asset object.",
    TAG_SET: "Membership of a set of other tag ids.",
};

let _tagFormState = {
    mode: "create",   // "create" | "edit"
    tagId: null,      // populated on edit
    lastValidation: null,
    saveAnyway: false,  // operator escape hatch when Qualys-side warnings disagree with our heuristics
};

function _ruleTypeOptionLabel(t) {
    const status = TAG_RULE_TYPE_STATUS[t];
    if (status) return `${t} (${status.status})`;
    // Provide friendly context for common types
    const labels = {
        GLOBAL_ASSET_VIEW: "GLOBAL_ASSET_VIEW (preferred)",
        CLOUD_ASSET: "CLOUD_ASSET (AWS/Azure/GCP/OCI)",
        VULN_EXIST: "VULN_EXIST (QID match)",
        VULN_DETECTION: "VULN_DETECTION (QID detection)",
        STATIC: "STATIC (manual assignment)",
        NETWORK_RANGE: "NETWORK_RANGE (CIDR/IP)",
        NETWORK_RANGE_ENHANCED: "NETWORK_RANGE_ENHANCED (extended CIDR)",
        ASSET_SEARCH: "ASSET_SEARCH (XML criteria)",
        NAME_CONTAINS: "NAME_CONTAINS (hostname match)",
        OPEN_PORTS: "OPEN_PORTS (port list)",
        INSTALLED_SOFTWARE: "INSTALLED_SOFTWARE (app name)",
    };
    return labels[t] || t;
}

function _populateRuleTypeDropdown() {
    const sel = document.getElementById("tagFormRuleType");
    if (!sel || sel.options.length > 1) return;  // already populated
    sel.innerHTML = '<option value="">-- pick a rule type --</option>'
        + TAG_RULE_TYPES.map(t => `<option value="${t}">${_ruleTypeOptionLabel(t)}</option>`).join("");
}

function openTagCreateForm() {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a Qualys platform first", "error"); return; }
    _tagFormState = { mode: "create", tagId: null, lastValidation: null, saveAnyway: false };
    document.getElementById("tagFormTitle").textContent = "New Tag";
    document.getElementById("tagFormSaveBtn").textContent = "Create";
    document.getElementById("tagFormDeleteBtn").style.display = "none";
    _resetTagForm();
    _populateRuleTypeDropdown();
    onTagRuleTypeChange();
    openModal("tagFormModal");
    validateTagFormDebounced();
}

async function openTagEditForm(tagId) {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a Qualys platform first", "error"); return; }
    _tagFormState = { mode: "edit", tagId, lastValidation: null, saveAnyway: false };
    document.getElementById("tagFormTitle").textContent = "Edit Tag #" + tagId;
    document.getElementById("tagFormSaveBtn").textContent = "Save changes";
    document.getElementById("tagFormDeleteBtn").style.display = "";
    _resetTagForm();
    _populateRuleTypeDropdown();
    try {
        const resp = await apiFetch("/api/tags/" + tagId);
        const t = await resp.json();
        if (t.error) { showToast(t.error, "error"); return; }
        document.getElementById("tagFormName").value = t.name || "";
        if (t.color) document.getElementById("tagFormColor").value = t.color;
        if (t.criticality != null) document.getElementById("tagFormCriticality").value = t.criticality;
        if (t.parent_tag_id) document.getElementById("tagFormParent").value = t.parent_tag_id;
        if (t.description) document.getElementById("tagFormDescription").value = t.description;
        if (t.rule_type) document.getElementById("tagFormRuleType").value = t.rule_type;
        if (t.rule_text) document.getElementById("tagFormRuleText").value = t.rule_text;
        onTagRuleTypeChange();
        openModal("tagFormModal");
        validateTagFormDebounced();
    } catch (e) {
        showToast("Failed to load tag: " + e.message, "error");
    }
}

function _resetTagForm() {
    document.getElementById("tagFormName").value = "";
    document.getElementById("tagFormColor").value = "#22c55e";
    document.getElementById("tagFormCriticality").value = "";
    document.getElementById("tagFormParent").value = "";
    document.getElementById("tagFormDescription").value = "";
    const sel = document.getElementById("tagFormRuleType");
    if (sel) sel.value = "";
    document.getElementById("tagFormRuleText").value = "";
    document.getElementById("tagFormSummary").style.display = "none";
    document.getElementById("tagFormTestResult").style.display = "none";
    ["Name", "Color", "Criticality", "Parent", "Description", "RuleType", "RuleText"].forEach(k => {
        const el = document.getElementById("tagForm" + k + "Error");
        if (el) el.textContent = "";
    });
    document.getElementById("tagFormSaveBtn").disabled = true;
}

function _ruleTypeStatusBannerHtml(rt) {
    /* Renders a status callout under the rule_type select. Empty
     * string when the rule type has no special status (the common
     * case — keeps the form quiet). */
    const status = TAG_RULE_TYPE_STATUS[rt];
    if (!status) return "";
    const cls = status.status === "legacy" ? "rule-status-legacy"
              : status.status === "restricted" ? "rule-status-restricted"
              : "rule-status-info";
    const repl = status.replacement
        ? ` <strong>Recommended replacement:</strong> ${escapeHtml(status.replacement)}.`
        : "";
    return `<div class="${cls}"><strong>[${escapeHtml(status.status.toUpperCase())}]</strong> ${escapeHtml(status.notes)}${repl}</div>`;
}

function _setRuleTypeStatusBanner(containerId, rt) {
    const c = document.getElementById(containerId);
    if (!c) return;
    c.innerHTML = _ruleTypeStatusBannerHtml(rt);
    c.style.display = c.innerHTML ? "" : "none";
}

function onTagRuleTypeChange() {
    const rt = document.getElementById("tagFormRuleType").value;
    const help = document.getElementById("tagFormRuleTextHelp");
    const required = document.getElementById("tagFormRuleTextRequired");
    help.textContent = rt ? (TAG_RULE_TEXT_HELP[rt] || "") : "";
    required.style.display = (rt && !TAG_RULE_TEXT_OPTIONAL.has(rt)) ? "" : "none";
    _setRuleTypeStatusBanner("tagFormRuleTypeStatus", rt);
    validateTagFormDebounced();
}

let _tagFormValidateTimer = null;
function validateTagFormDebounced() {
    if (_tagFormValidateTimer) clearTimeout(_tagFormValidateTimer);
    _tagFormValidateTimer = setTimeout(validateTagForm, 250);
}

function _gatherTagForm() {
    return {
        name: document.getElementById("tagFormName").value,
        color: document.getElementById("tagFormColor").value,
        criticality: document.getElementById("tagFormCriticality").value,
        parent_tag_id: document.getElementById("tagFormParent").value,
        description: document.getElementById("tagFormDescription").value,
        rule_type: document.getElementById("tagFormRuleType").value,
        rule_text: document.getElementById("tagFormRuleText").value,
    };
}

async function validateTagForm() {
    const form = _gatherTagForm();
    try {
        const resp = await apiFetch("/api/tags/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(form),
        });
        const result = await resp.json();
        _tagFormState.lastValidation = result;
        _renderTagFormErrors(result);
        const summary = document.getElementById("tagFormSummary");
        if (result.ok && Object.keys(result.warnings || {}).length === 0) {
            summary.style.display = "none";
        } else {
            summary.style.display = "";
            summary.innerHTML = _summaryHtml(result);
        }
        document.getElementById("tagFormSaveBtn").disabled = !result.ok;
    } catch (e) {
        // Validation network error — don't block save, but flag it.
        _tagFormState.lastValidation = null;
        document.getElementById("tagFormSaveBtn").disabled = false;
    }
}

function _renderTagFormErrors(result) {
    const fieldMap = {
        name: "Name", color: "Color", criticality: "Criticality",
        parentTagId: "Parent", description: "Description",
        ruleType: "RuleType", ruleText: "RuleText",
    };
    Object.entries(fieldMap).forEach(([apiKey, suffix]) => {
        const el = document.getElementById("tagForm" + suffix + "Error");
        if (!el) return;
        const errs = (result.errors || {})[apiKey] || [];
        el.textContent = errs.join(" · ");
    });
}

function _summaryHtml(result) {
    let html = "";
    if (!result.ok) {
        const flat = [];
        Object.entries(result.errors || {}).forEach(([k, msgs]) =>
            msgs.forEach(m => flat.push(`<li><strong>${escapeHtml(k)}:</strong> ${escapeHtml(m)}</li>`))
        );
        if (flat.length) html += `<div class="tag-form-errors"><strong>Validation errors:</strong><ul>${flat.join("")}</ul></div>`;
    }
    const wflat = [];
    Object.entries(result.warnings || {}).forEach(([k, msgs]) =>
        msgs.forEach(m => wflat.push(`<li><strong>${escapeHtml(k)}:</strong> ${escapeHtml(m)}</li>`))
    );
    if (wflat.length) html += `<div class="tag-form-warnings"><strong>Warnings:</strong><ul>${wflat.join("")}</ul></div>`;
    return html;
}

async function testTagOnQualys() {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a platform first", "error"); return; }
    const form = { ..._gatherTagForm(), ...auth };
    const resultEl = document.getElementById("tagFormTestResult");
    resultEl.style.display = "";
    resultEl.className = "tag-form-test loading";
    resultEl.textContent = "Asking Qualys to evaluate the rule…";
    try {
        const resp = await apiFetch("/api/tags/test-rule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(form),
        });
        const result = await resp.json();
        if (!resp.ok || result.ok === false) {
            resultEl.className = "tag-form-test error";
            const errs = result.errors ? Object.entries(result.errors).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ") : "";
            resultEl.textContent = (result.message || "Test failed") + (errs ? " — " + errs : "");
            return;
        }
        if (result.stage === "fallback") {
            resultEl.className = "tag-form-test warn";
            resultEl.textContent = "Qualys preview not available on this tenant — relying on local validation. " +
                                   "(Fallback reason: " + (result.fallback_reason || "endpoint not exposed") + ")";
            return;
        }
        const count = result.asset_count;
        resultEl.className = "tag-form-test success";
        resultEl.textContent = (count != null
            ? "Qualys evaluated the rule against " + count.toLocaleString() + " matching asset(s)."
            : "Qualys accepted the rule (asset count not returned).");
    } catch (e) {
        resultEl.className = "tag-form-test error";
        resultEl.textContent = "Test failed: " + e.message;
    }
}

async function submitTagForm() {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a platform first", "error"); return; }
    const body = { ..._gatherTagForm(), ...auth };
    const isEdit = _tagFormState.mode === "edit";
    const url = isEdit ? `/api/tags/${_tagFormState.tagId}/update` : "/api/tags/create";
    try {
        const resp = await apiFetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const result = await resp.json();
        if (!resp.ok || result.error) {
            const detail = result.errors
                ? Object.entries(result.errors).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ")
                : "";
            showToast((result.error || "Save failed") + (detail ? " — " + detail : ""), "error");
            return;
        }
        showToast(isEdit ? "Tag updated in Qualys" : ("Tag created in Qualys (id " + result.tag_id + ")"), "success");
        closeModal("tagFormModal");
        searchTags();
        if (isEdit) showTagDetail(_tagFormState.tagId);
    } catch (e) {
        showToast("Save failed: " + e.message, "error");
    }
}

function confirmTagDeleteFromForm() {
    if (_tagFormState.mode !== "edit" || !_tagFormState.tagId) return;
    openTagDeleteConfirm(_tagFormState.tagId);
}

let _pendingTagDelete = null;
async function openTagDeleteConfirm(tagId) {
    _pendingTagDelete = tagId;
    document.getElementById("tagDeleteName").textContent = "Tag #" + tagId;
    document.getElementById("tagDeleteImpact").textContent = "Loading impact preview…";
    openModal("tagDeleteModal");
    try {
        const resp = await apiFetch("/api/tags/" + tagId + "/impact");
        const data = await resp.json();
        if (data.error) {
            document.getElementById("tagDeleteImpact").textContent = data.error;
            return;
        }
        document.getElementById("tagDeleteName").textContent = data.name || ("Tag #" + tagId);
        const cc = data.child_count || 0;
        let txt = cc === 0
            ? "This tag has no children in your local view."
            : `This tag has ${cc} child tag${cc === 1 ? "" : "s"} in your local view`;
        if (data.child_sample && data.child_sample.length) {
            txt += ": " + data.child_sample.map(c => escapeHtml(c.name || "tag " + c.tag_id)).join(", ");
            if (cc > data.child_sample.length) txt += `, and ${cc - data.child_sample.length} more`;
            txt += ".";
        } else if (cc > 0) {
            txt += ".";
        }
        document.getElementById("tagDeleteImpact").textContent = txt;
    } catch (e) {
        document.getElementById("tagDeleteImpact").textContent = "Could not load impact preview: " + e.message;
    }
}

async function confirmTagDelete() {
    if (!_pendingTagDelete) return;
    const auth = getApiAuth();
    try {
        const resp = await apiFetch("/api/tags/" + _pendingTagDelete + "/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(auth),
        });
        const result = await resp.json();
        if (!resp.ok || result.error) {
            showToast(result.error || "Delete failed", "error");
            return;
        }
        showToast("Tag deleted in Qualys", "success");
        const id = _pendingTagDelete;
        _pendingTagDelete = null;
        closeModal("tagDeleteModal");
        // If the form modal is open for this tag, close it too — the
        // tag no longer exists.
        if (_tagFormState.mode === "edit" && _tagFormState.tagId === id) {
            closeModal("tagFormModal");
        }
        // Refresh list and any open detail modal.
        searchTags();
        const detailModal = document.getElementById("tagDetailModal");
        if (detailModal && detailModal.style.display !== "none") {
            closeModal("tagDetailModal");
        }
    } catch (e) {
        showToast("Delete failed: " + e.message, "error");
    }
}


// ─── Tag Phase 2: Cross-environment migration ───────────────────────────
// Mirrors the Policy migration trio. Workflow:
//   1. exportTagToLocal — POST /api/tags/<id>/export with the SOURCE env
//      credential. Backend pulls fresh JSON from Qualys and stashes it
//      in tag_exports.
//   2. (operator picks a destination credential)
//   3. uploadTagToEnv — POST /api/tags/upload with that credential.
//      Backend strips ids/timestamps and POSTs to the destination
//      env's /qps/rest/2.0/create/am/tag.
//
// Import-from-file lets operators move bundles between machines without
// the source credential being available locally — the JSON file itself
// is the bridge.

async function exportTagToLocal(tagId) {
    const auth = getApiAuth();
    if (!auth.platform) { showToast("Select a Qualys platform first", "error"); return; }
    try {
        const resp = await apiFetch("/api/tags/" + tagId + "/export", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(auth),
        });
        const result = await resp.json();
        if (result.error) { showToast(result.error, "error"); return; }
        showToast("Tag exported (" + (result.payload_size || 0).toLocaleString() + " bytes stored)", "success");
        loadTagExports();
    } catch (e) {
        showToast("Export failed: " + e.message, "error");
    }
}

async function loadTagExports() {
    const container = document.getElementById("tagExportsList");
    if (!container) return;  // panel not in DOM yet
    try {
        const resp = await apiFetch("/api/tags/exports");
        const exports = await resp.json();
        if (!Array.isArray(exports) || exports.length === 0) {
            container.innerHTML = `<p class="muted-small">No exported tags yet. Open a tag's detail and click Export Tag.</p>`;
            return;
        }
        container.innerHTML = exports.map(e => {
            const date = e.exported_at ? new Date(e.exported_at).toLocaleString() : "";
            const size = (e.payload_size || 0).toLocaleString();
            const sysFlag = e.reserved_type ? `<span class="tag-system-pill-inline" title="System tag — cannot be migrated">SYSTEM</span>` : "";
            const ruleType = e.rule_type ? `<span class="badge-pill">${escapeHtml(e.rule_type)}</span>` : "";
            return `<div class="tag-export-row" data-tag-id="${e.tag_id}">
                <div class="tag-export-meta">
                    <strong>${escapeHtml(e.name || "Tag " + e.tag_id)}</strong> ${ruleType} ${sysFlag}
                    <div class="muted-small">id ${e.tag_id} · exported ${escapeHtml(date)} · ${size} bytes</div>
                </div>
                <div class="tag-export-actions">
                    <button class="btn-sm btn-outline" onclick="window.location.href='/api/tags/${e.tag_id}/export-download'">Download</button>
                    <button class="btn-sm" onclick="openTagUploadDialog(${e.tag_id}, ${JSON.stringify(e.name || "").replace(/"/g, "&quot;")})" ${e.reserved_type ? "disabled title='System tag cannot be migrated'" : ""}>Upload to env…</button>
                    <button class="btn-sm btn-outline btn-danger" onclick="deleteTagExport(${e.tag_id})">×</button>
                </div>
            </div>`;
        }).join("");
    } catch (e) {
        container.innerHTML = `<p class="muted-small">Failed to load exports: ${escapeHtml(e.message)}</p>`;
    }
}

async function deleteTagExport(tagId) {
    if (!await themedConfirm("Remove this stored tag export? The original tag in Qualys is unaffected.")) return;
    try {
        const resp = await apiFetch("/api/tags/" + tagId + "/export", { method: "DELETE" });
        const result = await resp.json();
        if (result.error) { showToast(result.error, "error"); return; }
        showToast("Export removed", "success");
        loadTagExports();
    } catch (e) {
        showToast("Delete failed: " + e.message, "error");
    }
}

async function importTagFromFile() {
    const input = document.getElementById("tagImportFileInput");
    if (!input || !input.files || input.files.length === 0) {
        showToast("Pick a tag JSON file first", "error");
        return;
    }
    const fd = new FormData();
    fd.append("file", input.files[0]);
    try {
        const resp = await apiFetch("/api/tags/import-json", { method: "POST", body: fd });
        const result = await resp.json();
        if (result.error) { showToast(result.error, "error"); return; }
        showToast("Imported tag " + result.tag_id + ": " + (result.name || ""), "success");
        input.value = "";
        loadTagExports();
    } catch (e) {
        showToast("Import failed: " + e.message, "error");
    }
}

let _pendingTagUpload = null;  // {tagId, name}
function openTagUploadDialog(tagId, name) {
    _pendingTagUpload = { tagId, name };
    const modal = document.getElementById("tagUploadModal");
    if (!modal) {
        showToast("Upload dialog not found", "error");
        return;
    }
    document.getElementById("tagUploadSourceName").textContent = name || ("Tag " + tagId);
    document.getElementById("tagUploadSourceId").textContent = "id " + tagId;
    document.getElementById("tagUploadNewName").value = "";
    document.getElementById("tagUploadParentId").value = "";
    // Populate the destination credential picker from the existing creds
    fetch("/api/credentials").then(r => r.json()).then(creds => {
        const sel = document.getElementById("tagUploadCredSelect");
        sel.innerHTML = '<option value="">-- pick destination credential --</option>'
            + (Array.isArray(creds) ? creds.map(c =>
                `<option value="${c.id}" data-platform="${c.platform_id || ""}">${escapeHtml(formatCredLabel(c))}</option>`
            ).join("") : "");
    }).catch(() => {});
    openModal("tagUploadModal");
}

async function confirmTagUpload() {
    if (!_pendingTagUpload) return;
    const sel = document.getElementById("tagUploadCredSelect");
    const credId = sel.value;
    if (!credId) { showToast("Pick a destination credential", "error"); return; }
    const platform = sel.options[sel.selectedIndex].dataset.platform || "";
    const newName = document.getElementById("tagUploadNewName").value.trim();
    const parentId = document.getElementById("tagUploadParentId").value.trim();
    const body = {
        source_tag_id: _pendingTagUpload.tagId,
        credential_id: credId,
        platform: platform,
    };
    if (newName) body.new_name = newName;
    if (parentId) body.parent_tag_id = parentId;
    try {
        const resp = await apiFetch("/api/tags/upload", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const result = await resp.json();
        if (result.error) {
            showToast(result.error, "error");
            return;
        }
        showToast("Uploaded — destination tag id " + (result.destination_tag_id || "?"), "success");
        closeModal("tagUploadModal");
        _pendingTagUpload = null;
    } catch (e) {
        showToast("Upload failed: " + e.message, "error");
    }
}


async function setTagEditabilityOverride(tagId, value) {
    try {
        const body = { editability: value === "" ? null : value };
        const resp = await apiFetch("/api/tags/" + tagId + "/editability", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const result = await resp.json();
        if (result.error) { showToast(result.error, "error"); return; }
        showToast("Editability updated", "success");
        showTagDetail(tagId);
        searchTags();
    } catch (e) {
        showToast("Failed to update editability: " + e.message, "error");
    }
}

async function searchTagsPage(page) {
    try {
        const resp = await apiFetch("/api/tags?" + _tagSearchParams(page).toString());
        const data = await resp.json();
        renderTagResults(data);
    } catch (e) { showToast("Search failed", "error"); }
}

// ─── Intelligence ────────────────────────────────────────────────────────
const _intelState = {
    page: 1,
    severities: new Set(),    // {1..5}
    chips: new Set(),         // 'patchable', 'pm_win', 'pm_lin', 'pm_any', 'pci_flag'
    vulnTypes: new Set(['Vulnerability', 'Potential Vulnerability', 'Information Gathered']),
};

function _intelParams(page) {
    const p = new URLSearchParams();
    const q = document.getElementById("intelSearchInput").value.trim();
    if (q) p.set("q", q);
    if (_intelState.severities.size > 0) {
        // Check if any severities are negated
        const incSevs = [];
        const excSevs = [];
        for (const sev of _intelState.severities) {
            if (_intelNegatedFilters.has(`sev:${sev}`)) excSevs.push(sev);
            else incSevs.push(sev);
        }
        if (incSevs.length) p.set("severities", incSevs.join(","));
        if (excSevs.length) p.set("exclude_severities", excSevs.join(","));
    }
    // Chip filters: "1" = include, "0" = exclude (negated)
    const chipParams = {
        patchable: "patchable", pm_any: "pm_any", pm_win: "pm_win",
        pm_lin: "pm_lin", pci_flag: "pci_flag", disabled: "disabled",
        threat_active: "threat_active", threat_cisa_kev: "threat_cisa_kev",
        threat_exploit_public: "threat_exploit_public", threat_rce: "threat_rce",
        threat_malware: "threat_malware", has_exploits: "has_exploits",
    };
    for (const [chip, param] of Object.entries(chipParams)) {
        if (_intelState.chips.has(chip)) {
            const negated = _intelNegatedFilters.has(`chip:${chip}`);
            p.set(param, negated ? "0" : "1");
        }
    }
    if (_intelState.vulnTypes.size === 0) {
        p.set("vuln_types", "__NONE__");
    } else if (_intelState.vulnTypes.size < 3) {
        p.set("vuln_types", [..._intelState.vulnTypes].join(","));
    }
    const cat = document.getElementById("intelCategory");
    if (cat && cat.value) {
        if (_intelNegatedFilters.has("cat:val")) {
            p.set("exclude_category", cat.value);
        } else {
            p.set("category", cat.value);
        }
    }
    // Text search negation — if the search text tag is negated, prefix with NOT
    if (q && _intelNegatedFilters.has("q:text")) {
        p.delete("q");
        p.set("exclude_q", q);
    }
    p.set("page", page || _intelState.page);
    p.set("per_page", "50");
    return p;
}

function toggleIntelSev(sev) {
    if (_intelState.severities.has(sev)) _intelState.severities.delete(sev);
    else _intelState.severities.add(sev);
    document.querySelectorAll('.intel-chip.sev').forEach(b => {
        const v = parseInt(b.dataset.sev);
        b.classList.toggle('active', _intelState.severities.has(v));
    });
    _intelState.page = 1;
    runIntel();
}

function toggleIntelChip(chip) {
    if (_intelState.chips.has(chip)) _intelState.chips.delete(chip);
    else _intelState.chips.add(chip);
    const map = {
        patchable: "intelChipPatch", pm_win: "intelChipPmW",
        pm_lin: "intelChipPmL", pm_any: "intelChipPmA",
        pci_flag: "intelChipPci", disabled: "intelChipDisabled",
        threat_active: "intelChipActive", threat_cisa_kev: "intelChipCisa",
        threat_exploit_public: "intelChipExploit", threat_rce: "intelChipRce",
        threat_malware: "intelChipMalware", has_exploits: "intelChipHasExploits",
    };
    const el = document.getElementById(map[chip]);
    if (el) el.classList.toggle('active', _intelState.chips.has(chip));
    _intelState.page = 1;
    runIntel();
}

function clearIntelFilters() {
    _intelState.severities.clear();
    _intelState.chips.clear();
    _intelNegatedFilters.clear();
    _intelState.vulnTypes = new Set(['Vulnerability', 'Potential Vulnerability', 'Information Gathered']);
    document.getElementById('intelSearchInput').value = '';
    document.getElementById('intelCategory').value = '';
    document.getElementById('intelVtConfirmed').checked = true;
    document.getElementById('intelVtPotential').checked = true;
    document.getElementById('intelVtInfo').checked = true;
    document.querySelectorAll('.intel-chip.sev,.intel-chip.active').forEach(b => b.classList.remove('active'));
    _intelState.page = 1;
    _updateIntelActiveFilters();
    runIntel();
}

// ─── Active filter summary bar ───────────────────────────────────────────
const _INTEL_FILTER_LABELS = {
    patchable: "KB Patchable", pm_any: "PM Any", pm_win: "PM Windows",
    pm_lin: "PM Linux", pci_flag: "PCI", disabled: "Disabled",
    threat_active: "Active Attacks", threat_cisa_kev: "CISA KEV",
    threat_exploit_public: "Public Exploit", threat_rce: "RCE",
    threat_malware: "Malware", has_exploits: "Has Exploits",
};

let _intelFiltersExpanded = false;
let _intelNegatedFilters = new Set(); // filters that are negated (NOT match)

function _updateIntelActiveFilters() {
    const container = document.getElementById("intelActiveFilters");
    if (!container) return;
    const parts = [];
    const q = (document.getElementById("intelSearchInput").value || "").trim();
    if (q) parts.push({ label: `"${q}"`, key: "q:text", remove: () => { document.getElementById("intelSearchInput").value = ""; runIntel(); } });
    for (const sev of [..._intelState.severities].sort()) {
        parts.push({ label: `Sev ${sev}`, key: `sev:${sev}`, remove: () => { toggleIntelSev(sev); } });
    }
    for (const chip of _intelState.chips) {
        parts.push({ label: _INTEL_FILTER_LABELS[chip] || chip, key: `chip:${chip}`, remove: () => { toggleIntelChip(chip); } });
    }
    const cat = (document.getElementById("intelCategory") || {}).value;
    if (cat) parts.push({ label: `Category: ${cat}`, key: "cat:val", remove: () => { document.getElementById("intelCategory").value = ""; runIntel(); } });

    if (parts.length === 0) {
        container.style.display = "none";
        _intelFiltersExpanded = false;
        return;
    }
    container.style.display = "block";
    const expandClass = _intelFiltersExpanded ? " expanded" : "";
    const expandBtn = parts.length > 4
        ? `<button class="intel-filter-expand" onclick="_toggleIntelFilterExpand()">${_intelFiltersExpanded ? "Collapse" : "Expand"}</button>`
        : "";
    container.innerHTML = `<div class="intel-filter-row${expandClass}">
        <span class="intel-filter-label">Active filters:</span>
        <span class="intel-filter-tags">
            ${parts.map((p, i) => {
                const negated = _intelNegatedFilters.has(p.key);
                const cls = negated ? "intel-filter-tag negated" : "intel-filter-tag";
                const prefix = negated ? "NOT " : "";
                return `<span class="${cls}" onclick="_toggleIntelFilterNegate(${i})" title="Click to toggle include/exclude">${escapeHtml(prefix + p.label)} <button onclick="event.stopPropagation();_removeIntelFilter(${i})">&times;</button></span>`;
            }).join("")}
        </span>
        ${expandBtn}
    </div>`;
    container._removers = parts.map(p => p.remove);
    container._keys = parts.map(p => p.key);
}

function _toggleIntelFilterNegate(idx) {
    const container = document.getElementById("intelActiveFilters");
    const key = container._keys && container._keys[idx];
    if (!key) return;
    if (_intelNegatedFilters.has(key)) {
        _intelNegatedFilters.delete(key);
    } else {
        _intelNegatedFilters.add(key);
    }
    _updateIntelActiveFilters();
    runIntel();
}

function _toggleIntelFilterExpand() {
    _intelFiltersExpanded = !_intelFiltersExpanded;
    _updateIntelActiveFilters();
}

function _removeIntelFilter(idx) {
    const container = document.getElementById("intelActiveFilters");
    // Also remove from negated set
    if (container._keys && container._keys[idx]) {
        _intelNegatedFilters.delete(container._keys[idx]);
    }
    if (container._removers && container._removers[idx]) {
        container._removers[idx]();
    }
    _updateIntelActiveFilters();
}

// ─── Saved Intelligence Searches ─────────────────────────────────────────
const _INTEL_SAVED_KEY = "qkbe_intel_saved_searches";

function _getIntelSavedSearches() {
    try { return JSON.parse(localStorage.getItem(_INTEL_SAVED_KEY) || "[]"); }
    catch { return []; }
}

async function saveIntelSearch() {
    const name = await themedPrompt("Name this search:");
    if (!name) return;
    const state = {
        q: (document.getElementById("intelSearchInput").value || "").trim(),
        severities: [..._intelState.severities],
        chips: [..._intelState.chips],
        vulnTypes: [..._intelState.vulnTypes],
        category: (document.getElementById("intelCategory") || {}).value || "",
    };
    const saved = _getIntelSavedSearches();
    saved.unshift({ name, state, timestamp: new Date().toISOString() });
    if (saved.length > 20) saved.length = 20;
    localStorage.setItem(_INTEL_SAVED_KEY, JSON.stringify(saved));
    showToast(`Search saved: "${name}"`, "success");
}

function toggleSavedIntelSearches() {
    const el = document.getElementById("intelSavedSearches");
    if (el.style.display !== "none") { el.style.display = "none"; return; }
    const saved = _getIntelSavedSearches();
    if (saved.length === 0) {
        el.innerHTML = '<div class="intel-saved-empty">No saved searches. Use "Save" to store the current filter set.</div>';
    } else {
        el.innerHTML = saved.map((s, i) => `
            <div class="intel-saved-item">
                <span class="intel-saved-name" onclick="loadIntelSearch(${i})">${escapeHtml(s.name)}</span>
                <span class="intel-saved-meta">${_timeAgo(new Date(s.timestamp))}</span>
                <button class="intel-saved-delete" onclick="deleteIntelSearch(${i})" title="Delete">&times;</button>
            </div>`).join("");
    }
    el.style.display = "block";
}

function loadIntelSearch(idx) {
    const saved = _getIntelSavedSearches();
    const s = saved[idx];
    if (!s) return;
    // Restore state
    document.getElementById("intelSearchInput").value = s.state.q || "";
    _intelState.severities = new Set(s.state.severities || []);
    _intelState.chips = new Set(s.state.chips || []);
    _intelState.vulnTypes = new Set(s.state.vulnTypes || ['Vulnerability', 'Potential Vulnerability', 'Information Gathered']);
    if (document.getElementById("intelCategory")) document.getElementById("intelCategory").value = s.state.category || "";
    // Update UI checkboxes/chips
    document.getElementById('intelVtConfirmed').checked = _intelState.vulnTypes.has('Vulnerability');
    document.getElementById('intelVtPotential').checked = _intelState.vulnTypes.has('Potential Vulnerability');
    document.getElementById('intelVtInfo').checked = _intelState.vulnTypes.has('Information Gathered');
    document.querySelectorAll('.intel-chip.sev').forEach(b => {
        b.classList.toggle('active', _intelState.severities.has(parseInt(b.dataset.sev)));
    });
    const chipMap = {
        patchable: "intelChipPatch", pm_win: "intelChipPmW",
        pm_lin: "intelChipPmL", pm_any: "intelChipPmA",
        pci_flag: "intelChipPci", disabled: "intelChipDisabled",
        threat_active: "intelChipActive", threat_cisa_kev: "intelChipCisa",
        threat_exploit_public: "intelChipExploit", threat_rce: "intelChipRce",
        threat_malware: "intelChipMalware", has_exploits: "intelChipHasExploits",
    };
    Object.entries(chipMap).forEach(([chip, elId]) => {
        const el = document.getElementById(elId);
        if (el) el.classList.toggle('active', _intelState.chips.has(chip));
    });
    document.getElementById("intelSavedSearches").style.display = "none";
    _intelState.page = 1;
    _updateIntelActiveFilters();
    runIntel();
    showToast(`Loaded: "${s.name}"`, "info");
}

function deleteIntelSearch(idx) {
    const saved = _getIntelSavedSearches();
    saved.splice(idx, 1);
    localStorage.setItem(_INTEL_SAVED_KEY, JSON.stringify(saved));
    toggleSavedIntelSearches(); // re-render
}

function _refreshIntelVulnTypes() {
    _intelState.vulnTypes.clear();
    if (document.getElementById('intelVtConfirmed').checked) _intelState.vulnTypes.add('Vulnerability');
    if (document.getElementById('intelVtPotential').checked) _intelState.vulnTypes.add('Potential Vulnerability');
    if (document.getElementById('intelVtInfo').checked) _intelState.vulnTypes.add('Information Gathered');
}

async function runIntel() {
    _refreshIntelVulnTypes();
    _updateIntelActiveFilters();
    try {
        const params = _intelParams(_intelState.page);
        const [qidResp, statsResp] = await Promise.all([
            apiFetch("/api/qids?" + params.toString()),
            apiFetch("/api/intelligence/stats?" + params.toString()),
        ]);
        const data = await qidResp.json();
        const stats = await statsResp.json();
        if (data.error) { showToast(data.error, "error"); return; }
        renderIntelStats(stats);
        renderIntelTable(data);
    } catch (e) {
        showToast("Intelligence search failed: " + e.message, "error");
    }
}

function renderIntelStats(s) {
    const total = s.total_qids || 0;
    const pct = (n) => total > 0 ? Math.round((n / total) * 100) + "%" : "0%";
    // Each card has an action that adds its filter to the current state
    const primaryCards = [
        { l: "Filtered QIDs",      v: total.toLocaleString(),                                                          cls: "cyan",   action: null },
        { l: "Active Attacks",     v: (s.threat_active || 0).toLocaleString(),                                         cls: "red",    action: "threat_active" },
        { l: "CISA KEV",           v: (s.threat_cisa_kev || 0).toLocaleString(),                                       cls: "red",    action: "threat_cisa_kev" },
        { l: "Public Exploits",    v: (s.threat_exploit_public || 0).toLocaleString(),                                 cls: "yellow", action: "threat_exploit_public" },
        { l: "RCE",                v: (s.threat_rce || 0).toLocaleString(),                                            cls: "yellow", action: "threat_rce" },
        { l: "Has Exploits",       v: (s.has_exploits || 0).toLocaleString(),                                          cls: "yellow", action: "has_exploits" },
        { l: "KB Patchable",       v: (s.kb_patchable || 0).toLocaleString() + " (" + pct(s.kb_patchable || 0) + ")",  cls: "green",  action: "patchable" },
        { l: "PM Any",             v: (s.pm_any || 0).toLocaleString() + " (" + pct(s.pm_any || 0) + ")",              cls: "green",  action: "pm_any" },
        { l: "PCI",                v: (s.pci || 0).toLocaleString(),                                                   cls: "red",    action: "pci_flag" },
    ];
    const secondaryCards = [
        { l: "With CVE",  v: (s.with_cve || 0).toLocaleString(), cls: "white",  action: null },
        { l: "Sev 5",     v: (s.sev_5 || 0).toLocaleString(),    cls: "red",    action: "sev_5" },
        { l: "Sev 4",     v: (s.sev_4 || 0).toLocaleString(),    cls: "yellow", action: "sev_4" },
        { l: "Sev 3",     v: (s.sev_3 || 0).toLocaleString(),    cls: "yellow", action: "sev_3" },
        { l: "Sev 2",     v: (s.sev_2 || 0).toLocaleString(),    cls: "white",  action: "sev_2" },
        { l: "Sev 1",     v: (s.sev_1 || 0).toLocaleString(),    cls: "white",  action: "sev_1" },
    ];

    function cardHtml(c, sm) {
        const clickAttr = c.action ? ` onclick="drillIntelStat('${c.action}')" style="cursor:pointer;"` : "";
        const cardClass = sm ? "intel-stat-card intel-stat-card-sm" : "intel-stat-card";
        const clickableClass = c.action ? " intel-stat-clickable" : "";
        return `<div class="${cardClass}${clickableClass}"${clickAttr}>
            <div class="intel-stat-label">${escapeHtml(c.l)}</div>
            <div class="intel-stat-value ${c.cls}">${c.v}</div>
        </div>`;
    }

    document.getElementById("intelStatStrip").innerHTML =
        '<div class="intel-stat-row">' + primaryCards.map(c => cardHtml(c, false)).join("") + '</div>' +
        '<div class="intel-stat-row intel-stat-row-sm">' + secondaryCards.map(c => cardHtml(c, true)).join("") + '</div>';
}

function drillIntelStat(action) {
    // Severity drill-down: set ONLY that severity (replacing any existing selection)
    if (action.startsWith("sev_")) {
        const sev = parseInt(action.split("_")[1]);
        _intelState.severities.clear();
        _intelState.severities.add(sev);
        document.querySelectorAll('.intel-chip.sev').forEach(b => {
            const v = parseInt(b.dataset.sev);
            b.classList.toggle('active', _intelState.severities.has(v));
        });
    } else {
        // Chip-based filter: add to current chip set (additive narrowing)
        if (!_intelState.chips.has(action)) {
            _intelState.chips.add(action);
            // Update chip button UI
            const map = {
                patchable: "intelChipPatch", pm_win: "intelChipPmW",
                pm_lin: "intelChipPmL", pm_any: "intelChipPmA",
                pci_flag: "intelChipPci", disabled: "intelChipDisabled",
                threat_active: "intelChipActive", threat_cisa_kev: "intelChipCisa",
                threat_exploit_public: "intelChipExploit", threat_rce: "intelChipRce",
                threat_malware: "intelChipMalware", has_exploits: "intelChipHasExploits",
            };
            const el = document.getElementById(map[action]);
            if (el) el.classList.add('active');
        }
    }
    _intelState.page = 1;
    runIntel();
}

function renderIntelTable(data) {
    const items = data.results || [];
    const container = document.getElementById("intelResults");
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No QIDs match the current filters.</p></div>';
        document.getElementById("intelPagination").style.display = "none";
        return;
    }
    let html = '<div style="overflow-x:auto;"><table class="intel-table">';
    html += '<thead><tr>'
         + '<th>QID</th><th>Title</th><th>Sev</th><th>Type</th><th>Category</th>'
         + '<th>KB</th><th>PM</th><th>PCI</th><th>CVEs</th><th>Published</th>'
         + '</tr></thead><tbody>';
    html += items.map(r => {
        const sev = r.severity_level || 0;
        const cveCount = (r.cves || []).length;
        const cvePill = cveCount > 0
            ? `<span class="cve-pill">${escapeHtml((r.cves || [])[0]?.cve_id || "")}${cveCount > 1 ? ' +' + (cveCount - 1) : ''}</span>`
            : '<span class="badge-no">—</span>';
        return `<tr onclick="showQidDetail(${r.qid})" style="cursor:pointer;">
            <td><span class="qid-num">${r.qid}</span></td>
            <td class="intel-title">${escapeHtml(r.title || "")}</td>
            <td><span class="intel-sev intel-sev-${sev}">${sev}</span></td>
            <td>${escapeHtml(r.vuln_type || "")}</td>
            <td>${escapeHtml(r.category || "")}</td>
            <td>${r.patchable ? '<span class="intel-yes">Yes</span>' : '<span class="badge-no">—</span>'}</td>
            <td><span class="intel-pm-cell" data-qid="${r.qid}">…</span></td>
            <td>${r.pci_flag ? '<span class="intel-pci">Yes</span>' : '<span class="badge-no">—</span>'}</td>
            <td>${cvePill}</td>
            <td class="dim-cell">${(r.published_datetime || "").substring(0, 10)}</td>
        </tr>`;
    }).join("");
    html += '</tbody></table></div>';
    container.innerHTML = html;
    renderPagination("intel", data);
    // PM cell hydration: one round-trip per row, but parallel
    items.forEach(r => {
        apiFetch("/api/qids/" + r.qid + "/patches").then(async resp => {
            const body = await resp.json();
            const cell = document.querySelector(`.intel-pm-cell[data-qid="${r.qid}"]`);
            if (!cell) return;
            const w = body.win_patches || 0;
            const l = body.lin_patches || 0;
            if (w + l === 0) {
                cell.innerHTML = '<span class="badge-no">—</span>';
            } else {
                cell.innerHTML = (w ? `<span class="intel-pm-win">W:${w}</span> ` : '')
                              + (l ? `<span class="intel-pm-lin">L:${l}</span>` : '');
            }
        }).catch(() => {});
    });
}

async function searchIntelPage(page) {
    _intelState.page = page;
    runIntel();
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
    if (!await themedConfirm("Delete " + ids.length + " selected " + (ids.length === 1 ? "policy" : "policies") + "? This cannot be undone.")) return;
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
    if (!await themedConfirm("Delete policy #" + _policyDetailId + "? This cannot be undone.")) return;
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
    document.getElementById("qidExportActions").style.display = "none";
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
    document.getElementById("qidExportActions").style.display = "";
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

function exportSelectedQids() {
    const ids = Array.from(document.querySelectorAll("#qidResults .qid-select-cb:checked")).map(cb => parseInt(cb.dataset.qid));
    if (ids.length === 0) { showToast("No QIDs selected", "info"); return; }
    window.open("/api/qids/export-details?ids=" + ids.join(",") + "&format=csv", "_blank");
}

// ─── CID Select / Bulk Export Mode ───────────────────────────────────────
let _cidSelectMode = false;

function enterCidSelectMode() {
    _cidSelectMode = true;
    document.getElementById("cidSelectBar").style.display = "flex";
    document.getElementById("cidExportActions").style.display = "none";
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
    document.getElementById("cidExportActions").style.display = "";
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

function exportSelectedCids() {
    const ids = Array.from(document.querySelectorAll("#cidResults .cid-select-cb:checked")).map(cb => parseInt(cb.dataset.cid));
    if (ids.length === 0) { showToast("No CIDs selected", "info"); return; }
    window.open("/api/cids/export-details?ids=" + ids.join(",") + "&format=csv", "_blank");
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
    else if (prefix === "tag") { searchTagsPage(page); }
    else if (prefix === "intel") { searchIntelPage(page); }
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
    tags: "Tags",
    pm_patches: "PM Patch Catalog",
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

    // Show active credential being used
    const credInfoEl = document.getElementById("deltaSyncCredInfo");
    if (credInfoEl && activeCredentialId) {
        try {
            const creds = await fetch("/api/credentials").then(r => r.json());
            const cred = Array.isArray(creds) ? creds.find(c => c.id === activeCredentialId) : null;
            credInfoEl.textContent = cred ? "Credential: " + formatCredLabel(cred) : "";
            credInfoEl.style.display = cred ? "" : "none";
        } catch (_) { credInfoEl.style.display = "none"; }
    }

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
            if (sched.start_date && sched.start_date >= today) dateInput.value = sched.start_date;
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
        tags: "schedBadgeTags",
        pm_patches: "schedBadgePmPatches",
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
        renderThreatOverview(stats.threat_intel || {});
        renderSeverityChart(stats.severity || {});
        renderCriticalityChart(stats.criticality || {});
        renderCategoriesChart(stats.categories_top15 || []);
        renderPatchable(stats.patchable || {});
        renderComplianceSummary(stats.compliance || {});
        renderSyncHealth(sync);
        renderDbHealth(stats.db_health || {});
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
        { key: "tags", elCount: "dashTagCount", elSync: "dashTagSync" },
        { key: "pm_patches", elCount: "dashPmCount", elSync: "dashPmSync" },
    ];
    types.forEach(t => {
        const s = sync[t.key] || {};
        const el = document.getElementById(t.elCount);
        const syncEl = document.getElementById(t.elSync);
        if (!el) return;
        el.textContent = (s.record_count || 0).toLocaleString();
        if (s.last_sync) {
            syncEl.textContent = "Synced " + _timeAgo(new Date(s.last_sync));
        } else {
            syncEl.textContent = "Not synced";
        }
    });
}

function renderThreatOverview(ti) {
    const el = (id, val) => {
        const e = document.getElementById(id);
        if (e) e.textContent = (val || 0).toLocaleString();
    };
    el("dashThreatActive", ti.active_attacks);
    el("dashThreatCisa", ti.cisa_kev);
    el("dashThreatExploit", ti.exploit_public);
    el("dashThreatRce", ti.rce);
    el("dashThreatHasExploits", ti.has_exploits);
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
        { key: "tags", label: "Tags" },
        { key: "pm_patches", label: "PM Patch Catalog" },
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
            <td title="${health.tooltip}" style="cursor:help;"><span class="health-dot ${health.cls}"></span>${health.label}</td>
        </tr>`;
    }).join("");
}

function _syncHealthStatus(syncState) {
    if (!syncState.last_sync) {
        return { cls: "health-red", label: "Never synced", tooltip: "No sync has been performed yet for this data type." };
    }
    const age = Date.now() - new Date(syncState.last_sync).getTime();
    const days = Math.floor(age / (1000 * 60 * 60 * 24));
    const daysText = days === 0 ? "today" : days === 1 ? "1 day ago" : days + " days ago";

    if (days < 7) {
        return { cls: "health-green", label: "Healthy", tooltip: "Last synced " + daysText + ". Data is fresh (synced within the last 7 days)." };
    }
    if (days < 30) {
        return { cls: "health-orange", label: "Aging", tooltip: "Last synced " + daysText + ". Data is aging (7\u201330 days old). Consider running a delta sync." };
    }
    return { cls: "health-red", label: "Stale", tooltip: "Last synced " + daysText + ". Data is stale (over 30 days old). A full sync is recommended." };
}

function renderDbHealth(dbh) {
    const fmtSize = (n) => {
        if (!n) return "—";
        if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
        return (n / 1048576).toFixed(1) + " MB";
    };
    const el = (id) => document.getElementById(id);
    if (el("dbSize")) el("dbSize").textContent = fmtSize(dbh.size);
    if (el("dbLastMaint")) {
        el("dbLastMaint").textContent = dbh.last_maintenance
            ? new Date(dbh.last_maintenance).toLocaleString() : "Never";
    }
    if (el("dbMaintStatus")) {
        const s = dbh.last_status;
        if (s === "ok") {
            el("dbMaintStatus").innerHTML = '<span style="color:var(--green);font-weight:600;">OK</span>';
        } else if (s === "error") {
            el("dbMaintStatus").innerHTML = '<span style="color:var(--red, #d32f2f);font-weight:600;">ERROR</span>';
        } else {
            el("dbMaintStatus").textContent = "—";
        }
    }
    if (el("dbMaintDuration")) {
        el("dbMaintDuration").textContent = dbh.last_duration_s != null
            ? dbh.last_duration_s + "s" : "—";
    }
    if (el("dbBackupInfo")) {
        if (dbh.backup_size && dbh.backup_date) {
            const bDate = new Date(dbh.backup_date).toLocaleString();
            el("dbBackupInfo").textContent = fmtSize(dbh.backup_size) + " · " + bDate;
        } else {
            el("dbBackupInfo").textContent = "No backup yet";
        }
    }
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
        const _expDisEl = document.getElementById("qidDisabledFilter");
        const _expDis = _expDisEl ? _expDisEl.value : "";
        if (_expDis !== "") p.set("disabled", _expDis);
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
