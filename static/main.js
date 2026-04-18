// ===========================
// Test-Feed - Frontend Logic
// ===========================

// SVG icon constants — defined once to avoid duplication
const SVG_COPY  = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const SVG_CHECK = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;

const articleList = document.getElementById("article-list");
const filterContainer = document.querySelector(".filters");
const articleCount = document.getElementById("article-count"); // header pill — shows totalIndexed
const filterStats = document.getElementById("filter-stats");   // below filters — shows active category count
const dateFilterContainer = document.querySelector(".date-filters");
const sortToggle = document.getElementById("sort-toggle");
const sourceFilter = document.getElementById("source-filter");

let currentCategory = "All";
let currentSort = "newest";
let currentDateRange = "all";
let currentSource = "All";
let currentSearch = "";
let allArticles = [];
let articlesRequestController = null;
let categoriesLoaded = false;
let latestRequestId = 0;
let totalIndexed = 0;    // Running DB total — updated from /api/categories
let categoryCounts = {}; // Per-category article counts — keyed by category name
let focusedIndex  = -1;  // Keyboard-navigated article index (-1 = none)

// Badge CSS class map
const badgeClass = {
    "Cloud Breach":                  "badge-cloud",
    "SaaS Breach":                   "badge-saas",
    "OT/ICS":                        "badge-ot",
    "Ransomware":                    "badge-ransomware",
    "Identity & Access":             "badge-identity",
    "Vulnerability/CVE":             "badge-vuln",
    "Nation State/APT":              "badge-apt",
    "Malware/Infostealer":           "badge-malware",
    "AI Security":                   "badge-ai",
    "Phishing & Social Engineering": "badge-phishing",
    "Supply Chain":                  "badge-supply",
    "Mobile Security":               "badge-mobile",
    "Uncategorized":                 "badge-uncat",
};

// Escape HTML special characters — prevents XSS when inserting untrusted text into innerHTML
function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function setStatus(message, className = "loading") {
    articleList.className = `article-list ${className}`;
    articleList.replaceChildren();

    const status = document.createElement("div");
    status.className = className;
    status.textContent = message;
    articleList.appendChild(status);
}

// Format an absolute date string — used for hover tooltips
function formatDate(dateStr, fallbackStr) {
    const parse = (str) => {
        if (!str) return null;
        const d = new Date(str);
        return Number.isNaN(d.getTime()) ? null : d;
    };

    const d = parse(dateStr) || parse(fallbackStr);
    if (!d) return dateStr || fallbackStr || "";

    return d.toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
        hour12: true,
    });
}

// Format a human-readable relative time string — e.g. "3h ago", "yesterday"
// Falls back to a short absolute date for older articles
function relativeTime(dateStr, fallbackStr) {
    const parse = (str) => {
        if (!str) return null;
        const d = new Date(str);
        return Number.isNaN(d.getTime()) ? null : d;
    };

    const d = parse(dateStr) || parse(fallbackStr);
    if (!d) return formatDate(dateStr, fallbackStr);

    const diffMs  = Date.now() - d.getTime();

    // Guard against future-dated feed articles
    if (diffMs < 0) return formatDate(dateStr, fallbackStr);

    const diffMin = Math.floor(diffMs / 60_000);
    const diffHr  = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr  / 24);

    if (diffMin < 1)   return "just now";
    if (diffMin < 60)  return `${diffMin}m ago`;
    if (diffHr  < 24)  return `${diffHr}h ago`;
    if (diffDay === 1) return "yesterday";
    if (diffDay < 7)   return `${diffDay}d ago`;
    if (diffDay < 30)  return `${Math.floor(diffDay / 7)}w ago`;

    // Older than 30 days — short date, include year only if not the current year
    const opts = { month: "short", day: "numeric" };
    if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
    return d.toLocaleDateString("en-US", opts);
}

// Sort articles by date
function sortArticles(articles) {
    return [...articles].sort((a, b) => {
        const da = new Date(a.published_date || a.created_at || 0);
        const db = new Date(b.published_date || b.created_at || 0);
        return currentSort === "newest" ? db - da : da - db;
    });
}

// Filter articles by date range
function filterByDateRange(articles) {
    if (currentDateRange === "all") return articles;
    const cutoff = new Date();
    if (currentDateRange === "today") cutoff.setHours(0, 0, 0, 0);
    else if (currentDateRange === "7days") cutoff.setDate(cutoff.getDate() - 7);
    else if (currentDateRange === "30days") cutoff.setDate(cutoff.getDate() - 30);
    return articles.filter((a) => {
        const d = new Date(a.published_date || a.created_at || 0);
        return !Number.isNaN(d.getTime()) && d >= cutoff;
    });
}

// Filter articles by source
function filterBySource(articles) {
    if (currentSource === "All") return articles;
    return articles.filter((a) => a.source_name === currentSource);
}

// Filter articles by search term (title + summary)
function filterBySearch(articles) {
    if (!currentSearch) return articles;
    const term = currentSearch.toLowerCase();
    return articles.filter((a) =>
        (a.title || "").toLowerCase().includes(term) ||
        (a.summary || "").toLowerCase().includes(term)
    );
}

// Highlight matched search term in text
// Input text is HTML-escaped first to prevent XSS from untrusted RSS content
function highlight(text, term) {
    const safe = escapeHtml(text);
    if (!term) return safe;
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return safe.replace(new RegExp(`(${escaped})`, "gi"), "<mark>$1</mark>");
}

// Rebuild source dropdown from current articles
function buildSourceFilter(articles) {
    if (!sourceFilter) return;
    const currentVal = sourceFilter.value;
    const sources = ["All", ...new Set(articles.map((a) => a.source_name).filter(Boolean))].sort();
    sourceFilter.replaceChildren();
    sources.forEach((s) => {
        const opt = document.createElement("option");
        opt.value = s;
        opt.textContent = s === "All" ? "All sources" : s;
        if (s === currentVal) opt.selected = true;
        sourceFilter.appendChild(opt);
    });
}

// Apply date filter → source filter → search → sort → render — no extra API call
function applyAndRender() {
    const byDate = filterByDateRange(allArticles);
    const bySource = filterBySource(byDate);
    const bySearch = filterBySearch(bySource);
    const sorted = sortArticles(bySearch);
    renderArticles(sorted);
}

function safeHref(rawUrl) {
    if (!rawUrl) return "#";

    try {
        const parsed = new URL(rawUrl, window.location.origin);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            return parsed.href;
        }
    } catch (err) {
        console.warn("Invalid article URL:", rawUrl, err);
    }

    return "#";
}

// Render articles into the list
function renderArticles(articles) {
    articleList.className = "article-list";
    articleList.replaceChildren();
    focusedIndex = -1;

    // Header pill — real DB total, "indexed" lives here only
    if (articleCount) {
        articleCount.textContent = `${totalIndexed.toLocaleString()} articles indexed`;
    }

    if (!Array.isArray(articles) || articles.length === 0) {
        setStatus("No articles found in this category.", "empty");
        if (filterStats) filterStats.textContent = "";
        return;
    }

    // Filter stats — count of articles currently loaded (API-capped, max 500)
    if (filterStats) {
        if (currentSearch) {
            filterStats.innerHTML = `${articles.length.toLocaleString()} result${articles.length !== 1 ? "s" : ""} &mdash; matching <mark>${escapeHtml(currentSearch)}</mark>`;
        } else {
            const label = currentCategory === "All"
                ? `${articles.length.toLocaleString()} articles`
                : `${articles.length.toLocaleString()} articles in ${currentCategory}`;
            filterStats.textContent = label;
        }
    }

    for (const article of articles) {
        const card = document.createElement("div");
        card.className = "article-card";

        const link = document.createElement("a");
        link.href = safeHref(article.url);
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        if (currentSearch) {
            link.innerHTML = highlight(article.title || "Untitled", currentSearch);
        } else {
            link.textContent = article.title || "Untitled";
        }

        const meta = document.createElement("div");
        meta.className = "article-meta";

        const badge = document.createElement("span");
        badge.className = `badge ${badgeClass[article.category] || "badge-uncat"}`;
        badge.textContent = article.category || "Uncategorized";

        const source = document.createElement("span");
        source.className = "article-source";
        source.textContent = article.source_name || "";

        const date = document.createElement("span");
        date.className = "article-date";
        date.textContent = relativeTime(article.published_date, article.created_at);
        date.title = formatDate(article.published_date, article.created_at);

        // Copy link button
        const copyBtn = document.createElement("button");
        copyBtn.className = "copy-btn";
        copyBtn.dataset.tip = "Copy link";
        copyBtn.setAttribute("aria-label", "Copy article link");
        copyBtn.innerHTML = SVG_COPY;
        copyBtn.addEventListener("click", () => {
            const href = safeHref(article.url);
            if (href === "#") return;
            navigator.clipboard.writeText(href).catch(() => {});
            copyBtn.innerHTML = SVG_CHECK;
            copyBtn.dataset.tip = "Copied!";
            copyBtn.classList.add("copied");
            setTimeout(() => {
                copyBtn.innerHTML = SVG_COPY;
                copyBtn.dataset.tip = "Copy link";
                copyBtn.classList.remove("copied");
            }, 1500);
        });

        meta.append(badge, source, date);

        // CVE chips — extracted from title, linked to NVD
        const cves = (article.title || "").match(/CVE-\d{4}-\d{4,7}/gi) || [];
        cves.forEach((cve) => {
            const cveLink = document.createElement("a");
            cveLink.href = `https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}`;
            cveLink.target = "_blank";
            cveLink.rel = "noopener noreferrer";
            cveLink.className = "cve-tag";
            cveLink.textContent = cve.toUpperCase();
            meta.append(cveLink);
        });

        card.append(link, meta, copyBtn);
        articleList.appendChild(card);
    }
}

// Fetch and display articles
async function loadArticles(category = "All") {
    const requestId = ++latestRequestId;

    if (articlesRequestController) {
        articlesRequestController.abort();
    }

    articlesRequestController = new AbortController();
    setStatus("Loading...");

    try {
        const url = category === "All"
            ? "/api/articles"
            : `/api/articles?category=${encodeURIComponent(category)}`;

        const res = await fetch(url, {
            signal: articlesRequestController.signal,
            headers: {
                "Accept": "application/json",
            },
        });

        if (!res.ok) {
            throw new Error(`Failed to load articles: HTTP ${res.status}`);
        }

        const articles = await res.json();
        if (requestId !== latestRequestId) {
            return;
        }

        allArticles = articles;
        currentSource = "All";
        buildSourceFilter(articles);
        applyAndRender();
    } catch (err) {
        if (err.name === "AbortError") {
            return;
        }

        console.error("Failed to load articles:", err);
        setStatus("Failed to load articles. Please try again.", "empty");
    }
}

// Build filter buttons dynamically from API
async function loadCategories() {
    if (categoriesLoaded) {
        return;
    }

    try {
        const res = await fetch("/api/categories", {
            headers: {
                "Accept": "application/json",
            },
        });

        if (!res.ok) {
            throw new Error(`Failed to load categories: HTTP ${res.status}`);
        }

        const categories = await res.json();
        const dynamicButtons = filterContainer.querySelectorAll(".filter-btn[data-dynamic='true']");
        dynamicButtons.forEach((button) => button.remove());

        // Sum all category counts to get the real DB total
        totalIndexed = categories.reduce((sum, cat) => sum + cat.count, 0);
        categoryCounts["All"] = totalIndexed;
        if (articleCount) articleCount.textContent = `${totalIndexed.toLocaleString()} articles indexed`;
        categories.forEach((cat) => {
            categoryCounts[cat.category] = cat.count;
        });

        categories.forEach((cat) => {
            const btn = document.createElement("button");
            btn.className = "filter-btn";
            btn.dataset.category = cat.category;
            btn.dataset.dynamic = "true";
            btn.textContent = cat.category;
            filterContainer.appendChild(btn);
        });

        categoriesLoaded = true;
    } catch (err) {
        console.error("Failed to load categories:", err);
    }
}

// Handle filter button clicks
if (filterContainer) {
    filterContainer.addEventListener("click", (e) => {
        const button = e.target.closest(".filter-btn");
        if (!button) return;

        document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
        button.classList.add("active");

        currentCategory = button.dataset.category || "All";
        loadArticles(currentCategory);
    });
}

// Handle sort toggle
if (sortToggle) {
    sortToggle.addEventListener("click", () => {
        currentSort = currentSort === "newest" ? "oldest" : "newest";
        sortToggle.textContent = currentSort === "newest" ? "↓ Newest" : "↑ Oldest";
        applyAndRender();
    });
}

// Handle source filter
if (sourceFilter) {
    sourceFilter.addEventListener("change", () => {
        currentSource = sourceFilter.value;
        applyAndRender();
    });
}

// Handle date range filter
if (dateFilterContainer) {
    dateFilterContainer.addEventListener("click", (e) => {
        const btn = e.target.closest(".tool-btn");
        if (!btn) return;
        dateFilterContainer.querySelectorAll(".tool-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        currentDateRange = btn.dataset.range || "all";
        applyAndRender();
    });
}

// Handle search input
const searchInput = document.getElementById("search-input");
const searchClear = document.getElementById("search-clear");
let searchDebounce;

if (searchInput) {
    searchInput.addEventListener("input", () => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            currentSearch = searchInput.value.trim();
            searchClear.classList.toggle("visible", currentSearch.length > 0);
            searchInput.classList.toggle("active", currentSearch.length > 0);
            applyAndRender();
        }, 150);
    });
}

if (searchClear) {
    searchClear.addEventListener("click", () => {
        searchInput.value = "";
        currentSearch = "";
        searchClear.classList.remove("visible");
        searchInput.classList.remove("active");
        applyAndRender();
        searchInput.focus();
    });
}

// ---- Keyboard Shortcuts ----
// j/k or ↓/↑ — navigate articles
// Enter       — open focused article in new tab
// /           — focus search bar
// Escape      — clear focus / exit search

function getCards() {
    return Array.from(articleList.querySelectorAll(".article-card"));
}

function setFocusedCard(index) {
    const cards = getCards();
    if (!cards.length) return;

    index = Math.max(0, Math.min(index, cards.length - 1));
    cards.forEach((c) => c.classList.remove("kb-focused"));
    cards[index].classList.add("kb-focused");
    cards[index].scrollIntoView({ block: "nearest", behavior: "smooth" });
    focusedIndex = index;
}

document.addEventListener("keydown", (e) => {
    const inInput = e.target.tagName === "INPUT"
        || e.target.tagName === "SELECT"
        || e.target.tagName === "TEXTAREA";

    // While in search: only handle Escape to exit
    if (e.target === searchInput) {
        if (e.key === "Escape") {
            searchInput.blur();
            e.preventDefault();
        }
        return;
    }

    // While in any other input: do nothing
    if (inInput) return;

    switch (e.key) {
        case "/":
            e.preventDefault();
            searchInput?.focus();
            break;

        case "j":
        case "ArrowDown":
            e.preventDefault();
            setFocusedCard(focusedIndex < 0 ? 0 : focusedIndex + 1);
            break;

        case "k":
        case "ArrowUp":
            e.preventDefault();
            setFocusedCard(focusedIndex <= 0 ? 0 : focusedIndex - 1);
            break;

        case "Enter": {
            const cards = getCards();
            if (focusedIndex >= 0 && cards[focusedIndex]) {
                const link = cards[focusedIndex].querySelector("a");
                if (link && link.href !== "#") {
                    window.open(link.href, "_blank", "noopener,noreferrer");
                }
            }
            break;
        }

        case "Escape":
            getCards().forEach((c) => c.classList.remove("kb-focused"));
            focusedIndex = -1;
            break;
    }
});


// Init
(async () => {
    if (!articleList || !filterContainer || !articleCount) {
        console.error("Missing required DOM elements.");
        return;
    }

    await loadCategories();
    await loadArticles(currentCategory);
})();
