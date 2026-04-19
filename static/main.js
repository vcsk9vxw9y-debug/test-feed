// ===========================================================
// Threat-Feed — v4.1 Intelligence Desk front-end
// ===========================================================
// No inline handlers anywhere — all event wiring via addEventListener.
// Untrusted feed text (title, summary, source) is always inserted via
// textContent or escapeHtml() before being passed to innerHTML.

const SVG_COPY  = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const SVG_CHECK = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;

const feedStatus   = document.getElementById("feed-status");
const articleList  = document.getElementById("article-list");
const leadContainer = document.getElementById("lead-container");
const filterContainer = document.getElementById("filters");
const filterStats  = document.getElementById("filter-stats");
const dateRangeBar = document.getElementById("date-range");
const sortToggle   = document.getElementById("sort-toggle");
const sourceFilter = document.getElementById("source-filter");
const datelineDate = document.getElementById("dateline-date");

let currentCategory  = "All";
let currentSort      = "newest";
let currentDateRange = "all";
let currentSource    = "All";
let currentSearch    = "";
let allArticles = [];
let articlesRequestController = null;
let categoriesLoaded = false;
let latestRequestId  = 0;
let focusedIndex = -1;
// Top Story payload from /api/top-story. Loaded once on init; the backend
// reads config/top_story.yml and returns {active:false} if the file is
// missing / malformed / not set active. See TOP_STORY.md for the contract.
let topStory = null;

// Category → meta-top class (pip color + category text color). The `rail`
// property is retained for now but unused after the left-border → dot-pip
// refactor; slated for cleanup in a follow-up commit.
const categoryMap = {
    "Cloud Breach":                  { cat: "cloud",    rail: "c-cloud" },
    "SaaS Breach":                   { cat: "saas",     rail: "c-saas" },
    "OT/ICS":                        { cat: "ot",       rail: "c-ot" },
    "Ransomware":                    { cat: "ransom",   rail: "c-ransom" },
    "Identity & Access":             { cat: "identity", rail: "c-identity" },
    "Vulnerability/CVE":             { cat: "vuln",     rail: "c-vuln" },
    "Nation State/APT":              { cat: "apt",      rail: "c-apt" },
    "Malware/Infostealer":           { cat: "malware",  rail: "c-malware" },
    "AI Security":                   { cat: "ai",       rail: "c-ai" },
    "Phishing & Social Engineering": { cat: "phishing", rail: "c-phishing" },
    "Supply Chain":                  { cat: "supply",   rail: "c-supply" },
    "Mobile Security":               { cat: "mobile",   rail: "c-mobile" },
    "Industry/Policy":               { cat: "policy",   rail: "c-policy" },
    "Uncategorized":                 { cat: "uncat",    rail: "c-uncat" },
};

// ---------- Utilities ----------
function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function setStatus(message) {
    if (!feedStatus) return;
    feedStatus.textContent = message;
    feedStatus.hidden = false;
    if (leadContainer) leadContainer.hidden = true;
    if (articleList) articleList.replaceChildren();
}

function clearStatus() {
    if (feedStatus) feedStatus.hidden = true;
}

function formatAbsolute(dateStr, fallbackStr) {
    const parse = (s) => {
        if (!s) return null;
        const d = new Date(s);
        return Number.isNaN(d.getTime()) ? null : d;
    };
    const d = parse(dateStr) || parse(fallbackStr);
    if (!d) return dateStr || fallbackStr || "";
    return d.toLocaleString("en-US", {
        month: "short", day: "numeric", year: "numeric",
        hour: "numeric", minute: "2-digit", hour12: false,
    });
}

function relativeTime(dateStr, fallbackStr) {
    const parse = (s) => {
        if (!s) return null;
        const d = new Date(s);
        return Number.isNaN(d.getTime()) ? null : d;
    };
    const d = parse(dateStr) || parse(fallbackStr);
    if (!d) return "";
    const diffMs = Date.now() - d.getTime();
    if (diffMs < 0) return formatAbsolute(dateStr, fallbackStr);
    const diffMin = Math.floor(diffMs / 60_000);
    const diffHr  = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr  / 24);
    if (diffMin < 1)   return "just now";
    if (diffMin < 60)  return `filed ${diffMin}m ago`;
    if (diffHr  < 24)  return `filed ${diffHr}h ago`;
    if (diffDay === 1) return "filed yesterday";
    if (diffDay < 7)   return `filed ${diffDay}d ago`;
    if (diffDay < 30)  return `filed ${Math.floor(diffDay / 7)}w ago`;
    const opts = { month: "short", day: "numeric" };
    if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
    return `filed ${d.toLocaleDateString("en-US", opts)}`;
}

function shortSourceId(url) {
    // Deterministic 8-char hex tag derived from the URL.
    // Purely decorative — matches v4.1 mock style (e.g. "#a7f2e91d").
    if (!url) return "";
    let h = 2166136261 >>> 0;
    for (let i = 0; i < url.length; i++) {
        h ^= url.charCodeAt(i);
        h = Math.imul(h, 16777619) >>> 0;
    }
    return "#" + h.toString(16).padStart(8, "0").slice(-8);
}

function safeHref(rawUrl) {
    if (!rawUrl) return null;
    try {
        const parsed = new URL(rawUrl, window.location.origin);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            return parsed.href;
        }
    } catch (err) {
        console.warn("Invalid article URL:", rawUrl, err);
    }
    return null;
}

// Highlight search term inside HTML-escaped text
function highlight(text, term) {
    const safe = escapeHtml(text);
    if (!term) return safe;
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return safe.replace(new RegExp(`(${escaped})`, "gi"), "<mark>$1</mark>");
}

// Title with inline entity highlighting + optional search highlight.
// Safe because we HTML-escape the text first, then layer known entity
// matches (CVE IDs) via regex replacement on the already-escaped string.
function titleHtml(title, term) {
    let out = highlight(title || "Untitled", term);
    // CVE spans (CVE-YYYY-NNNNN) — token is ASCII, safe to wrap post-escape
    out = out.replace(/CVE-\d{4}-\d{4,7}/gi, (m) => `<span class="cve">${m.toUpperCase()}</span>`);
    return out;
}

// ---------- Filtering / sorting ----------
function sortArticles(articles) {
    return [...articles].sort((a, b) => {
        const da = new Date(a.published_date || a.created_at || 0);
        const db = new Date(b.published_date || b.created_at || 0);
        return currentSort === "newest" ? db - da : da - db;
    });
}

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

function filterBySource(articles) {
    if (currentSource === "All") return articles;
    return articles.filter((a) => a.source_name === currentSource);
}

function filterBySearch(articles) {
    if (!currentSearch) return articles;
    const term = currentSearch.toLowerCase();
    return articles.filter((a) =>
        (a.title || "").toLowerCase().includes(term) ||
        (a.summary || "").toLowerCase().includes(term)
    );
}

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

function applyAndRender() {
    const byDate   = filterByDateRange(allArticles);
    const bySource = filterBySource(byDate);
    const bySearch = filterBySearch(bySource);
    const sorted   = sortArticles(bySearch);
    renderFeed(sorted);
}

// ---------- Render ----------
function renderFeed(articles) {
    focusedIndex = -1;

    if (!Array.isArray(articles) || articles.length === 0) {
        setStatus("No articles match these filters.");
        if (filterStats) filterStats.textContent = "";
        return;
    }
    clearStatus();

    // Filter stats — match-count only; no site-wide totals per S4
    if (filterStats) {
        if (currentSearch) {
            filterStats.innerHTML = `${articles.length.toLocaleString()} result${articles.length !== 1 ? "s" : ""} matching <mark>${escapeHtml(currentSearch)}</mark>`;
        } else if (currentCategory !== "All" || currentSource !== "All" || currentDateRange !== "all") {
            filterStats.textContent = `${articles.length.toLocaleString()} in view`;
        } else {
            filterStats.textContent = "";
        }
    }

    // Lead story. Precedence:
    //   1. If filters are active, no lead — hero belongs on the unfiltered front page.
    //   2. Else if a curated Top Story is active (config/top_story.yml), use it.
    //   3. Else fall back to the first article as a visual stand-in.
    const filtersActive =
        currentCategory !== "All" ||
        currentSource   !== "All" ||
        currentDateRange !== "all" ||
        !!currentSearch;

    let leadData = null;
    let keyPoints = null;
    let rest = articles;

    if (!filtersActive) {
        if (topStory && topStory.active) {
            // Normalize top story payload to the article-shape buildArticleCard expects
            leadData = {
                title: topStory.title,
                summary: topStory.summary,
                url: topStory.url,
                source_name: topStory.source_name,
                category: topStory.category || "Uncategorized",
                published_date: topStory.published_at,
                created_at: topStory.published_at,
                confidence: topStory.confidence,
                confidence_reason: topStory.confidence_reason,
            };
            keyPoints = Array.isArray(topStory.key_points) ? topStory.key_points : null;
            // The curated Top Story stays on top — no feed article is consumed.
            rest = articles;
        } else if (articles.length > 0) {
            leadData = articles[0];
            rest = articles.slice(1);
        }
    }

    renderLead(leadData, keyPoints);
    renderStandardList(rest);
}

function renderLead(leadData, keyPoints) {
    if (!leadContainer) return;
    leadContainer.replaceChildren();
    if (!leadData) {
        leadContainer.hidden = true;
        return;
    }
    leadContainer.hidden = false;

    // Marker rule: "▁▁▁ Top Story · <short-date> ▁▁▁▁▁"
    const marker = document.createElement("div");
    marker.className = "lead-marker";
    const markerB = document.createElement("b");
    markerB.textContent = "Top Story";
    const markerDate = document.createElement("span");
    const d = new Date(leadData.published_date || leadData.created_at || Date.now());
    markerDate.textContent = Number.isNaN(d.getTime())
        ? ""
        : ` · ${d.toLocaleDateString("en-US", { day: "numeric", month: "short" })}`;
    marker.append(markerB, markerDate);

    const card = buildArticleCard(leadData, { lead: true });
    leadContainer.append(marker, card);

    // Key Points block — only rendered when a curated Top Story supplied them.
    // The fallback (first article) never has key_points, so this block is skipped.
    if (Array.isArray(keyPoints) && keyPoints.length > 0) {
        const kp = document.createElement("section");
        kp.className = "key-points";
        kp.setAttribute("aria-label", "Key points");
        const kpLabel = document.createElement("div");
        kpLabel.className = "kp-label";
        kpLabel.textContent = "Key points";
        kp.appendChild(kpLabel);
        const ul = document.createElement("ul");
        for (const point of keyPoints) {
            const li = document.createElement("li");
            li.textContent = String(point);
            ul.appendChild(li);
        }
        kp.appendChild(ul);
        leadContainer.appendChild(kp);
    }

    // Divider before "Latest" list
    const head = document.createElement("div");
    head.className = "feed-head";
    head.textContent = "Latest";
    leadContainer.appendChild(head);
}

function renderStandardList(articles) {
    if (!articleList) return;
    articleList.replaceChildren();
    for (const article of articles) {
        articleList.appendChild(buildArticleCard(article, { lead: false }));
    }
}

function buildArticleCard(article, { lead }) {
    const catMeta = categoryMap[article.category] || categoryMap["Uncategorized"];

    const card = document.createElement("article");
    card.className = `article ${catMeta.rail}${lead ? " lead" : ""}`;

    // --- meta-top row: pip · category · filed · confidence ---
    const metaTop = document.createElement("div");
    metaTop.className = "meta-top";

    // Category dot pip — decorative, aria-hidden since the category label
    // (next sibling) carries the accessible name.
    const pip = document.createElement("span");
    pip.className = `dot-pip dot-${catMeta.cat}`;
    pip.setAttribute("aria-hidden", "true");
    metaTop.appendChild(pip);

    const cat = document.createElement("span");
    cat.className = `cat ${catMeta.cat}`;
    cat.textContent = article.category || "Uncategorized";
    metaTop.appendChild(cat);

    metaTop.appendChild(sep());

    const filed = document.createElement("span");
    filed.textContent = relativeTime(article.published_date, article.created_at);
    filed.title = formatAbsolute(article.published_date, article.created_at);
    metaTop.appendChild(filed);

    metaTop.appendChild(sep());

    // Source Confidence — B2-compliant label. Label copy intentionally says
    // "Source Confidence" (not "Severity") to disambiguate source-trust from
    // threat-severity. Values come from /api/articles; UNSET (rendered "—")
    // is what the API emits when CONFIDENCE_ENABLED is off (S1 kill-switch).
    metaTop.appendChild(buildConfidenceBadge(article));

    card.appendChild(metaTop);

    // --- title with optional link + entity highlighting ---
    const titleEl = document.createElement("h2");
    titleEl.className = "title";

    const href = safeHref(article.url);
    const titleInner = titleHtml(article.title || "Untitled", currentSearch);
    if (href) {
        const a = document.createElement("a");
        a.href = href;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.innerHTML = titleInner;
        titleEl.appendChild(a);
    } else {
        titleEl.innerHTML = titleInner;
    }
    card.appendChild(titleEl);

    // --- summary ---
    if (article.summary) {
        const summary = document.createElement("p");
        summary.className = "summary";
        if (currentSearch) {
            summary.innerHTML = highlight(article.summary, currentSearch);
        } else {
            summary.textContent = article.summary;
        }
        card.appendChild(summary);
    }

    // --- entities (CVE chips from title) ---
    const cves = (article.title || "").match(/CVE-\d{4}-\d{4,7}/gi) || [];
    if (cves.length) {
        const ents = document.createElement("div");
        ents.className = "entities";
        cves.forEach((cve) => {
            const chip = document.createElement("a");
            chip.className = "e cve";
            chip.href = `https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}`;
            chip.target = "_blank";
            chip.rel = "noopener noreferrer";
            chip.textContent = `cve:${cve.toUpperCase().replace(/^CVE-/, "")}`;
            ents.appendChild(chip);
        });
        card.appendChild(ents);
    }

    // --- meta-bottom: source · short-id · read → ---
    const metaBottom = document.createElement("div");
    metaBottom.className = "meta-bottom";

    const src = document.createElement("div");
    src.className = "src";
    const srcName = document.createElement("span");
    srcName.className = "name";
    srcName.textContent = article.source_name || "Unknown";
    const srcId = document.createElement("span");
    srcId.className = "id";
    srcId.textContent = shortSourceId(article.url || article.title);
    src.append(srcName, srcId);

    const read = document.createElement("a");
    read.className = "read";
    if (href) {
        read.href = href;
        read.target = "_blank";
        read.rel = "noopener noreferrer";
    } else {
        read.setAttribute("aria-disabled", "true");
    }
    read.textContent = "read primary source";

    metaBottom.append(src, read);
    card.appendChild(metaBottom);

    // --- copy-link button (hover reveal) ---
    if (href) {
        const copy = document.createElement("button");
        copy.className = "copy-btn";
        copy.type = "button";
        copy.setAttribute("aria-label", "Copy article link");
        copy.innerHTML = SVG_COPY;
        copy.addEventListener("click", (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            navigator.clipboard.writeText(href).catch(() => {});
            copy.innerHTML = SVG_CHECK;
            copy.classList.add("copied");
            setTimeout(() => {
                copy.innerHTML = SVG_COPY;
                copy.classList.remove("copied");
            }, 1400);
        });
        card.appendChild(copy);
    }

    return card;
}

function sep() {
    const s = document.createElement("span");
    s.className = "sep";
    s.textContent = "·";
    return s;
}

// ---------- Source Confidence badge ----------
// Renders the per-card badge from article.confidence (HIGH|MEDIUM|LOW|UNSET).
// Copy is B2-compliant: the label always says "Source Confidence" to keep the
// source-trust axis distinct from threat-severity. Tooltip carries the tier's
// committed reason (from scheduler.py) plus a general explainer line.
const CONF_META = {
    HIGH: {
        cls: "high",
        text: "HIGH",
        label: "Source confidence: HIGH",
        headline:
            "HIGH — Tier 1 source. Government CERTs, first-party vendor PSIRTs, " +
            "gold-standard threat-intel research. Claims are actionable as reported.",
    },
    MEDIUM: {
        cls: "med",
        text: "MEDIUM",
        label: "Source confidence: MEDIUM",
        headline:
            "MEDIUM — Tier 2 source. Established security journalism, vendor TI " +
            "research with commercial context, niche-authoritative research. " +
            "Credible single source — verify before acting on.",
    },
    LOW: {
        cls: "low",
        text: "LOW",
        label: "Source confidence: LOW",
        headline:
            "LOW — Tier 3 source. User-submitted aggregators, single-author " +
            "niche blogs, community posts. Signal worth tracking — do not " +
            "escalate without corroboration.",
    },
    UNSET: {
        cls: "unset",
        text: "—",
        label: "Source confidence: not set",
        headline:
            "Source confidence is not currently available for this article.",
    },
};

function buildConfidenceBadge(article) {
    const value = (article && article.confidence) || "UNSET";
    const meta  = CONF_META[value] || CONF_META.UNSET;

    const conf = document.createElement("span");
    conf.className = `conf ${meta.cls}`;
    conf.setAttribute("aria-label", meta.label);
    conf.setAttribute("tabindex", "0");
    // Native browser tooltip — source-committed reason + general explainer.
    // We concatenate reason onto the headline; both strings come from
    // committed data only, never user input.
    const reason = article && article.confidence_reason;
    const tip = reason ? `${meta.headline}\n\nWhy this tier: ${reason}` : meta.headline;
    conf.setAttribute("title", tip);

    const confLabel = document.createElement("span");
    confLabel.className = "conf-label";
    confLabel.textContent = "Source Confidence";
    const confValue = document.createElement("b");
    confValue.textContent = meta.text;
    conf.append(confLabel, document.createTextNode(" "), confValue);
    return conf;
}

// ---------- Source Confidence explainer panel ----------
// A single toggle in the filter rail that expands/collapses a compact
// reference panel. Keeps the per-card tooltips as the primary affordance;
// the panel is the "what is this signal?" one-pager for first-time readers.
function setupConfidenceExplainer() {
    const filters = document.getElementById("filters");
    if (!filters) return;

    // Chip button in the filter rail
    const chip = document.createElement("button");
    chip.className = "tag conf-help";
    chip.type = "button";
    chip.setAttribute("aria-expanded", "false");
    chip.setAttribute("aria-controls", "conf-explainer");
    chip.textContent = "about confidence";
    filters.appendChild(chip);

    // Collapsible panel injected after the filter rail
    const panel = document.createElement("aside");
    panel.id = "conf-explainer";
    panel.className = "conf-explainer";
    panel.hidden = true;
    panel.setAttribute("aria-label", "About the Source Confidence badge");
    panel.innerHTML = `
        <p class="ce-lede">
            <b>Source Confidence</b> reflects how much trust to place in the
            <i>source</i>, not how severe the threat is. Every feed is tiered
            in the committed config — no runtime override.
        </p>
        <ul class="ce-tiers">
            <li><b class="ce-h">HIGH</b> — Tier 1. Government CERTs (CISA, NCSC), first-party vendor PSIRTs (MSRC, Project Zero, ZDI), top threat-intel research (Mandiant, Unit 42, Talos). Actionable as reported.</li>
            <li><b class="ce-m">MEDIUM</b> — Tier 2. Established journalism (Krebs, Bleeping, SecurityWeek), vendor TI with commercial framing, niche-authoritative research (PortSwigger, SANS ISC). Credible — verify before acting.</li>
            <li><b class="ce-l">LOW</b> — Tier 3. User-submitted (Reddit), single-author niche blogs. Signal worth tracking — do not escalate without corroboration.</li>
        </ul>
        <p class="ce-note">
            Unknown or missing tier falls back to LOW by design. Hover or tab
            to any badge for the specific reason behind its tier.
        </p>
    `;
    filters.insertAdjacentElement("afterend", panel);

    chip.addEventListener("click", () => {
        const open = panel.hidden;
        panel.hidden = !open;
        chip.setAttribute("aria-expanded", open ? "true" : "false");
        chip.classList.toggle("on", open);
    });
}

// ---------- API wiring ----------
async function loadArticles(category = "All") {
    const requestId = ++latestRequestId;
    if (articlesRequestController) articlesRequestController.abort();
    articlesRequestController = new AbortController();
    setStatus("Loading…");

    try {
        const url = category === "All"
            ? "/api/articles"
            : `/api/articles?category=${encodeURIComponent(category)}`;
        const res = await fetch(url, {
            signal: articlesRequestController.signal,
            headers: { "Accept": "application/json" },
        });
        if (!res.ok) throw new Error(`Failed to load articles: HTTP ${res.status}`);
        const articles = await res.json();
        if (requestId !== latestRequestId) return;
        allArticles = articles;
        currentSource = "All";
        buildSourceFilter(articles);
        applyAndRender();
    } catch (err) {
        if (err.name === "AbortError") return;
        console.error("Failed to load articles:", err);
        setStatus("Failed to load articles. Please try again.");
    }
}

async function loadTopStory() {
    // Pulled once on init. A 404 / network error / malformed payload all land
    // in the same bucket: topStory = {active:false}, frontend falls back to
    // first-article-as-lead per the renderFeed precedence.
    try {
        const res = await fetch("/api/top-story", { headers: { "Accept": "application/json" } });
        if (!res.ok) { topStory = { active: false }; return; }
        const data = await res.json();
        topStory = (data && typeof data === "object") ? data : { active: false };
    } catch (err) {
        console.warn("Top story fetch failed, falling back to first article:", err);
        topStory = { active: false };
    }
}

async function loadCategories() {
    if (categoriesLoaded) return;
    try {
        const catRes = await fetch("/api/categories", { headers: { "Accept": "application/json" } });
        if (!catRes.ok) throw new Error(`Failed to load categories: HTTP ${catRes.status}`);
        const categories = await catRes.json();

        // Remove any previously injected dynamic buttons
        filterContainer.querySelectorAll(".tag[data-dynamic='true']").forEach((b) => b.remove());

        categories.forEach((cat) => {
            // Skip if a static tag for this category already exists
            if (filterContainer.querySelector(`[data-category="${CSS.escape(cat.category)}"]`)) return;

            const btn = document.createElement("button");
            btn.className = "tag";
            btn.type = "button";
            btn.dataset.category = cat.category;
            btn.dataset.dynamic = "true";
            btn.textContent = cat.category.toLowerCase();
            filterContainer.appendChild(btn);
        });
        categoriesLoaded = true;
    } catch (err) {
        console.error("Failed to load categories:", err);
    }
}

// ---------- Event wiring ----------
if (filterContainer) {
    filterContainer.addEventListener("click", (e) => {
        const button = e.target.closest(".tag");
        if (!button) return;
        filterContainer.querySelectorAll(".tag").forEach((b) => b.classList.remove("on"));
        button.classList.add("on");
        currentCategory = button.dataset.category || "All";
        loadArticles(currentCategory);
    });
}

if (dateRangeBar) {
    dateRangeBar.addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn) return;
        dateRangeBar.querySelectorAll("button").forEach((b) => b.classList.remove("on"));
        btn.classList.add("on");
        currentDateRange = btn.dataset.range || "all";
        applyAndRender();
    });
}

if (sortToggle) {
    sortToggle.addEventListener("click", () => {
        currentSort = currentSort === "newest" ? "oldest" : "newest";
        sortToggle.textContent = currentSort === "newest" ? "↓ New" : "↑ Old";
        sortToggle.dataset.sort = currentSort;
        applyAndRender();
    });
}

if (sourceFilter) {
    sourceFilter.addEventListener("change", () => {
        currentSource = sourceFilter.value;
        applyAndRender();
    });
}

const searchInput  = document.getElementById("search-input");
const searchClear  = document.getElementById("search-clear");
let searchDebounce;

if (searchInput) {
    searchInput.addEventListener("input", () => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            currentSearch = searchInput.value.trim();
            if (searchClear) searchClear.classList.toggle("visible", currentSearch.length > 0);
            applyAndRender();
        }, 150);
    });
}

if (searchClear) {
    searchClear.addEventListener("click", () => {
        searchInput.value = "";
        currentSearch = "";
        searchClear.classList.remove("visible");
        applyAndRender();
        searchInput.focus();
    });
}

// ---------- Keyboard nav ----------
function getCards() {
    const cards = [];
    if (leadContainer && !leadContainer.hidden) {
        cards.push(...leadContainer.querySelectorAll(".article"));
    }
    if (articleList) {
        cards.push(...articleList.querySelectorAll(".article"));
    }
    return cards;
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

    if (e.target === searchInput) {
        if (e.key === "Escape") {
            searchInput.blur();
            e.preventDefault();
        }
        return;
    }
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
                const link = cards[focusedIndex].querySelector("a[href]");
                if (link) window.open(link.href, "_blank", "noopener,noreferrer");
            }
            break;
        }
        case "Escape":
            getCards().forEach((c) => c.classList.remove("kb-focused"));
            focusedIndex = -1;
            break;
    }
});

// ---------- Dateline (masthead) ----------
function setDateline() {
    if (!datelineDate) return;
    const now = new Date();
    const parts = [
        now.toLocaleDateString("en-US", { weekday: "short", day: "numeric", month: "short", year: "numeric" }),
    ];
    datelineDate.textContent = parts.join(" ");
}

// ---------- Init ----------
(async () => {
    if (!articleList || !filterContainer) {
        console.error("Missing required DOM elements.");
        return;
    }
    setDateline();
    setupConfidenceExplainer();
    // Fire top-story and categories in parallel — neither blocks the other.
    await Promise.all([loadTopStory(), loadCategories()]);
    await loadArticles(currentCategory);
})();
