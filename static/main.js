// ===========================
// Test-Feed - Frontend Logic
// ===========================

const articleList = document.getElementById("article-list");
const filterContainer = document.querySelector(".filters");
const articleCount = document.getElementById("article-count");

let currentCategory = "All";
let articlesRequestController = null;
let categoriesLoaded = false;
let latestRequestId = 0;

// Badge CSS class map
const badgeClass = {
    "Cloud Breach": "badge-cloud",
    "SaaS Breach": "badge-saas",
    "OT/ICS": "badge-ot",
    "Ransomware": "badge-ransomware",
    "Vulnerability/CVE": "badge-vuln",
    "Uncategorized": "badge-uncat",
};

function setStatus(message, className = "loading") {
    articleList.className = `article-list ${className}`;
    articleList.replaceChildren();

    const status = document.createElement("div");
    status.className = className;
    status.textContent = message;
    articleList.appendChild(status);
}

// Format date string
function formatDate(dateStr) {
    if (!dateStr) return "";

    const d = new Date(dateStr);
    if (Number.isNaN(d.getTime())) return dateStr;

    return d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
    });
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

    if (!Array.isArray(articles) || articles.length === 0) {
        setStatus("No articles found in this category.", "empty");
        articleCount.textContent = "0 articles";
        return;
    }

    articleCount.textContent = `${articles.length} article${articles.length !== 1 ? "s" : ""}`;

    for (const article of articles) {
        const card = document.createElement("div");
        card.className = "article-card";

        const link = document.createElement("a");
        link.href = safeHref(article.url);
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = article.title || "Untitled";

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
        date.textContent = formatDate(article.published_date);

        meta.append(badge, source, date);
        card.append(link, meta);
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

        renderArticles(articles);
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

        categories.forEach((cat) => {
            const btn = document.createElement("button");
            btn.className = "filter-btn";
            btn.dataset.category = cat.category;
            btn.dataset.dynamic = "true";
            btn.textContent = `${cat.category} (${cat.count})`;
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

// Init
(async () => {
    if (!articleList || !filterContainer || !articleCount) {
        console.error("Missing required DOM elements.");
        return;
    }

    await loadCategories();
    await loadArticles(currentCategory);
})();
