/* ===========================================================
   Threat-Feed — Category Spotlight page JS
   ===========================================================

   Scope: only loaded by templates/category.html (Spotlight pages).
   Does NOT run on the homepage — keeps main.js lean.

   Responsibilities:
     1. Expand / collapse group rollup rows (Ransomware page)
     2. Keyboard accessibility (Enter / Space toggles a focused row)

   Security posture:
     - No innerHTML, no template strings injected into the DOM
     - No external fetches — page is fully SSR-rendered
     - Toggles the [hidden] attribute and aria-expanded only
     - Click delegation via a single rollup container listener
       (no per-row listeners, fewer GC roots)

   No external dependencies, no globals beyond the IIFE.
*/
(function () {
    "use strict";

    const rollup = document.querySelector(".rollup-rows");
    if (!rollup) return;

    /**
     * Toggle a group row's expanded state.
     * Mirrors aria-expanded with the [hidden] attribute on the victim list.
     */
    function toggleRow(row) {
        if (!row || !row.classList.contains("group-row")) return;
        const victims = row.querySelector(".group-victims");
        if (!victims) return;
        const expanded = row.getAttribute("aria-expanded") === "true";
        const next = !expanded;
        row.setAttribute("aria-expanded", String(next));
        if (next) {
            victims.removeAttribute("hidden");
        } else {
            victims.setAttribute("hidden", "");
        }
    }

    // Single click delegate at the container — no per-row listeners.
    rollup.addEventListener("click", function (e) {
        const row = e.target.closest(".group-row");
        if (!row) return;
        // Don't toggle if the user clicked a link inside the victim list
        // (defensive — current template has no links there, but if a future
        // change adds them we don't want to swallow the navigation).
        if (e.target.closest("a")) return;
        toggleRow(row);
    });

    // Keyboard support — Enter and Space on a focused group row.
    rollup.addEventListener("keydown", function (e) {
        if (e.key !== "Enter" && e.key !== " ") return;
        const row = e.target.closest(".group-row");
        if (!row) return;
        // The row itself must be focused, not a child element (links etc).
        if (document.activeElement !== row) return;
        e.preventDefault();
        toggleRow(row);
    });
})();
