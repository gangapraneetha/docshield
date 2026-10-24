/**
 * DocShield Main Frontend Interaction Script
 * Handles tabs, modals, document filtering, and UX interactions.
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Tab Navigation
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.tab;
            tabButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.style.display = "none");

            btn.classList.add("active");
            const activeContent = document.getElementById(target);
            if (activeContent) activeContent.style.display = "block";
        });
    });

    // 2. Modal Controls
    window.openModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add("active");
            document.body.style.overflow = "hidden";
        }
    };

    window.closeModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove("active");
            document.body.style.overflow = "";
        }
    };

    // Close on backdrop click
    document.querySelectorAll(".modal-overlay").forEach(overlay => {
        overlay.addEventListener("click", (e) => {
            if (e.target === overlay) {
                overlay.classList.remove("active");
                document.body.style.overflow = "";
            }
        });
    });

    // Close on Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            document.querySelectorAll(".modal-overlay.active").forEach(m => {
                m.classList.remove("active");
            });
            document.body.style.overflow = "";
        }
    });

    // 3. Share Modal Populate Helper
    window.openShareModal = function(docId, docTitle) {
        const modal = document.getElementById("share-modal");
        if (!modal) return;
        const form = document.getElementById("share-form");
        form.action = `/documents/${docId}/share`;
        document.getElementById("share-modal-title").innerText = `Share '${docTitle}'`;
        window.openModal("share-modal");
    };

    // 4. Live Table Filter / Search
    const searchInput = document.getElementById("quick-filter-input");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            const term = e.target.value.toLowerCase();
            document.querySelectorAll(".filterable-row").forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(term) ? "" : "none";
            });
        });
    }

    // 5. Auto dismiss flash alerts after 6 seconds
    setTimeout(() => {
        document.querySelectorAll(".flash-alert").forEach(alert => {
            alert.style.transition = "opacity 0.4s ease";
            alert.style.opacity = "0";
            setTimeout(() => alert.remove(), 400);
        });
    }, 6000);
});
