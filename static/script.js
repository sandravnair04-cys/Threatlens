// ThreatLens front-end. Sends scans to the Flask API and draws the result.
// SECURITY: all text from the server is inserted with textContent, never innerHTML,
// so malicious strings returned by third parties cannot run as code (XSS).
(function () {
    "use strict";

    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

    const statusBox = $("#status");
    const resultBox = $("#result");

    // ---------- helpers ----------
    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = text;
        return node;
    }

    function showStatus(message, isError) {
        statusBox.textContent = message;
        statusBox.className = "status" + (isError ? " error" : "");
    }
    function hideStatus() { statusBox.className = "status hidden"; }

    function setBusy(form, busy) {
        $$("button", form).forEach((b) => (b.disabled = busy));
    }

    async function postJson(url, payload) {
        const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        return handle(resp);
    }

    async function postForm(url, formData) {
        return handle(await fetch(url, { method: "POST", body: formData }));
    }

    async function handle(resp) {
        let data = {};
        try { data = await resp.json(); } catch (e) { /* not JSON */ }
        if (!resp.ok) throw new Error(data.error || "Request failed (" + resp.status + ")");
        return data;
    }

    // ---------- tabs ----------
    $$(".tab").forEach((tab) => {
        tab.addEventListener("click", () => {
            $$(".tab").forEach((t) => t.classList.toggle("active", t === tab));
            $$(".panel").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== tab.dataset.tab));
            hideStatus();
            resultBox.className = "hidden";
        });
    });

    // ---------- result rendering ----------
    function renderResult(r, extraNode) {
        resultBox.replaceChildren();
        resultBox.className = "";

        const level = (r.assessment.level || "Unknown").toLowerCase();

        // Summary card
        const summary = el("div", "card");
        summary.appendChild(el("p", "target-line", r.target));
        if (r.filename) summary.appendChild(el("p", "note", "File: " + r.filename + " (" + r.file_size + " bytes)"));
        const row = el("div", "score-row");
        row.appendChild(el("span", "badge big lvl-" + level, r.assessment.level));
        const bar = el("div", "score-bar");
        const progress = document.createElement("progress");
        progress.max = 100;
        progress.value = r.assessment.score;
        progress.className = "lvl-" + level;
        bar.appendChild(progress);
        bar.appendChild(el("span", "", r.assessment.score + " / 100"));
        row.appendChild(bar);
        summary.appendChild(row);
        resultBox.appendChild(summary);

        // Breakdown
        const why = el("div", "card");
        why.appendChild(el("h2", "", "Why this score?"));
        if (r.assessment.breakdown.length) {
            const ul = el("ul", "breakdown");
            r.assessment.breakdown.forEach((b) => {
                const li = el("li");
                li.appendChild(el("span", "", "+" + b.points));
                li.appendChild(document.createTextNode(" " + b.label));
                ul.appendChild(li);
            });
            why.appendChild(ul);
        } else {
            why.appendChild(el("p", "note", "No risk indicators were found."));
        }
        resultBox.appendChild(why);

        // VirusTotal
        const vtCard = el("div", "card");
        vtCard.appendChild(el("h2", "", "VirusTotal"));
        if (r.vt_error) {
            vtCard.appendChild(el("p", "warn", r.vt_error));
        } else if (r.vt && r.vt.found) {
            if (r.vt.status === "pending") vtCard.appendChild(el("p", "warn", r.vt.message));
            const grid = el("div", "stat-grid");
            ["malicious", "suspicious", "harmless", "undetected"].forEach((k) => {
                const box = el("div", "stat");
                box.appendChild(el("span", "", String(r.vt.stats[k] || 0)));
                box.appendChild(document.createTextNode(k.charAt(0).toUpperCase() + k.slice(1)));
                grid.appendChild(box);
            });
            vtCard.appendChild(grid);

            const keys = Object.keys(r.vt.details || {});
            if (keys.length) {
                const dl = el("dl", "details");
                keys.forEach((k) => {
                    dl.appendChild(el("dt", "", k));
                    dl.appendChild(el("dd", "", String(r.vt.details[k])));
                });
                vtCard.appendChild(dl);
            }
            if (r.vt.flagged && r.vt.flagged.length) {
                vtCard.appendChild(el("h3", "", "Engines that flagged it"));
                const wrap = el("div", "table-wrap");
                const table = el("table");
                const head = el("tr");
                ["Engine", "Category", "Result"].forEach((h) => head.appendChild(el("th", "", h)));
                table.appendChild(head);
                r.vt.flagged.forEach((f) => {
                    const tr = el("tr");
                    [f.engine, f.category, f.result].forEach((v) => tr.appendChild(el("td", "", v)));
                    table.appendChild(tr);
                });
                wrap.appendChild(table);
                vtCard.appendChild(wrap);
            }
            if (r.vt.permalink) {
                const p = el("p");
                const a = el("a", "", "Open on VirusTotal");
                a.href = r.vt.permalink;
                a.target = "_blank";
                a.rel = "noopener noreferrer";
                p.appendChild(a);
                vtCard.appendChild(p);
            }
        } else {
            vtCard.appendChild(el("p", "note", "VirusTotal has no report for this item."));
        }
        if (extraNode) vtCard.appendChild(extraNode);
        resultBox.appendChild(vtCard);

        // Link to saved report
        const actions = el("div", "actions");
        const link = el("a", "btn", "Open full report #" + r.id);
        link.href = "/report/" + r.id;
        actions.appendChild(link);
        resultBox.appendChild(actions);
        resultBox.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ---------- URL / domain / IP / hash ----------
    $$("form[data-type]").forEach((form) => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const type = form.dataset.type;          // url | domain | ip | hash
            const field = form.elements[type];
            setBusy(form, true);
            resultBox.className = "hidden";
            showStatus(type === "url"
                ? "Scanning... new URLs can take up to ~15 seconds while VirusTotal analyses them."
                : "Scanning...");
            try {
                const report = await postJson("/api/scan/" + type, { [type]: field.value });
                hideStatus();
                renderResult(report);
            } catch (err) {
                showStatus(err.message, true);
            } finally {
                setBusy(form, false);
            }
        });
    });

    // ---------- file scan ----------
    const fileForm = $("#file-form");
    if (fileForm) {
        fileForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const file = $("#file-input").files[0];
            const consent = $("#consent").checked;
            if (!file) return;
            setBusy(fileForm, true);
            resultBox.className = "hidden";
            showStatus("Hashing file and checking VirusTotal...");
            try {
                const fd = new FormData();
                fd.append("file", file);
                fd.append("consent", consent ? "true" : "false");
                const report = await postForm("/api/scan/file", fd);
                hideStatus();

                let extra = null;
                if (report.vt && !report.vt.found) {
                    extra = el("div");
                    if (!consent) {
                        extra.appendChild(el("p", "note",
                            "VirusTotal has never seen this file. Tick the consent box and scan again if you want to upload it."));
                    } else {
                        showStatus("Unknown file - uploading to VirusTotal (you gave consent)...");
                        const up = await postForm("/api/scan/file/upload", fd);
                        hideStatus();
                        extra.appendChild(el("p", "warn", up.message));
                    }
                }
                renderResult(report, extra);
            } catch (err) {
                showStatus(err.message, true);
            } finally {
                setBusy(fileForm, false);
            }
        });
    }

    // ---------- auto-scan when opened from the browser extension ----------
    const prefill = $("#scanner") ? $("#scanner").dataset.prefillUrl : "";
    if (prefill) {
        const form = $('form[data-type="url"]');
        form.elements.url.value = prefill;
        form.requestSubmit();
    }
})();
