// Popup: reads the active tab's URL, sends it to the ThreatLens backend, shows the result.
// All server text is inserted with textContent (never innerHTML) to prevent XSS.
const pageUrlEl = document.getElementById("page-url");
const scanBtn = document.getElementById("scan-btn");
const output = document.getElementById("output");

let currentUrl = "";

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

async function init() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentUrl = (tab && tab.url) || "";
    if (/^https?:\/\//i.test(currentUrl)) {
        pageUrlEl.textContent = currentUrl;
        scanBtn.disabled = false;
    } else {
        pageUrlEl.textContent = "This page type (e.g. chrome:// or a new tab) cannot be scanned.";
    }
}

scanBtn.addEventListener("click", async () => {
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
    output.className = "";
    output.replaceChildren(el("p", "label", "Asking VirusTotal. This can take up to 15 seconds for new URLs."));

    try {
        const resp = await fetch(API_BASE + "/api/scan/url", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-ThreatLens-Client": "extension" },
            body: JSON.stringify({ url: currentUrl }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || "Request failed");
        render(data);
    } catch (err) {
        const msg = err instanceof TypeError
            ? "Cannot reach the ThreatLens server. Is Flask running at " + API_BASE + "?"
            : err.message;
        output.replaceChildren(el("p", "error", msg));
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan again";
    }
});

function render(r) {
    output.replaceChildren();

    const head = el("div");
    head.appendChild(el("span", "badge " + r.assessment.level.toLowerCase(), r.assessment.level));
    head.appendChild(el("span", "score", "Score " + r.assessment.score + "/100"));
    output.appendChild(head);

    if (r.assessment.breakdown.length) {
        const ul = el("ul");
        r.assessment.breakdown.forEach((b) => ul.appendChild(el("li", "", "+" + b.points + "  " + b.label)));
        output.appendChild(ul);
    }

    const vt = el("div", "vt");
    if (r.vt_error) {
        vt.textContent = "VirusTotal: " + r.vt_error;
    } else if (r.vt && r.vt.status === "pending") {
        vt.textContent = r.vt.message;
    } else if (r.vt && r.vt.found) {
        vt.textContent = "VirusTotal: " + r.vt.stats.malicious + " malicious, " +
            r.vt.stats.suspicious + " suspicious, " + r.vt.stats.harmless + " harmless";
    } else {
        vt.textContent = "VirusTotal has no report for this URL.";
    }
    output.appendChild(vt);

    const link = el("a", "", "Open full report");
    link.href = API_BASE + "/report/" + r.id;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    output.appendChild(link);
}

init();
