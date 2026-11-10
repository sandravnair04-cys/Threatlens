// Service worker: adds "Check link with ThreatLens" to the right-click menu on links.
importScripts("config.js");

const MENU_ID = "threatlens-check-link";

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: MENU_ID,
        title: "Check link with ThreatLens",
        contexts: ["link"],
    });
});

chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId !== MENU_ID || !info.linkUrl) return;
    if (!/^https?:\/\//i.test(info.linkUrl)) return;   // only scan web links
    // We never open the suspicious link itself. We open OUR page, which asks VirusTotal.
    chrome.tabs.create({ url: API_BASE + "/check?url=" + encodeURIComponent(info.linkUrl) });
});
