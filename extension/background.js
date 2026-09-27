// Tsoolgee Proxy - minimal fixed-proxy extension.
// The "proxy profile" is baked in here: an HTTP proxy at 127.0.0.1:10809
// (the local TsoolgeeProxy.exe front), which Chrome uses for http AND https
// (via CONNECT). Toggle on/off from the popup. Default: ON.

const PROXY = { scheme: "http", host: "127.0.0.1", port: 10809 };

// never send local/loopback traffic through the proxy
const BYPASS = ["localhost", "127.0.0.1", "[::1]", "<-loopback>"];

function apply(enabled) {
  if (enabled) {
    chrome.proxy.settings.set({
      scope: "regular",
      value: {
        mode: "fixed_servers",
        rules: { singleProxy: PROXY, bypassList: BYPASS }
      }
    });
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#16a34a" });
  } else {
    // hand control of the proxy setting back to Chrome (direct connection)
    chrome.proxy.settings.clear({ scope: "regular" });
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#9ca3af" });
  }
}

function syncFromStorage() {
  chrome.storage.local.get({ enabled: true }, (s) => apply(s.enabled));
}

// first install -> turn it on so it is ready to use immediately
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get({ enabled: true }, (s) => {
    chrome.storage.local.set({ enabled: s.enabled }, () => apply(s.enabled));
  });
});

// browser start / service-worker wake -> re-assert the stored state
chrome.runtime.onStartup.addListener(syncFromStorage);

// popup flips storage; we apply the change here
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.enabled) apply(changes.enabled.newValue);
});

// also sync whenever the worker spins up
syncFromStorage();
