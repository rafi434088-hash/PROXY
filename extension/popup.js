const label = document.getElementById("label");
const dot = document.getElementById("dot");
const btn = document.getElementById("toggle");

function render(enabled) {
  label.textContent = enabled ? "פעיל (דרך הפרוקסי)" : "כבוי (חיבור ישיר)";
  dot.style.background = enabled ? "#16a34a" : "#9ca3af";
  btn.textContent = enabled ? "כבה פרוקסי" : "הפעל פרוקסי";
  btn.className = enabled ? "on" : "off";
}

chrome.storage.local.get({ enabled: true }, (s) => render(s.enabled));

btn.addEventListener("click", () => {
  chrome.storage.local.get({ enabled: true }, (s) => {
    const next = !s.enabled;
    chrome.storage.local.set({ enabled: next }, () => render(next));
  });
});
