window.dataLayer = window.dataLayer || [];
function track(name, props) {
  fetch("https://news.example/collect?e=" + encodeURIComponent(name));
  window.dataLayer.push({ event: name, ...props });
}
document.addEventListener("click", (e) => track("click", { tag: e.target.tagName }));
