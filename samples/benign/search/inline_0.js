const form = document.querySelector("#search");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const q = document.querySelector("#q").value;
  const res = await fetch("/api/search", { method: "POST", body: JSON.stringify({ q }) });
  render(await res.json());
});
