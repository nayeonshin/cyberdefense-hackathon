document.querySelector("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = new FormData(e.target);
  const res = await fetch("https://auth.acmebank.example/session", { method: "POST", body: data });
  if (res.ok) window.location = "/dashboard";
});
