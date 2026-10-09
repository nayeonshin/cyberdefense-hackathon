// A hidden fetch alias and a decoded URL serve a public search, not a password.
const url = atob("aHR0cHM6Ly9zZWFyY2guZXhhbXBsZS9hcGk=");
const request = window["fe" + "tch"];
request(url, { method: "POST", body: document.querySelector("#search").value });
// A decoder elsewhere must not taint an unrelated password submission.
fetch("/login", { method: "POST", body: document.querySelector("#password").value });
