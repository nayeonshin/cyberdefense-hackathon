// Escaped text and ordinary unescape usage do not load a remote script.
document.write(unescape("%3Cdiv%20class%3D%27notice%27%3EHello%3C/div%3E"));
const label = unescape("Hello%20world");
document.querySelector("#notice").textContent = label;
