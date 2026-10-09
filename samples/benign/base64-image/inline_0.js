function decodeThumb(b64) {
  const bytes = atob(b64);
  const arr = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
  return URL.createObjectURL(new Blob([arr], { type: "image/png" }));
}
document.querySelectorAll("img[data-thumb]").forEach((img) => (img.src = decodeThumb(img.dataset.thumb)));
if (location.protocol === "http:") window.location.href = "https://blog.example" + location.pathname;
