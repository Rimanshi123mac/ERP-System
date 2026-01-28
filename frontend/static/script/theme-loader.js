document.addEventListener("DOMContentLoaded", () => {
  const wrapper = document.querySelector(".main-wrapper");
  if (!wrapper) return;

  const theme = wrapper.dataset.theme || "light";
  const font = wrapper.dataset.font || "Poppins";
  const size = wrapper.dataset.size || "16px";
  const bold = wrapper.dataset.bold === "1";

  wrapper.classList.remove("theme-light","theme-dark","theme-aqua","theme-green");
  wrapper.classList.add("theme-" + theme);

  wrapper.style.setProperty("--font-family", font);
  wrapper.style.setProperty("--font-size", size);

  wrapper.classList.toggle("font-bold", bold);
});
