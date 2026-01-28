document.addEventListener("DOMContentLoaded", () => {
  const openBtn = document.getElementById("openPopupBtn");
  const closeBtn = document.getElementById("closePopupBtn");
  const cancelBtn = document.getElementById("cancelPopupBtn");
  const popup = document.getElementById("popup");
  const overlay = document.getElementById("overlay");

  function openPopup() {
    popup.classList.remove("hidden");
    overlay.classList.remove("hidden");
  }

  function closePopup() {
    popup.classList.add("hidden");
    overlay.classList.add("hidden");
  }

  if (openBtn) openBtn.addEventListener("click", openPopup);
  if (closeBtn) closeBtn.addEventListener("click", closePopup);
  if (cancelBtn) cancelBtn.addEventListener("click", closePopup);
  if (overlay) overlay.addEventListener("click", closePopup);
});
