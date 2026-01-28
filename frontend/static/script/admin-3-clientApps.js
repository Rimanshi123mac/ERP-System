document.addEventListener("DOMContentLoaded", () => {

  // === POPUP HANDLERS FOR CLIENT APPS ===
  const openBtn = document.getElementById("openAppPopupBtn");
  const closeBtn = document.getElementById("closeAppPopupBtn");
  const cancelBtn = document.getElementById("cancelAppPopupBtn");
  const popup = document.getElementById("appPopup");
  const overlay = document.getElementById("appOverlay");

  const openPopup = () => {
    if (popup) popup.classList.remove("hidden");
    if (overlay) overlay.classList.remove("hidden");
  };

  const closePopup = () => {
    if (popup) popup.classList.add("hidden");
    if (overlay) overlay.classList.add("hidden");
  };

  if (openBtn) openBtn.addEventListener("click", openPopup);
  if (closeBtn) closeBtn.addEventListener("click", closePopup);
  if (cancelBtn) cancelBtn.addEventListener("click", closePopup);
  if (overlay) overlay.addEventListener("click", closePopup);

});
