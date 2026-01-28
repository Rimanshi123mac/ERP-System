document.addEventListener("DOMContentLoaded", () => {

  // popup setup
  const openBtn = document.getElementById("openFilePopupBtn");
  const closeBtn = document.getElementById("closeFilePopupBtn");
  const cancelBtn = document.getElementById("cancelFilePopupBtn");
  const popup = document.getElementById("filePopup");
  const overlay = document.getElementById("fileOverlay");

  const openPopup = () => {
    popup.classList.remove("hidden");
    overlay.classList.remove("hidden");
  };

  const closePopup = () => {
    popup.classList.add("hidden");
    overlay.classList.add("hidden");
  };

  if (openBtn) {
    console.log("Open button detected");
    openBtn.addEventListener("click", () => {
      console.log("Open button clicked!");
      openPopup();
    });
  }

  if (closeBtn) closeBtn.addEventListener("click", closePopup);
  if (cancelBtn) cancelBtn.addEventListener("click", closePopup);
  if (overlay) overlay.addEventListener("click", closePopup);


  // Vanilla SEARCH FILTER
  const searchInput = document.getElementById("fileSearch");
  const table = document.getElementById("fileTable");
  const rows = table.querySelectorAll("tbody tr");

  searchInput?.addEventListener("keyup", () => {
    const q = searchInput.value.toLowerCase();
    rows.forEach(row => {
      row.style.display = row.innerText.toLowerCase().includes(q) ? "" : "none";
    });
  });

});

document.getElementById("fileSearch").addEventListener("keyup", function () {
  const filter = this.value.toLowerCase();
  const rows = document.querySelectorAll(".modern-table tbody tr");

  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(filter) ? "" : "none";
  });
});
