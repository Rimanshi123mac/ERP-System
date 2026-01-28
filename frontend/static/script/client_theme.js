// function saveAppearance(e) {
//   e.preventDefault();

//   const themeEl = document.querySelector(".theme.selected");
//   const fontFamilyEl = document.getElementById("font_family");
//   const fontSizeEl = document.getElementById("font_size");

//   const theme = themeEl ? themeEl.dataset.theme : null;
//   const fontFamily = fontFamilyEl ? fontFamilyEl.value : null;
//   const fontSize = fontSizeEl ? fontSizeEl.value : null;

//   if (theme)      localStorage.setItem("client_theme", theme);
//   if (fontFamily) localStorage.setItem("client_font", fontFamily);
//   if (fontSize)   localStorage.setItem("client_font_size", fontSize);

//   applyClientTheme();
// }

// function applyClientTheme() {
//   const theme    = localStorage.getItem("client_theme");
//   const font     = localStorage.getItem("client_font");
//   const fontSize = localStorage.getItem("client_font_size");

//   document.body.classList.remove(
//     "theme-light",
//     "theme-dark",
//     "theme-aqua",
//     "theme-blue",
//     "theme-green"
//   );

//   if (theme) {
//     document.body.classList.add(`theme-${theme}`);
//   }

//   if (font) {
//     document.documentElement.style.setProperty("--font-family", font);
//   }

//   if (fontSize) {
//     document.documentElement.style.setProperty("--font-size", fontSize);
//   }
// }

// document.addEventListener("DOMContentLoaded", applyClientTheme);

// document.querySelectorAll(".theme").forEach(theme => {
//   theme.addEventListener("click", () => {
//     document.querySelectorAll(".theme").forEach(t =>
//       t.classList.remove("selected")
//     );
//     theme.classList.add("selected");
//   });
// });




// Called when the user clicks "Save Preferences"
function saveAppearance(e) {
  e.preventDefault();

  const themeEl      = document.querySelector(".theme.selected");
  const fontFamilyEl = document.getElementById("font_family");
  const fontSizeEl   = document.getElementById("font_size");

  const theme      = themeEl ? themeEl.dataset.theme : null;
  const fontFamily = fontFamilyEl ? fontFamilyEl.value : null;
  const fontSize   = fontSizeEl ? fontSizeEl.value : null;

  if (theme)      localStorage.setItem("client_theme", theme);
  if (fontFamily) localStorage.setItem("client_font", fontFamily);
  if (fontSize)   localStorage.setItem("client_font_size", fontSize);

  applyClientTheme();
}

// Applies saved theme + font globally (all tabs/pages)
// function applyClientTheme() {
//   const theme    = localStorage.getItem("client_theme");
//   const font     = localStorage.getItem("client_font");
//   const fontSize = localStorage.getItem("client_font_size");

//   document.body.classList.remove(
//     "theme-light",
//     "theme-dark",
//     "theme-aqua",
//     "theme-green"
//   );

//   if (theme) {
//     document.body.classList.add(`theme-${theme}`);
//   }

//   if (font) {
//     document.documentElement.style.setProperty("--font-family", font);
//   }

//   if (fontSize) {
//     document.documentElement.style.setProperty("--font-size", fontSize);
//   }
// }


function applyClientTheme() {
  const theme = localStorage.getItem("theme") || "light";
  const font = localStorage.getItem("fontFamily") || "Poppins";
  const size = localStorage.getItem("fontSize") || "16px";
  const bold = localStorage.getItem("isBold") === "true";

  const wrapper = document.querySelector(".main-wrapper");

  // reset classes
  document.body.classList.remove("theme-light", "theme-dark", "theme-aqua", "theme-green");
  if (wrapper) wrapper.classList.remove("theme-light", "theme-dark", "theme-aqua", "theme-green");

  // add theme everywhere
  document.body.classList.add(`theme-${theme}`);
  if (wrapper) wrapper.classList.add(`theme-${theme}`);

  // fonts
  document.documentElement.style.setProperty("--font-family", font);
  document.documentElement.style.setProperty("--font-size", size);

  // bold
  if (bold) {
    document.body.classList.add("font-bold");
    if (wrapper) wrapper.classList.add("font-bold");
  } else {
    document.body.classList.remove("font-bold");
    if (wrapper) wrapper.classList.remove("font-bold");
  }
}



// Apply saved preferences on every client page load
document.addEventListener("DOMContentLoaded", applyClientTheme);

// Theme dots: only select/unselect (no global change yet)
document.querySelectorAll(".theme").forEach(theme => {
  theme.addEventListener("click", () => {
    document.querySelectorAll(".theme").forEach(t =>
      t.classList.remove("selected")
    );
    theme.classList.add("selected");
  });
});

// === Preview-only behavior inside Appearance tab ===
const previewBox   = document.querySelector(".appearance-preview");
const fontFamilyEl = document.getElementById("font_family");
const fontSizeEl   = document.getElementById("font_size");

if (previewBox && fontFamilyEl) {
  fontFamilyEl.addEventListener("change", () => {
    previewBox.style.fontFamily = fontFamilyEl.value;
  });
}

if (previewBox && fontSizeEl) {
  fontSizeEl.addEventListener("change", () => {
    previewBox.style.fontSize = fontSizeEl.value;
  });
}

// function showPopup(message) {
//   const popup     = document.getElementById("globalPopup");
//   const msgBox    = document.getElementById("popupMessage");
//   if (!popup || !msgBox) return;

//   msgBox.textContent = message;
//   popup.style.display = "flex";     
// }
function showPopup(message, type = "error") {
  const popup  = document.getElementById("globalPopup");
  const msgBox = document.getElementById("popupMessage");
  const box    = popup?.querySelector(".popup-box");

  if (!popup || !msgBox || !box) return;

  msgBox.textContent = message;

  box.classList.remove("error", "success");
  box.classList.add(type);

  popup.style.display = "flex";
}



function hidePopup() {
  const popup = document.getElementById("globalPopup");
  if (popup) popup.style.display = "none";
}

document.addEventListener("DOMContentLoaded", () => {
  const popup     = document.getElementById("globalPopup");
  const closeBtn  = document.getElementById("popupClose");

  if (closeBtn) {
    closeBtn.addEventListener("click", hidePopup);
  }

  if (popup) {
    popup.addEventListener("click", (e) => {
      if (e.target === popup) hidePopup();
    });
  }
});


function confirmLogout() {
  const popup  = document.getElementById("globalPopup");
  const msgBox = document.getElementById("popupMessage");
  const actions = document.getElementById("popupActions");
  const confirmBtn = document.getElementById("popupConfirmBtn");

  if (!popup || !msgBox || !actions || !confirmBtn) return;

  msgBox.textContent = "Are you sure you want to logout?";
  actions.style.display = "flex";

  confirmBtn.onclick = () => {
    window.location.href = "/logout";
  };

  popup.style.display = "flex";
}

function hidePopup() {
  const popup = document.getElementById("globalPopup");
  const actions = document.getElementById("popupActions");
  if (actions) actions.style.display = "none";
  if (popup) popup.style.display = "none";
}

document.addEventListener("click", function (e) {
  const menu = document.getElementById("profileMenu");
  const button = document.querySelector(".profile-btn");

  if (!menu.contains(e.target) && !button.contains(e.target)) {
    menu.classList.remove("show");
  }
});
