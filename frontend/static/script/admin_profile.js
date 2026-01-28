// ==============================
// TAB SWITCHING
// ==============================
const tabs = document.querySelectorAll(".tab");
const contents = document.querySelectorAll(".tab-content");

tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => t.classList.remove("active"));
    contents.forEach(c => c.classList.remove("active"));

    tab.classList.add("active");
    document.getElementById(tab.dataset.tab).classList.add("active");
  });
});


// ==============================
// THEME SETUP
// ==============================
const wrapper = document.querySelector(".main-wrapper");

if (wrapper) {
  const theme = wrapper.dataset.theme || "light";
  const font = wrapper.dataset.font || "Poppins";
  const size = wrapper.dataset.size || "16px";
  const bold = wrapper.dataset.bold === "1";

  // Apply theme class
  wrapper.classList.remove("theme-light", "theme-dark", "theme-aqua", "theme-green");
  wrapper.classList.add("theme-" + theme);
  document.body.classList.remove("theme-light", "theme-dark", "theme-aqua", "theme-green");
  document.body.classList.add("theme-" + theme);
  
  // Apply font family and size to wrapper, body, and document
  wrapper.style.setProperty("--font-family", font);
  wrapper.style.setProperty("--font-size", size);
  document.body.style.setProperty("--font-family", font);
  document.body.style.setProperty("--font-size", size);
  document.documentElement.style.setProperty("--font-family", font);
  document.documentElement.style.setProperty("--font-size", size);
  
  // Apply font to all text elements
  const allElements = document.querySelectorAll("*");
  allElements.forEach(el => {
    el.style.setProperty("font-family", font);
    el.style.setProperty("font-size", size);
  });
  
  if (bold) {
    wrapper.classList.add("font-bold");
    document.body.classList.add("font-bold");
    document.documentElement.classList.add("font-bold");
  }
}


// ==============================
// THEME CLICK + SAVE
// ==============================
document.querySelectorAll(".theme").forEach(t => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".theme").forEach(x => x.classList.remove("selected"));
    t.classList.add("selected");

    const newTheme = t.dataset.theme;
    wrapper.classList.remove("theme-light", "theme-dark", "theme-aqua", "theme-green");
    wrapper.classList.add("theme-" + newTheme);
    document.body.classList.remove("theme-light", "theme-dark", "theme-aqua", "theme-green");
    document.body.classList.add("theme-" + newTheme);

    saveAppearance();
  });
});


// ==============================
// FONT FAMILY + SIZE
// ==============================
document.getElementById("fontFamily")?.addEventListener("change", e => {
  const font = e.target.value;
  wrapper.style.setProperty("--font-family", font);
  document.body.style.setProperty("--font-family", font);
  document.documentElement.style.setProperty("--font-family", font);
  saveAppearance();
});

document.getElementById("fontSize")?.addEventListener("change", e => {
  const size = e.target.value;
  wrapper.style.setProperty("--font-size", size);
  document.body.style.setProperty("--font-size", size);
  document.documentElement.style.setProperty("--font-size", size);
  saveAppearance();
});


// ==============================
// BOLD TOGGLE
// ==============================
document.getElementById("boldToggle")?.addEventListener("change", e => {
  if (e.target.checked) {
    wrapper.classList.add("font-bold");
    document.body.classList.add("font-bold");
  } else {
    wrapper.classList.remove("font-bold");
    document.body.classList.remove("font-bold");
  }
  saveAppearance();
});


// ==============================
// SAVE APPEARANCE (ADMIN API)
// ==============================
async function saveAppearance() {
  const theme = [...wrapper.classList].find(c => c.startsWith("theme-"))?.replace("theme-", "") || "light";
  const fontFamily = document.getElementById("fontFamily")?.value || "Poppins";
  const fontSize = document.getElementById("fontSize")?.value || "16px";
  const isBold = document.getElementById("boldToggle")?.checked || false;

  const response = await fetch("/api/save-appearance", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ theme, font_family: fontFamily, font_size: fontSize, is_bold: isBold })
  });
  
  if (response.ok) {
    // Store in localStorage for persistence
    localStorage.setItem("theme", theme);
    localStorage.setItem("fontFamily", fontFamily);
    localStorage.setItem("fontSize", fontSize);
    localStorage.setItem("isBold", isBold);
  }
}


// ==============================
// PASSWORD UPDATE
// ==============================
function changePassword(e) {
  e.preventDefault();

  const current = document.getElementById("current_password").value;
  const newPass = document.getElementById("new_password").value;
  const confirm = document.getElementById("confirm_password").value;

  if (newPass !== confirm) {
    alert("Passwords do not match");
    return;
  }

  fetch("/api/change_password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      current_password: current,
      new_password: newPass
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) {
      alert(data.error);
    } else {
      alert(data.message || "Password updated successfully");
      document.getElementById("current_password").value = "";
      document.getElementById("new_password").value = "";
      document.getElementById("confirm_password").value = "";
    }
  })
  .catch(() => alert("Error updating password"));
}


// ==============================
// PASSWORD SHOW/HIDE
// ==============================
function togglePassword(inputId, element) {
  const input = document.getElementById(inputId);
  if (input.type === "password") {
    input.type = "text";
    element.textContent = "Hide";
  } else {
    input.type = "password";
    element.textContent = "Show";
  }
}
