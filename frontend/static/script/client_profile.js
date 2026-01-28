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


const themes = document.querySelectorAll(".theme");

themes.forEach(theme => {
  theme.addEventListener("click", () => {
    const selectedTheme = theme.dataset.theme;

    document.body.className = `theme-${selectedTheme}`;

    themes.forEach(t => t.classList.remove("selected"));
    theme.classList.add("selected");

    localStorage.setItem("theme", selectedTheme);
  });
});


const fontFamilySelect = document.getElementById("fontFamily");
fontFamilySelect.addEventListener("change", () => {
  document.documentElement.style.setProperty(
    "--font-family",
    fontFamilySelect.value
  );
  localStorage.setItem("fontFamily", fontFamilySelect.value);
});


const fontSizeSelect = document.getElementById("fontSize");
fontSizeSelect.addEventListener("change", () => {
  document.documentElement.style.setProperty(
    "--font-size",
    fontSizeSelect.value
  );
  localStorage.setItem("fontSize", fontSizeSelect.value);
});


window.addEventListener("DOMContentLoaded", () => {
  const savedTheme = localStorage.getItem("theme");
  const savedFont = localStorage.getItem("fontFamily");
  const savedSize = localStorage.getItem("fontSize");

  if (savedTheme) {
    document.body.classList.add(`theme-${savedTheme}`);
    document.querySelector(`[data-theme="${savedTheme}"]`)?.classList.add("selected");
  }

  if (savedFont) {
    document.documentElement.style.setProperty("--font-family", savedFont);
    fontFamilySelect.value = savedFont;
  }

  if (savedSize) {
    document.documentElement.style.setProperty("--font-size", savedSize);
    fontSizeSelect.value = savedSize;
  }
});

function saveAppearance(e) {
  e.preventDefault();

  const theme = document.querySelector(".theme.selected")?.dataset.theme;
  const fontFamily = document.getElementById("font_family").value;
  const fontSize = document.getElementById("font_size").value;

  if (theme) {
    localStorage.setItem("theme", theme);
  }

  localStorage.setItem("fontFamily", fontFamily);
  localStorage.setItem("fontSize", fontSize);

  showPopup("Appearance saved successfully");
}


function changePassword(e) {
  e.preventDefault();

  const current = document.getElementById("current_password").value;
  const newPass = document.getElementById("new_password").value;
  const confirm = document.getElementById("confirm_password").value;

  if (newPass !== confirm) {
    showPopup("Passwords do not match");
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
  // .then(data => alert(data.message))
  .then(data => {
  if (data.error) showPopup(data.error);
  else showPopup(data.message);
})

  .catch(() => showPopup("Error updating password"));
}


function togglePass(id, btn) {
  const field = document.getElementById(id);
  if (field.type === "password") {
    field.type = "text";
    btn.textContent = "Hide";
  } else {
    field.type = "password";
    btn.textContent = "Show";
  }
}


// document.addEventListener("DOMContentLoaded", () => {
  
//   const avatarInput   = document.getElementById("avatarInput");
//   const avatarPreview = document.getElementById("avatarPreview");
//   const avatarRemove  = document.getElementById("avatarRemove");

//   console.log("AvatarInput:", avatarInput); // <--- DEBUG LINE

//   if (avatarInput) {
//     // avatarInput.addEventListener("change", function () {
//     //   const file = this.files[0];
//     //   if (!file) return;

//     //   avatarPreview.src = URL.createObjectURL(file);

//     //   const formData = new FormData();
//     //   formData.append("avatar", file);

//     //   fetch("/client/upload-avatar", { method: "POST", body: formData })
//     //     .then(r => r.json())
//     //     .then(data => console.log("Uploaded:", data))
//     //     .catch(err => console.error(err));
//     // });
    
//     avatarInput.addEventListener("change", () => {
//   const file = avatarInput.files[0];
//   if (!file) return;

//   const reader = new FileReader();
// reader.onload = e => avatarPreview.src = e.target.result;
// reader.readAsDataURL(file);


//   const fd = new FormData();
//   fd.append("avatar", file);

//   fetch("/client/upload-avatar", {
//     method: "POST",
//     body: fd
//   })
//   .then(r => r.json())
//   .then(data => {
//     console.log("Uploaded:", data);
//     avatarInput.value = ""; 
//   });
// });

//   }

//   if (avatarRemove) {
//     avatarRemove.addEventListener("click", function () {
//       fetch("/client/remove-avatar", { method: "POST" })
//         .then(r => r.json())
//         .then(data => {
//           if (data.success) {
//             avatarPreview.src = "/static/images/avatar.png";
//           }
//         });
//     });
//   }
// });


// document.addEventListener("DOMContentLoaded", () => {
  
//   const avatarInput   = document.getElementById("avatarInput");
//   const avatarPreview = document.getElementById("avatarPreview");
//   const avatarRemove  = document.getElementById("avatarRemove");

//   // LOAD SAVED AVATAR ON PAGE LOAD
//   fetch("/client/get-avatar")
//     .then(r => r.json())
//     .then(data => {
//       if (data.avatar_url) {
//         avatarPreview.src = data.avatar_url;
//       }
//     })
//     .catch(err => console.error("Error loading avatar:", err));

//   // UPLOAD AVATAR
//   if (avatarInput) {
//     avatarInput.addEventListener("change", () => {
//       const file = avatarInput.files[0];
//       if (!file) return;

//       // Show preview immediately
//       const reader = new FileReader();
//       reader.onload = e => avatarPreview.src = e.target.result;
//       reader.readAsDataURL(file);

//       // Upload to server
//       const fd = new FormData();
//       fd.append("avatar", file);

//       fetch("/client/upload-avatar", {
//         method: "POST",
//         body: fd
//       })
//       .then(r => r.json())
//       .then(data => {
//         if (data.success) {
//           console.log("Avatar uploaded:", data.avatar_url);
//           avatarPreview.src = data.avatar_url; // Update with server URL
//           avatarInput.value = ""; // Clear input
//         } else {
//           alert("Upload failed: " + data.error);
//         }
//       })
//       .catch(err => {
//         console.error("Upload error:", err);
//         alert("Error uploading avatar");
//       });
//     });
//   }

//   // REMOVE AVATAR
//   if (avatarRemove) {
//     avatarRemove.addEventListener("click", function () {
//       fetch("/client/remove-avatar", { method: "POST" })
//         .then(r => r.json())
//         .then(data => {
//           if (data.success) {
//             const defaultAvatar = avatarPreview.dataset.default || "/static/images/avatar.png";
//             avatarPreview.src = defaultAvatar;
//           } else {
//             alert("Error removing avatar");
//           }
//         })
//         .catch(err => console.error("Remove error:", err));
//     });
//   }
// });



document.addEventListener("DOMContentLoaded", () => {
  
  const avatarInput   = document.getElementById("avatarInput");
  const avatarPreview = document.getElementById("avatarPreview");
  const avatarRemove  = document.getElementById("avatarRemove");

  // LOAD SAVED AVATAR ON PAGE LOAD
  fetch("/client/get-avatar")
    .then(r => r.json())
    .then(data => {
      if (data.avatar_url) {
        avatarPreview.src = data.avatar_url;
      }
    })
    .catch(err => console.error("Error loading avatar:", err));

  // UPLOAD AVATAR
  if (avatarInput) {
    avatarInput.addEventListener("change", () => {
      const file = avatarInput.files[0];
      if (!file) return;

      console.log("File selected:", file.name, file.type, file.size);

      // Show preview immediately
      const reader = new FileReader();
      reader.onload = e => {
        console.log("Preview set from file");
        avatarPreview.src = e.target.result;
      };
      reader.readAsDataURL(file);

      // Upload to server
      const fd = new FormData();
      fd.append("avatar", file);

      console.log("Uploading to /client/upload-avatar");

      fetch("/client/upload-avatar", {
        method: "POST",
        body: fd
      })
      .then(r => {
        console.log("Response status:", r.status);
        return r.json();
      })
      .then(data => {
        console.log("Server response:", data);
        if (data.success) {
          console.log("Avatar uploaded successfully:", data.avatar_url);
          avatarPreview.src = data.avatar_url;
          avatarInput.value = "";
          alert("Avatar uploaded successfully!");
        } else {
          console.error("Upload failed:", data.error);
          alert("Upload failed: " + data.error);
        }
      })
      .catch(err => {
        console.error("Upload error:", err);
        alert("Error uploading avatar: " + err.message);
      });
    });
  }

  // REMOVE AVATAR
  if (avatarRemove) {
    avatarRemove.addEventListener("click", function () {
      fetch("/client/remove-avatar", { method: "POST" })
        .then(r => r.json())
        .then(data => {
          if (data.success) {
            const defaultAvatar = avatarPreview.dataset.default || "/static/images/avatar.png";
            avatarPreview.src = defaultAvatar;
          } else {
            alert("Error removing avatar");
          }
        })
        .catch(err => console.error("Remove error:", err));
    });
  }
});