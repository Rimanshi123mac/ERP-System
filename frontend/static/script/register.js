document.addEventListener("DOMContentLoaded", () => {
  const registerForm = document.getElementById("registerForm");
  const verifyBtn = document.getElementById("verifyBtn");

  // Check elements exist
  if (!registerForm) {
    console.error("❌ registerForm not found in DOM");
    return;
  }
  if (!verifyBtn) {
    console.warn("⚠️ verifyBtn not found, skipping verification logic");
  }

  // ✅ VERIFY EMAIL BUTTON
  if (verifyBtn) {
    verifyBtn.addEventListener("click", async () => {
      const fullname = document.getElementById("fullname").value.trim();
      const email = document.getElementById("email").value.trim();

      if (!fullname || !email) {
        alert("Please enter your name and email first!");
        return;
      }

      try {
        const response = await fetch("/api/send_verification", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ fullname, email })
        });

        const result = await response.json();
        if (response.ok) {
          alert("Verification email sent! Please check your inbox.");
        } else {
          alert("Error: " + (result.error || "Failed to send verification email"));
        }
      } catch (err) {
        console.error("Network error:", err);
        alert("Network error: " + err.message);
      }
    });
  }

  // ✅ REGISTER FORM SUBMIT
  registerForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    const fullname = document.getElementById("fullname").value.trim();
    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    try {
      const response = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fullname, username, email, password })
      });

      const result = await response.json();
      if (response.ok) {
        alert(result.message);
        window.location.href = "/login";
      } else {
        alert("Error: " + (result.error || "Registration failed"));
      }
    } catch (err) {
      alert("Network error: " + err.message);
    }
  });
});
