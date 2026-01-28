/* ------------------ DEF ----------------*/
document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("loginForm");
    const loginBox = document.querySelector(".login-box");

    function shakeBox() {
        loginBox.classList.add("shake");
        setTimeout(() => loginBox.classList.remove("shake"), 400);
    }

    loginForm.addEventListener("submit", async function (e) {
        e.preventDefault();

        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value;
        const captcha = document.getElementById("captchaInput").value;

        try {
            const response = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, captcha })
            });

            const textResponse = await response.text();
            let result;

            try {
                result = JSON.parse(textResponse);
            } catch (err) {
                showPopup("Server error. Check console.");
                console.log(textResponse);
                shakeBox();
                reloadCaptcha();
                return;
            }

            console.log("Login Response:", result);

            
        
if (result.status === "unverified") {
    showOtpModal();
    return;
}

// ==== PENDING ADMIN APPROVAL ====
if (result.status === "pending") {
    showPopup("Your login request is pending admin approval.");
    return;
}

// ==== ADMIN REJECTED ====
if (result.status === "rejected") {
    showPopup("Access denied by admin.");
    return;
}

if (!response.ok || result.error) {
    const msg = result.error || "Invalid username, password, or captcha.";
    showPopup(msg);
    shakeBox();
    reloadCaptcha();
    return;
}

if (result.status === "approved") {
    showPopup("Login Successful!");

    const role = result.role.toLowerCase();
    if (role === "admin") window.location.href = "/admin";
    else if (role === "employee") window.location.href = "/employee";
    else if (role === "client") window.location.href = "/client";
    else window.location.href = "/dashboard";
}


        } catch (err) {
            showPopup("Network error: " + err.message);
            shakeBox();
        }
    });
});

/* ------------------ PASSWORD TOGGLE ------------------- */
function togglePassword() {
    const input = document.getElementById("password");
    const toggle = document.querySelector(".toggle-password");

    if (input.type === "password") {
        input.type = "text";
        toggle.textContent = "Hide";
    } else {
        input.type = "password";
        toggle.textContent = "Show";
    }
}

/* ------------------ CAPTCHA ------------------- */
function reloadCaptcha() {
    const img = document.getElementById("captchaImg");
    img.src = "/captcha?" + new Date().getTime();
}

/* ------------------ OTP CONTROL ------------------- */
function showOtpModal() {
    document.getElementById("otpModal").classList.remove("hidden");
}

function closeOtpModal() {
    document.getElementById("otpModal").classList.add("hidden");
}

/* ------------------ SEND OTP ------------------- */
document.getElementById("sendOtpBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();

    const response = await fetch("/api/send_otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
    });

    const result = await response.json();
    console.log(result);

    if (result.status === "sent") {
        document.getElementById("otpMessage").innerText = "OTP sent successfully!";
        document.getElementById("otpVerifySection").classList.remove("hidden");
    } else {
        showPopup("Failed to send OTP");
    }
});

/* ------------------ VERIFY OTP ------------------- */
document.getElementById("verifyOtpBtn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    const otp = document.getElementById("otpInput").value.trim();

    const response = await fetch("/api/verify_otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, otp })
    });

    const result = await response.json();

    if (result.status === "verified") {
        showPopup("Email verified! Please login again.");
        closeOtpModal();
    } else {
        showPopup("Invalid OTP");
    }
});
