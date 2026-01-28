window.addEventListener("DOMContentLoaded", () => {
    const msg = document.getElementById("successMessage");
    if (msg){
        setTimeout(() => {
            msg.classList.add("fade-out");
            setTimeout(() => msg.remove(), 1000);
        }, 5000);
    }
});