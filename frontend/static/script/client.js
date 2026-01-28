// const USER_ID = document.getElementById("clientForm").dataset.userId;

// document.getElementById("clientForm").addEventListener("submit", async function (e) {
//     e.preventDefault();

//     const data = {
//         user_id: USER_ID,  
//         address: document.getElementById("address").value,
//         contact: document.getElementById("contact").value,
//         service: document.getElementById("service").value
//     };

//     const response = await fetch("/api/save_client_profile", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify(data)
//     });

//     const result = await response.json();

//     if (result.status === "success") {

//         Swal.fire({
//             title: "Profile Saved!",
//             text: "Your details have been successfully updated.",
//             icon: "success",
//             confirmButtonColor: "#233876",
//             timer: 2000
//         });

//         document.getElementById("clientForm").reset();
//     }
// });



// document.addEventListener("DOMContentLoaded", function () {

//     const profileBtn = document.querySelector(".profile-btn");
//     const profileMenu = document.getElementById("profileMenu");

//     profileBtn.addEventListener("click", function (e) {
//         e.stopPropagation();
//         profileMenu.style.display =
//             profileMenu.style.display === "flex" ? "none" : "flex";
//     });

//     document.addEventListener("click", function () {
//         profileMenu.style.display = "none";
//     });

// });




document.addEventListener("DOMContentLoaded", function () {

    /* ---------- PROFILE DROPDOWN ---------- */
    const profileBtn = document.querySelector(".profile-btn");
    const profileMenu = document.getElementById("profileMenu");

    if (profileBtn && profileMenu) {
        profileBtn.addEventListener("click", function (e) {
            e.stopPropagation();
            profileMenu.style.display =
                profileMenu.style.display === "flex" ? "none" : "flex";
        });

        document.addEventListener("click", function () {
            profileMenu.style.display = "none";
        });
    }

    /* ---------- CLIENT PROFILE FORM ---------- */
    const clientForm = document.getElementById("clientForm");

    if (clientForm) {
        const USER_ID = clientForm.dataset.userId;

        clientForm.addEventListener("submit", async function (e) {
            e.preventDefault();

            const data = {
                user_id: USER_ID,
                address: document.getElementById("address").value,
                contact: document.getElementById("contact").value,
                service: document.getElementById("service").value
            };

            const response = await fetch("/api/save_client_profile", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (result.status === "success") {
                Swal.fire({
                    title: "Profile Saved!",
                    text: "Your details have been successfully updated.",
                    icon: "success",
                    confirmButtonColor: "#233876",
                    timer: 2000
                });

                clientForm.reset();
            }
        });
    }

});


