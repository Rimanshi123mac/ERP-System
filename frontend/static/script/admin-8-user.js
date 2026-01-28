$("#addUserForm").on("submit", function (e) {
      e.preventDefault();

      const formData = Object.fromEntries(new FormData(this).entries());

      fetch("/api/admin/add_user", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData)
      })
        .then(res => res.json())
        .then(data => {
          const msgDiv = document.getElementById("message");
          if (data.error) {
            msgDiv.innerHTML = `<div class='alert alert-danger'>${data.error}</div>`;
          } else {
            msgDiv.innerHTML = `<div class='alert alert-success'>${data.message}</div>`;
            document.getElementById("addUserForm").reset();
          }
        })
        .catch(err => console.error("Error:", err));
    });

