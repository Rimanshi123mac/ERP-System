document.addEventListener("DOMContentLoaded", () => {

// ------------------------------------ LOAD PENDING USERS ----------------------------------
  function loadPendingUsers() {
    fetch("/api/pending_users")
      .then(res => res.json())
      .then(users => {
        const tbody = document.getElementById("pendingUsersBody");
        tbody.innerHTML = "";

        if (!users.length) {
          tbody.innerHTML = `<tr><td colspan="5" class="text-center">No pending users</td></tr>`;
          return;
        }

        users.forEach(user => {
          const row = `
            <tr>
              <td>${user.id}</td>
              <td>${user.username || "N/A"}</td>
              <td>${user.email}</td>
              <td>${user.created_at}</td>
              <td>
                <a href="/admin/user/${user.id}" class="btn btn-info btn-sm">View Profile</a>
              </td>
            </tr>`;
          tbody.insertAdjacentHTML("beforeend", row);
        });
      })
      .catch(err => console.error("Error fetching pending users:", err));
  }

// ------------------------------------ LOAD ALL USERS TABLE ---------------------------------------
  const loadBtn = document.getElementById("loadAllUsersBtn");
  const table = document.getElementById("allUsersTable");
  const tbody = document.getElementById("allUsersBody");

  loadBtn.addEventListener("click", () => {

  // If table already visible, hide it
  if (!table.classList.contains("d-none")) {
    table.classList.add("d-none");
    loadBtn.innerHTML = `<i class="fas fa-users"></i> Load All Users`;
    return;
  }

  // Else load & show
  fetch("/api/all_users")
    .then(res => res.json())
    .then(users => {

      tbody.innerHTML = "";

      if (!users.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center">No clients or employees found</td></tr>`;
      } else {
        users.forEach(user => {
          const status = user.is_active ? "Active" : "Inactive";
          const row = `
            <tr>
              <td>${user.id}</td>
              <td>${user.fullname}</td>
              <td>${user.username}</td>
              <td>${user.email}</td>
              <td>${user.role}</td>
              <td>${status}</td>
              <td class="text-center">
                <button class="btn btn-info btn-sm view-profile-btn" data-id="${user.id}">
                  View Profile
                </button>
              </td>
            </tr>`;
          tbody.insertAdjacentHTML("beforeend", row);
        });
      }

      table.classList.remove("d-none");
      loadBtn.innerHTML = `<i class="fas fa-times"></i> Hide Users`;

      // Profile redirect binding
      document.querySelectorAll(".view-profile-btn").forEach(btn => {
        btn.addEventListener("click", e => {
          window.location.href = `/admin/user/${e.target.dataset.id}`;
        });
      });

    })
    .catch(err => console.error("Error fetching all users:", err));
});

  loadPendingUsers();
});
