


document.getElementById("toggle-btn").addEventListener("click", function () {
    document.querySelector(".sidebar").classList.toggle("collapsed");
});

document.addEventListener("DOMContentLoaded", async () => {
  const tableBody = document.getElementById("pendingUsersBody");
  const rightSection = document.getElementById("rights-section");

  document.getElementById("menu-rights").addEventListener("click", (e) => {
    e.preventDefault();
    dashboardSection.classList.add("hidden");
    rightsSection.classList.remove("hidden");
    loadPendingUsers();
  });

  document.getElementById("menu-dashboard").addEventListener("click", (e) => {
    e.preventDefault();
    rightsSection.classList.add("hidden");
    dashboardSection.classList.remove("hidden");
  });

  await loadPendingUsers();
});

async function loadPendingUsers() {
  try {
    const res = await fetch("/api/pending_users");
    const users = await res.json();
    tableBody.innerHTML = "";

    if (!users.length) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: gray;">No pending users found</td></tr>`;
      return;
    }

    users.forEach(user => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${user.id}</td>
        <td>${user.username || "N/A"}</td>
        <td>${user.email}</td>
        <td>${user.role || "—"}</td>
        <td>${new Date(user.created_at).toLocaleString()}</td>
        <td><button class="profile-btn" data-id="${user.id}">View Profile</button></td>
      `;
      tableBody.appendChild(tr);
    });

    document.querySelectorAll(".profile-btn").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const id = e.target.dataset.id;
        window.location.href = `/admin/user/${id}`;
      });
    });

  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="6" style="color:red;">Error loading users.</td></tr>`;
  }
}

document.getElementById("add-user").addEventListener("click", (e) => {
  e.preventDefault();
  window.location.href = "/admin/user"; 
});
