async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  const result = response.status === 204 ? null : await response.json();
  if (!response.ok) throw new Error((result && result.error) || `HTTP ${response.status}`);
  return result;
}

const tbody = document.querySelector("#user-list");
const message = document.querySelector("#admin-message");
let currentUserId = null;

function showMessage(text, isError = false) {
  message.textContent = text;
  message.classList.toggle("error", isError);
}

function makeButton(label, action, danger = false) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = danger ? "button danger-button" : "button";
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

async function loadUsers() {
  showMessage("Loading users…");
  try {
    const [identity, data] = await Promise.all([
      request("/api/auth/me"),
      request("/api/admin/users"),
    ]);
    currentUserId = identity.user.id;
    tbody.replaceChildren();
    data.users.forEach((user) => {
      const row = document.createElement("tr");
      const username = document.createElement("td");
      username.textContent = user.username + (user.id === currentUserId ? " (you)" : "");
      const role = document.createElement("td");
      role.textContent = user.is_admin ? "Administrator" : "User";
      const created = document.createElement("td");
      created.textContent = new Date(user.created_at * 1000).toLocaleString();
      const actions = document.createElement("td");
      actions.className = "admin-actions";
      if (user.id !== currentUserId) {
        actions.append(
          makeButton(user.is_admin ? "Remove admin" : "Make admin", async () => {
            try {
              await request(`/api/admin/users/${user.id}`, {
                method: "PATCH",
                body: JSON.stringify({ is_admin: !user.is_admin }),
              });
              await loadUsers();
            } catch (error) {
              showMessage(error.message, true);
            }
          }),
          makeButton("Delete", async () => {
            if (!window.confirm(`Delete user “${user.username}”? Their sessions will be revoked.`)) return;
            try {
              await request(`/api/admin/users/${user.id}`, { method: "DELETE" });
              await loadUsers();
            } catch (error) {
              showMessage(error.message, true);
            }
          }, true),
        );
      } else {
        actions.textContent = "Manage from another admin account";
      }
      row.append(username, role, created, actions);
      tbody.append(row);
    });
    showMessage(`${data.users.length} user${data.users.length === 1 ? "" : "s"}.`);
  } catch (error) {
    showMessage(error.message, true);
  }
}

document.querySelector("#refresh-users").addEventListener("click", loadUsers);
document.querySelector("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  try {
    await request("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        username: data.get("username"),
        password: data.get("password"),
        is_admin: data.has("is_admin"),
      }),
    });
    form.reset();
    showMessage("User created.");
    await loadUsers();
  } catch (error) {
    showMessage(error.message, true);
  }
});
document.querySelector("#logout").addEventListener("click", async () => {
  try {
    await request("/api/auth/logout", { method: "POST" });
    location.replace("/login");
  } catch (error) {
    showMessage(error.message, true);
  }
});
loadUsers();
