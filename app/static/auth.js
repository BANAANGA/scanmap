const form = document.querySelector("#login-form, #setup-form");
const errorMessage = document.querySelector("#auth-error");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.textContent = "";
  const data = new FormData(form);
  const username = data.get("username");
  const password = data.get("password");
  if (form.id === "setup-form" && password !== data.get("confirm")) {
    errorMessage.textContent = "Passwords do not match.";
    return;
  }

  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const response = await fetch(
      form.id === "setup-form" ? "/api/auth/setup" : "/api/auth/login",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      },
    );
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Authentication failed.");
    location.replace("/");
  } catch (error) {
    errorMessage.textContent = error.message || "Could not contact scanmap.";
    button.disabled = false;
  }
});
