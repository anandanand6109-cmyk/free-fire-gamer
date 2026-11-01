
const $ = (id) => document.getElementById(id);

const loginForm = $("loginForm");
const registerForm = $("registerForm");
const forgotForm = $("forgotForm");
const message = $("message");

function showMessage(text, type = "error") {
  if (!message) return;
  message.textContent = text;
  message.className = `message show ${type}`;
}

function clearMessage() {
  if (!message) return;
  message.textContent = "";
  message.className = "message";
}

function showPage(page) {
  clearMessage();

  loginForm.classList.toggle("hidden", page !== "login");
  registerForm.classList.toggle("hidden", page !== "register");
  forgotForm.classList.toggle("hidden", page !== "forgot");

  $("tabs").classList.toggle("hidden", page === "forgot");
  $("loginTab").classList.toggle("active", page === "login");
  $("registerTab").classList.toggle("active", page === "register");
}

async function api(url, data) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(data)
  });

  const text = await response.text();
  let result;

  try {
    result = JSON.parse(text);
  } catch {
    throw new Error(
      `Server response error (${response.status}). Check server.js.`
    );
  }

  if (!response.ok) {
    throw new Error(
      result.error || `Request failed (${response.status}).`
    );
  }

  return result;
}

function goToTournament(result) {
  if (!result.token) {
    throw new Error("Login succeeded, but the server did not return a token.");
  }

  localStorage.setItem("ffTournamentToken", result.token);
  window.location.href = "/tournament.html";
}

// Login, Register and Forgot Password tabs
$("loginTab").addEventListener("click", () => showPage("login"));
$("registerTab").addEventListener("click", () => showPage("register"));
$("forgotButton").addEventListener("click", () => {
  $("resetFields").classList.add("hidden");
  showPage("forgot");
});
$("backButton").addEventListener("click", () => showPage("login"));

// Login
loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();

  const button = loginForm.querySelector('button[type="submit"]');
  button.disabled = true;

  try {
    const result = await api("/api/auth/login", {
      phone: $("loginPhone").value.trim(),
      password: $("loginPassword").value
    });

    showMessage("Login successful! Opening tournament...", "success");
    goToTournament(result);
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

// Register
registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();

  const password = $("registerPassword").value;
  const confirmPassword = $("confirmPassword").value;

  if (password !== confirmPassword) {
    showMessage("Passwords do not match.");
    return;
  }

  const button = registerForm.querySelector('button[type="submit"]');
  button.disabled = true;

  try {
    const result = await api("/api/auth/register", {
      phone: $("registerPhone").value.trim(),
      password,
      confirmPassword,
      uid: $("registerUid").value.trim()
    });

    showMessage("Account created! Opening tournament...", "success");
    goToTournament(result);
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

// Send OTP / start password recovery
$("sendOtpButton").addEventListener("click", async () => {
  clearMessage();

  const button = $("sendOtpButton");
  button.disabled = true;

  try {
    const result = await api("/api/auth/forgot-password", {
      phone: $("resetPhone").value.trim()
    });

    $("resetFields").classList.remove("hidden");
    showMessage(
      result.message || "OTP request completed. Follow the server instructions.",
      "success"
    );
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
  }
});

// Reset password
forgotForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessage();

  const password = $("newPassword").value;
  const confirmPassword = $("newConfirmPassword").value;

  if (password !== confirmPassword) {
    showMessage("Passwords do not match.");
    return;
  }

  try {
    const result = await api("/api/auth/reset-password", {
      phone: $("resetPhone").value.trim(),
      otp: $("resetOtp").value.trim(),
      password,
      confirmPassword
    });

    $("loginPhone").value = $("resetPhone").value.trim();
    $("loginPassword").value = "";
    showPage("login");
    showMessage(result.message || "Password reset successful. Please login.", "success");
  } catch (error) {
    showMessage(error.message);
  }
});

// Show / hide password controls
[
  ["showLoginPassword", "loginPassword"],
  ["showRegisterPassword", "registerPassword"],
  ["showConfirmPassword", "confirmPassword"],
  ["showNewPassword", "newPassword"],
  ["showNewConfirmPassword", "newConfirmPassword"]
].forEach(([checkboxId, inputId]) => {
  const checkbox = $(checkboxId);
  const input = $(inputId);

  if (checkbox && input) {
    checkbox.addEventListener("change", () => {
      input.type = checkbox.checked ? "text" : "password";
    });
  }
});

// Check whether the user is already logged in
(async function checkExistingLogin() {
  const token = localStorage.getItem("ffTournamentToken");
  if (!token) return;

  try {
    const response = await fetch("/api/auth/me", {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    if (response.ok) {
      window.location.href = "/tournament.html";
    } else {
      localStorage.removeItem("ffTournamentToken");
    }
  } catch {
    // Keep the login screen available if the server is offline.
  }
})();
