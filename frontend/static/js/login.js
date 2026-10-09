// ==========================================
// INNOVATECH SOAR - LOGIN
// ==========================================

document.addEventListener("DOMContentLoaded", function () {

    const loginForm = document.getElementById("loginForm");

    const passwordInput = document.getElementById("password");

    const emailInput = document.getElementById("email");

    const togglePassword = document.getElementById("togglePassword");

    const loginError = document.getElementById("loginError");

    const loginButton = document.getElementById("loginButton");


    // ==========================================
    // PASSWORD VISIBILITY
    // ==========================================

    togglePassword.addEventListener("click", function () {

        const isHidden = passwordInput.type === "password";

        passwordInput.type = isHidden ? "text" : "password";

        togglePassword.textContent = isHidden ? "Hide" : "Show";

        togglePassword.setAttribute(
            "aria-label",
            isHidden ? "Hide password" : "Show password"
        );

    });


    // ==========================================
    // CLEAR ERROR MESSAGE
    // ==========================================

    function clearError() {

        loginError.textContent = "";

        loginError.hidden = true;

    }

    emailInput.addEventListener("input", clearError);

    passwordInput.addEventListener("input", clearError);


    // ==========================================
    // LOGIN SUBMISSION
    // ==========================================

    loginForm.addEventListener("submit", function () {

        loginButton.disabled = true;

        loginButton.textContent = "Signing in...";

    });

});