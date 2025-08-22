const signupModal = document.getElementById("signupModal");
const closeModal = document.getElementById("closeModal");
const signupButton = document.getElementById("openSignupModal");
const togglePassword = document.getElementById("togglePassword");
const passwordInput = document.getElementById("passwordInput");

// Handle modal open/close if they exist
if (signupButton && signupModal) {
  signupButton.addEventListener("click", function (e) {
    e.preventDefault();
    signupModal.style.display = "flex";
    const modalContent = signupModal.querySelector(".modal-content");
    modalContent.classList.remove("slide-up");
    void modalContent.offsetWidth; // restart animation
    modalContent.classList.add("slide-up");
  });
}

if (closeModal && signupModal) {
  closeModal.addEventListener("click", function () {
    signupModal.style.display = "none";
  });
}

window.addEventListener("click", function (e) {
  if (signupModal && e.target === signupModal) {
    signupModal.style.display = "none";
  }
});

if (togglePassword && passwordInput) {
  togglePassword.addEventListener("click", function () {
    const type = passwordInput.getAttribute("type") === "password" ? "text" : "password";
    passwordInput.setAttribute("type", type);
  });
}

// === OTP / Signup flow ===
const signupForm = document.getElementById("signupForm");
const signupBtn = document.getElementById("signupBtn");
const otpField = document.getElementById("otpField");

if (signupForm && signupBtn && otpField) {
  signupForm.addEventListener("submit", function (e) {
    if (signupBtn.innerText === "Get OTP") {
      // First submit → show OTP field, change button text
      otpField.style.display = "block";
      signupBtn.innerText = "Sign Up";
      e.preventDefault(); // stop form submission on first click
    }
    // Second submit actually posts the form
  });
}
