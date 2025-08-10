const signupModal = document.getElementById("signupModal");
const closeModal = document.getElementById("closeModal");
const signupButton = document.getElementById("openSignupModal");
const togglePassword = document.getElementById("togglePassword");
const passwordInput = document.getElementById("passwordInput");

signupButton.addEventListener("click", function(e) {
  e.preventDefault();
  signupModal.style.display = "flex";
  const modalContent = signupModal.querySelector(".modal-content");
  modalContent.classList.remove("slide-up");
  void modalContent.offsetWidth; // restart animation
  modalContent.classList.add("slide-up");
});

closeModal.addEventListener("click", function() {
  signupModal.style.display = "none";
});

window.addEventListener("click", function(e) {
  if (e.target === signupModal) {
    signupModal.style.display = "none";
  }
});

togglePassword.addEventListener("click", function() {
  const type = passwordInput.getAttribute("type") === "password" ? "text" : "password";
  passwordInput.setAttribute("type", type);
});
