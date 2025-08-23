// ===============================
// MODAL TOGGLING (mutually exclusive)
// ===============================
const loginBtn = document.getElementById('login-btn');
const signupBtn = document.getElementById('signup-btn');
const loginModal = document.getElementById('login-modal');
const signupModal = document.getElementById('signup-modal');
const otpModal = document.getElementById('otp-modal');

const closeLogin = document.getElementById('close-login');
const closeSignup = document.getElementById('close-signup');
const closeOtp = document.getElementById('close-otp');

function openModal(modal) {
    // Close all modals first
    loginModal.style.display = 'none';
    signupModal.style.display = 'none';
    otpModal.style.display = 'none';
    // Open the desired modal
    modal.style.display = 'block';
}

// Open modals mutually exclusive
loginBtn.onclick = () => openModal(loginModal);
signupBtn.onclick = () => openModal(signupModal);

closeLogin.onclick = () => { loginModal.style.display = 'none'; document.getElementById('login-message').innerHTML=''; }
closeSignup.onclick = () => { signupModal.style.display = 'none'; document.getElementById('signup-message').innerHTML=''; }
closeOtp.onclick = () => { otpModal.style.display = 'none'; document.getElementById('otp-message').innerHTML=''; }

// ===============================
// LOGIN AJAX
// ===============================
const loginForm = document.getElementById('login-form');
loginForm.onsubmit = async function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    const data = { username: formData.get('username'), password: formData.get('password') };

    const response = await fetch('/login_ajax', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data)
    });

    const result = await response.json();
    document.getElementById('login-message').innerHTML = result.message;
    if(result.status === 'success'){
        location.href = "/dashboard";
    }
}

// ===============================
// SIGNUP AJAX: check username/email & open OTP modal
// ===============================
const signupForm = document.getElementById('signup-form');
signupForm.onsubmit = async function(e) {
    e.preventDefault();
    const formData = new FormData(this);
    const data = {
        username: formData.get('username'),
        email: formData.get('email'),
        password: formData.get('password')
    };

    const response = await fetch('/signup_ajax', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data)
    });

    const result = await response.json();
    document.getElementById('signup-message').innerHTML = result.message;

    if(result.status === 'otp_modal'){
        signupModal.style.display = 'none';
        otpModal.style.display = 'block';

        // Send OTP in background after modal opens
        fetch('/send_otp_ajax', { method:'POST' })
            .then(resp => resp.json())
            .then(res => {
                document.getElementById('otp-message').innerHTML = res.message;
            });
    }
}

// ===============================
// OTP AJAX
// ===============================
const otpForm = document.getElementById('otp-form');
otpForm.onsubmit = async function(e){
    e.preventDefault();
    const formData = new FormData(this);
    const data = { otp: formData.get('otp') };

    const response = await fetch('/verify_otp_ajax', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(data)
    });

    const result = await response.json();
    document.getElementById('otp-message').innerHTML = result.message;

    if(result.status === 'success'){
        // Close OTP modal and open login modal
        setTimeout(() => { 
            otpModal.style.display = 'none';
            document.getElementById('otp-message').innerHTML='';
            openModal(loginModal);
            document.getElementById('login-message').innerHTML = 'Signup successful! Please login.';
        }, 1000);
    }
}
