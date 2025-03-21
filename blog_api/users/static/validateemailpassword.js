function validateform(event) {
    event.preventDefault(); 

    let isValid = true;

    const email = document.getElementById("email").value.trim();
    const emailformat = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (email === '') {
        alert('Email cannot be empty');
        isValid = false;
    } else if (!emailformat.test(email)) {
        alert('Invalid email address');
        isValid = false;
    }

    const username = document.getElementById("username").value.trim();

    if (username === '') {
        alert('Username field cannot be empty');
        isValid = false;
    } else if (username.length < 5) { 
        alert('Username must be at least 5 characters long');
        isValid = false;
    }

    const password = document.getElementById("password").value.trim();

    if (password === '') {
        alert('Password field cannot be empty');
        isValid = false;
    } else if (password.length < 8) {
        alert('Password must be at least 8 characters long');
        isValid = false;
    }

    if (isValid) {
        document.getElementById("registerForm").submit();
    }
}

document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("registerForm").addEventListener("submit", validateform);
});
