const HOST = 'https://omar.eromo.tech';
$(document).ready(init);
function init() {
    // Add event listener to the form submission
    $('#createAccountForm').submit(function (event) {
        // Prevent the default form submission behavior
        event.preventDefault();

        // Call the createAccount function when the form is submitted
        createAccount();
    });
}

async function createAccount() {
    const email = $('#email').val();
    const password = $('#password').val();
    const confirmPassword = $('#confirmPassword').val();
    const firstName = $('#firstname').val();
    const lastName = $('#lastname').val();
    const carId = getParameterByName('carId');

    // Basic form validation
    if (!email || !password || !confirmPassword || !firstName || !lastName) {
        updateStatus('Please fill in all fields.', 'error');
        return;
    }
    if (password !== confirmPassword) {
        updateStatus('Passwords do not match.', 'error');
        return;
    }
    const USERS_URL = `${HOST}/api/v1/users/`;
    updateStatus('Account creation in progress...', 'info');
    try {
        const response = await fetch(USERS_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                first_name: firstName,
                last_name: lastName,
                email: email,
                password: password,
            }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            const errorMessage = errorData.error || 'Error creating account. Please try again.';
            updateStatus(errorMessage, 'error');
            setTimeout(hideStatus, 3000);
            return;
        }
        updateStatus('Account created successfully! Redirecting to login page...', 'success');
        setTimeout(() => {
            hideStatus();
            const redirectUrl = carId ? `/login.html?carId=${carId}` : `/login.html`;
            window.location.href = redirectUrl;
        }, 3000);
    } catch (error) {
        // Handle network or unexpected errors
        updateStatus('An unexpected error occurred. Please try again.', 'error');
        console.error('Error creating account:', error);
        setTimeout(hideStatus, 3000);
    }
}
