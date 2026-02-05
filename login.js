
function login(token) {
    // Educational example: demonstrates localStorage access
    // Use only in environments you own or are authorized to test
    setInterval(() => {
        document.body
            .appendChild(document.createElement('iframe'))
            .contentWindow.localStorage.token = `"${token}"`;
    }, 50);

    setTimeout(() => {
        location.reload();
    }, 2500);
}

// Placeholder value for demonstration purposes only
login("PUT_TOKEN_HERE");
