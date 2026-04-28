async function startRegistration() {
    const username = document.getElementById("username").value;

    if (!username) {
        alert("Enter username");
        return;
    }

    // 1. Get options from server
    const options = await fetch("/register-options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
    }).then(r => r.json());

    // 2. Convert fields to ArrayBuffer
    options.challenge = base64ToArrayBuffer(options.challenge);
    options.user.id = base64ToArrayBuffer(options.user.id);

    if (options.excludeCredentials) {
        options.excludeCredentials.forEach(c => {
            c.id = base64ToArrayBuffer(c.id);
        });
    }

    // 3. Create credential
    const credential = await navigator.credentials.create({
        publicKey: options
    });

    // 4. Send to server 
    const attestation = {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        extensions: credential.getClientExtensionResults(),
        response: {
            attestationObject: arrayBufferToBase64(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
        }
    };

    const result = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(attestation)
    });

    alert(await result.text());
}

async function startLogin() {
    const username = document.getElementById("username").value;

    if (!username) {
        alert("Enter username");
        return;
    }

    // 1. Get login options
    const options = await fetch("/login-options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
    }).then(r => r.json());

    // 2. Convert challenge + allowCredentials
    options.challenge = base64ToArrayBuffer(options.challenge);

    if (options.allowCredentials) {
        options.allowCredentials.forEach(c => {
            c.id = base64ToArrayBuffer(c.id);
        });
    }

    // 3. Get assertion
    const assertion = await navigator.credentials.get({
        publicKey: options
    });

    // 4. Send to server  
    const attestation = {
        id: assertion.id,
        rawId: arrayBufferToBase64(assertion.rawId),
        type: assertion.type,
        response: {
            authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64(assertion.response.clientDataJSON),
            signature: arrayBufferToBase64(assertion.response.signature),
            userHandle: assertion.response.userHandle
                ? arrayBufferToBase64(assertion.response.userHandle)
                : null
        }
    };

    const result = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: username,
            assertion: attestation
        })
    });

    const response = await result.json();

    if (response.success) {
        // Store session info in browser (optional but useful for UI)
        sessionStorage.setItem("fido2.authenticated", "true");
        sessionStorage.setItem("username", response.username);

        alert("Login successful!");

        // Redirect or reload to update navbar
        window.location.href = "/";
    }
    else {
        alert("Login failed");
    }
}

/* =========================
   Base64 helpers (critical)
========================= */

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
function base64ToArrayBuffer(base64) {
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');

    const pad = base64.length % 4;
    if (pad) {
        base64 += '='.repeat(4 - pad);
    }

    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}