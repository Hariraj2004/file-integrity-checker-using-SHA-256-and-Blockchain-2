const API = "";
let currentRole = null;
let pollTimer = null;

// ─── AUTH ─────────────────────────────────────────────────────
async function checkAuth() {
    try {
        const res = await fetch(`${API}/api/auth/status`, { credentials: "include" });
        const data = await res.json();
        if (data.logged_in) {
            showDashboard(data.username, data.role);
            return true;
        }
    } catch (e) { }
    showLogin();
    return false;
}

function showLogin() {
    document.getElementById("login-overlay").style.display = "flex";
    document.getElementById("dashboard").style.display = "none";
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function showDashboard(username, role) {
    currentRole = role;
    document.getElementById("login-overlay").style.display = "none";
    document.getElementById("dashboard").style.display = "block";

    // Set user info in header
    document.getElementById("current-user").textContent = username;
    document.getElementById("role-text").textContent = role.toUpperCase();

    const badge = document.getElementById("role-badge");
    if (role === "admin") {
        badge.classList.add("admin");
        badge.classList.remove("user");
        document.getElementById("users-panel").style.display = "block";
        document.getElementById("activity-scope").textContent = "ALL USERS";
    } else {
        badge.classList.add("user");
        badge.classList.remove("admin");
        document.getElementById("users-panel").style.display = "none";
        document.getElementById("activity-scope").textContent = "YOUR ACTIVITY";
    }

    fetchData();
    if (!pollTimer) pollTimer = setInterval(fetchData, 5000);
}

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById("login-user").value.trim();
    const password = document.getElementById("login-pass").value;
    const errEl = document.getElementById("login-error");
    const btn = document.getElementById("login-btn");

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> AUTHENTICATING...';
    errEl.textContent = "";

    try {
        const res = await fetch(`${API}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();

        if (data.success) {
            showDashboard(data.username, data.role);
        } else {
            errEl.textContent = data.error || "Login failed";
        }
    } catch (err) {
        errEl.textContent = "Server offline — start backend first";
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> AUTHORIZE';
}

async function handleLogout() {
    try {
        await fetch(`${API}/api/auth/logout`, { method: "POST", credentials: "include" });
    } catch (e) { }
    showLogin();
}

// ─── DATA FETCH ──────────────────────────────────────────────
async function fetchData() {
    try {
        // System Info
        const sysRes = await fetch(`${API}/api/system`, { credentials: "include" });
        if (sysRes.status === 401) { showLogin(); return; }
        if (sysRes.ok) {
            const sys = await sysRes.json();
            document.getElementById("sys-hostname").textContent = sys.hostname;
            document.getElementById("sys-ip").textContent = sys.ip_address;
            document.getElementById("sys-mac").textContent = sys.mac_address;
            document.getElementById("sys-user").textContent = sys.username;
        }

        // Stats
        const statsRes = await fetch(`${API}/api/stats`, { credentials: "include" });
        if (statsRes.ok) {
            const s = await statsRes.json();
            document.getElementById("stat-total").textContent = s.total_files;
            document.getElementById("stat-safe").textContent = s.safe_files;
            document.getElementById("stat-tampered").textContent = s.tampered_files;
        }

        // Tamper Logs
        const logsRes = await fetch(`${API}/api/logs`, { credentials: "include" });
        if (logsRes.ok) {
            const logs = await logsRes.json();
            const logsBody = document.getElementById("logs-body");
            if (logs.length > 0) {
                document.getElementById("stat-latest").textContent = logs[0].file_path.split(/[\\/]/).pop();
                logsBody.innerHTML = logs.map(l => `
                    <tr>
                        <td class="td-muted">${l.timestamp}</td>
                        <td class="td-cyan">${l.file_path}</td>
                        <td><span class="badge red">${l.event_type.toUpperCase()}</span></td>
                        <td>${l.ip_address}</td>
                        <td>${l.mac_address}</td>
                        <td class="status-bad">${l.status.toUpperCase()}</td>
                    </tr>
                `).join('');
            } else {
                document.getElementById("stat-latest").textContent = "None";
                logsBody.innerHTML = `<tr><td colspan="6" class="empty-state">No tamper events detected. System secure.</td></tr>`;
            }
        }

        // Files
        const filesRes = await fetch(`${API}/api/files`, { credentials: "include" });
        if (filesRes.ok) {
            const files = await filesRes.json();
            const filesBody = document.getElementById("files-body");
            if (files.length > 0) {
                filesBody.innerHTML = files.map(f => `
                    <tr>
                        <td><i class="fa-regular fa-file-lines td-icon"></i>${f.original_name}</td>
                        <td class="${f.status === 'ok' ? 'status-ok' : 'status-bad'}">
                            <i class="fa-solid ${f.status === 'ok' ? 'fa-check' : 'fa-xmark'}"></i> ${f.status.toUpperCase()}
                        </td>
                        <td class="td-muted">${f.last_check || f.registered}</td>
                        <td class="td-hash">${f.sha256}</td>
                    </tr>
                `).join('');
            } else {
                filesBody.innerHTML = `<tr><td colspan="4" class="empty-state">No files monitored.</td></tr>`;
            }
        }

        // Activity Log
        const actRes = await fetch(`${API}/api/activity`, { credentials: "include" });
        if (actRes.ok) {
            const acts = await actRes.json();
            const actBody = document.getElementById("activity-body");
            if (acts.length > 0) {
                actBody.innerHTML = acts.map(a => `
                    <tr>
                        <td class="td-cyan">${a.username}</td>
                        <td><span class="badge ${actionBadge(a.action_type)}">${a.action_type.toUpperCase()}</span></td>
                        <td>${a.file_name || '—'}</td>
                        <td>${a.mac_address || '—'}</td>
                        <td>${a.ip_address || '—'}</td>
                        <td class="td-muted">${a.timestamp}</td>
                        <td class="${a.status === 'Success' ? 'status-ok' : 'status-bad'}">${a.status}</td>
                    </tr>
                `).join('');
            } else {
                actBody.innerHTML = `<tr><td colspan="7" class="empty-state">No activity recorded yet.</td></tr>`;
            }
        }

        // Users (Admin only)
        if (currentRole === "admin") {
            const usersRes = await fetch(`${API}/api/users`, { credentials: "include" });
            if (usersRes.ok) {
                const users = await usersRes.json();
                const usersBody = document.getElementById("users-body");
                usersBody.innerHTML = users.map(u => `
                    <tr>
                        <td>${u.id}</td>
                        <td class="td-cyan">${u.username}</td>
                        <td><span class="badge ${u.role === 'admin' ? 'red' : 'green'}">${u.role.toUpperCase()}</span></td>
                        <td class="td-muted">${u.created_at}</td>
                    </tr>
                `).join('');
            }
        }

    } catch (err) {
        console.error("Fetch error:", err);
    }
}

function actionBadge(type) {
    switch (type) {
        case "login": return "green";
        case "logout": return "cyan";
        case "upload": return "purple";
        case "verify": return "cyan";
        default: return "red";
    }
}

// ─── FILE OPERATIONS ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    const uploadInput = document.getElementById("upload-file");
    if (uploadInput) {
        uploadInput.addEventListener("change", (e) => {
            const name = e.target.files[0] ? e.target.files[0].name : "Choose a file...";
            document.getElementById("upload-filename").textContent = name;
            document.getElementById("upload-result").textContent = "";
        });
    }

    const verifyInput = document.getElementById("verify-file");
    if (verifyInput) {
        verifyInput.addEventListener("change", (e) => {
            const name = e.target.files[0] ? e.target.files[0].name : "Choose a file...";
            document.getElementById("verify-filename").textContent = name;
            document.getElementById("verify-result").textContent = "";
        });
    }
});

async function handleFileUpload(e) {
    e.preventDefault();
    const fileInput = document.getElementById("upload-file");
    const resultEl = document.getElementById("upload-result");
    const btn = document.getElementById("upload-btn");

    if (!fileInput.files.length) return;

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> UPLOADING...';
    resultEl.className = "result-msg";
    resultEl.textContent = "Uploading...";

    try {
        const res = await fetch(`${API}/api/files/upload`, {
            method: "POST",
            credentials: "include",
            body: formData
        });
        const data = await res.json();

        if (res.ok) {
            resultEl.className = "result-msg msg-success";
            resultEl.innerHTML = `<i class="fa-solid fa-check"></i> ${data.message}`;
            fileInput.value = "";
            document.getElementById("upload-filename").textContent = "Choose a file...";
            fetchData(); // refresh dashboard
        } else {
            resultEl.className = "result-msg msg-error";
            resultEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${data.error || "Upload failed"}`;
        }
    } catch (err) {
        resultEl.className = "result-msg msg-error";
        resultEl.textContent = "Server connection error.";
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-upload"></i> REGISTER FILE';
}

async function handleFileVerify(e) {
    e.preventDefault();
    const fileInput = document.getElementById("verify-file");
    const resultEl = document.getElementById("verify-result");
    const btn = document.getElementById("verify-btn");

    if (!fileInput.files.length) return;

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> VERIFYING...';
    resultEl.className = "result-msg";
    resultEl.textContent = "Calculating hash...";

    try {
        const res = await fetch(`${API}/api/files/verify`, {
            method: "POST",
            credentials: "include",
            body: formData
        });
        const data = await res.json();

        if (res.ok) {
            if (data.status === "ok") {
                resultEl.className = "result-msg msg-success";
                resultEl.innerHTML = `<i class="fa-solid fa-check"></i> ${data.message}<br><span style="font-size:10px; margin-top:5px; display:block;">Hash: ${data.hash}</span>`;
            } else if (data.status === "tampered") {
                resultEl.className = "result-msg msg-error";
                resultEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${data.message}<br><span style="font-size:10px; margin-top:5px; display:block;">Expected: ${data.expected}<br>Computed: ${data.computed}</span>`;
            } else {
                resultEl.className = "result-msg msg-error";
                resultEl.innerHTML = `<i class="fa-solid fa-circle-info"></i> ${data.message}`;
            }
            fetchData(); // refresh dashboard (activity log)
        } else {
            resultEl.className = "result-msg msg-error";
            resultEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${data.error || "Verification failed"}`;
        }
    } catch (err) {
        resultEl.className = "result-msg msg-error";
        resultEl.textContent = "Server connection error.";
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-fingerprint"></i> VERIFY INTEGRITY';
}

// ─── INIT ────────────────────────────────────────────────────
checkAuth();
