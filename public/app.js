const state = {
  me: null,
  roles: [],
  idleTimer: null,
  canWrite: false,
  canManage: false,
};

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  let data = null;
  const text = await res.text();
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text || "Nieznany błąd" };
  }

  if (!res.ok) {
    const err = new Error(data?.error || `Błąd ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function showMsg(el, text, type = "") {
  el.classList.remove("hidden", "error", "ok", "warn");
  if (type) el.classList.add(type);
  el.textContent = text;
}

function hide(el) {
  el.classList.add("hidden");
}

function show(el) {
  el.classList.remove("hidden");
}

function resetIdleWatch(minutes) {
  if (state.idleTimer) clearTimeout(state.idleTimer);
  const ms = Math.max(1, minutes || 10) * 60 * 1000;
  state.idleTimer = setTimeout(async () => {
    try {
      await api("/api/auth/logout", { method: "POST", body: "{}" });
    } catch {
      /* ignore */
    }
    alert("Sesja wygasła z powodu bezczynności.");
    location.reload();
  }, ms);
}

function bumpActivity() {
  if (state.me) resetIdleWatch(state.me.sessionIdleMinutes);
}

["click", "keydown", "mousemove", "scroll"].forEach((evt) => {
  window.addEventListener(evt, bumpActivity, { passive: true });
});

async function refreshMe() {
  state.me = await api("/api/auth/me");
  state.canManage = state.me.role === "Administrator";
  state.canWrite = state.me.role === "Administrator" || state.me.role === "Redaktor";
  document.getElementById("user-info").textContent =
    `${state.me.login} · ${state.me.role} · idle ${state.me.sessionIdleMinutes} min`;
  resetIdleWatch(state.me.sessionIdleMinutes);
}

function renderTabs(active) {
  const tabs = document.getElementById("tabs");
  const items = [{ id: "articles", label: "Artykuły" }];
  if (state.canManage) items.push({ id: "admin", label: "Panel administratora" });
  items.push({ id: "password", label: "Hasło" });

  tabs.innerHTML = items
    .map(
      (t) =>
        `<button class="tab ${t.id === active ? "active" : ""}" data-tab="${t.id}" type="button">${t.label}</button>`
    )
    .join("");

  tabs.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });
}

async function switchTab(name) {
  ["articles", "admin", "password"].forEach((n) => {
    hide(document.getElementById(`panel-${n}`));
  });
  show(document.getElementById(`panel-${name}`));
  renderTabs(name);

  if (name === "articles") await loadArticles();
  if (name === "admin") {
    await loadRoles();
    await loadUsers();
    await loadSettings();
  }
  if (name === "password") refreshTotpPanel();
}

function refreshTotpPanel() {
  const status = document.getElementById("totp-status");
  const setupBtn = document.getElementById("btn-totp-setup");
  const disableForm = document.getElementById("totp-disable-form");
  const setupBox = document.getElementById("totp-setup-box");

  if (!state.me) return;

  if (state.me.totpEnabled) {
    status.textContent = "Status 2FA: włączone";
    hide(setupBtn);
    hide(setupBox);
    show(disableForm);
  } else {
    status.textContent = "Status 2FA: wyłączone";
    show(setupBtn);
    hide(disableForm);
  }
}

async function enterApp() {
  hide(document.getElementById("login-view"));
  show(document.getElementById("app-view"));
  await refreshMe();

  if (state.me.mustChangePassword) {
    show(document.getElementById("force-password"));
    hide(document.getElementById("main-app"));
  } else {
    hide(document.getElementById("force-password"));
    show(document.getElementById("main-app"));
    const formWrap = document.getElementById("article-form-wrap");
    if (state.canWrite) show(formWrap);
    else hide(formWrap);
    await switchTab(state.canManage ? "admin" : "articles");
  }
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = document.getElementById("login-msg");
  const fd = new FormData(e.target);
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        login: fd.get("login"),
        password: fd.get("password"),
      }),
    });
    hide(msg);
    if (data.requiresTotp) {
      hide(document.getElementById("login-form"));
      show(document.getElementById("totp-login-form"));
      document.getElementById("totp-code").focus();
      return;
    }
    await enterApp();
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

document.getElementById("totp-login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = document.getElementById("login-msg");
  const fd = new FormData(e.target);
  try {
    await api("/api/auth/totp/verify-login", {
      method: "POST",
      body: JSON.stringify({ code: fd.get("code") }),
    });
    hide(msg);
    await enterApp();
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

document.getElementById("totp-cancel").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } catch {
    /* ignore */
  }
  location.reload();
});

document.getElementById("btn-logout").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST", body: "{}" });
  location.reload();
});

document.getElementById("btn-change-pass").addEventListener("click", () => {
  if (!state.me?.mustChangePassword) switchTab("password");
});

async function submitPasswordChange(form, msgEl) {
  const fd = new FormData(form);
  try {
    await api("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({
        oldPassword: fd.get("oldPassword"),
        newPassword: fd.get("newPassword"),
        confirmPassword: fd.get("confirmPassword"),
      }),
    });
    showMsg(msgEl, "Hasło zmienione.", "ok");
    form.reset();
    return true;
  } catch (err) {
    showMsg(msgEl, err.message, "error");
    return false;
  }
}

document.getElementById("force-password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const ok = await submitPasswordChange(e.target, document.getElementById("force-msg"));
  if (ok) await enterApp();
});

document.getElementById("password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await submitPasswordChange(e.target, document.getElementById("password-msg"));
});

document.getElementById("btn-totp-setup").addEventListener("click", async () => {
  const msg = document.getElementById("totp-msg");
  try {
    const data = await api("/api/auth/totp/setup", { method: "POST", body: "{}" });
    document.getElementById("totp-qr").src = data.qrDataUrl;
    document.getElementById("totp-secret").textContent = `Sekret (ręcznie): ${data.secret}`;
    show(document.getElementById("totp-setup-box"));
    showMsg(msg, data.note, "warn");
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

document.getElementById("totp-enable-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = document.getElementById("totp-msg");
  const fd = new FormData(e.target);
  try {
    await api("/api/auth/totp/enable", {
      method: "POST",
      body: JSON.stringify({ code: fd.get("code") }),
    });
    showMsg(msg, "2FA zostało włączone. Przy następnym logowaniu wymagany będzie kod TOTP.", "ok");
    await refreshMe();
    refreshTotpPanel();
    e.target.reset();
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

document.getElementById("totp-disable-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = document.getElementById("totp-msg");
  const fd = new FormData(e.target);
  try {
    await api("/api/auth/totp/disable", {
      method: "POST",
      body: JSON.stringify({
        password: fd.get("password"),
        code: fd.get("code"),
      }),
    });
    showMsg(msg, "2FA zostało wyłączone.", "ok");
    await refreshMe();
    refreshTotpPanel();
    e.target.reset();
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

async function loadArticles() {
  const list = document.getElementById("articles-list");
  try {
    const articles = await api("/api/articles");
    if (!articles.length) {
      list.innerHTML = "<p>Brak artykułów.</p>";
      return;
    }
    list.innerHTML = articles
      .map(
        (a) => `
      <article class="article-item">
        <h3>${escapeHtml(a.title)}</h3>
        <p class="article-meta">${escapeHtml(a.author)} · ${escapeHtml(a.updated_at)}</p>
        <p>${escapeHtml(a.body)}</p>
        ${
          state.canWrite
            ? `<div class="row">
                <button class="btn secondary" data-edit="${a.id}" type="button">Edytuj</button>
                <button class="btn danger" data-del="${a.id}" type="button">Usuń</button>
              </div>`
            : ""
        }
      </article>`
      )
      .join("");

    list.querySelectorAll("[data-edit]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const a = articles.find((x) => String(x.id) === btn.dataset.edit);
        const form = document.getElementById("article-form");
        form.id.value = a.id;
        form.title.value = a.title;
        form.body.value = a.body;
      });
    });

    list.querySelectorAll("[data-del]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm("Usunąć artykuł?")) return;
        await api(`/api/articles/${btn.dataset.del}`, { method: "DELETE" });
        await loadArticles();
      });
    });
  } catch (err) {
    list.innerHTML = `<div class="msg error">${escapeHtml(err.message)}</div>`;
  }
}

document.getElementById("article-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const id = fd.get("id");
  const payload = { title: fd.get("title"), body: fd.get("body") };
  if (id) {
    await api(`/api/articles/${id}`, { method: "PUT", body: JSON.stringify(payload) });
  } else {
    await api("/api/articles", { method: "POST", body: JSON.stringify(payload) });
  }
  e.target.reset();
  await loadArticles();
});

document.getElementById("article-cancel").addEventListener("click", () => {
  document.getElementById("article-form").reset();
});

async function loadRoles() {
  state.roles = await api("/api/admin/roles");
  const select = document.getElementById("role-select");
  select.innerHTML = state.roles
    .map((r) => `<option value="${r.id}">${escapeHtml(r.name)}</option>`)
    .join("");
}

async function loadUsers() {
  const users = await api("/api/admin/users");
  const wrap = document.getElementById("users-table");
  wrap.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Login</th><th>Imię i nazwisko</th><th>Rola</th><th>Status</th><th>Akcje</th>
        </tr>
      </thead>
      <tbody>
        ${users
          .map(
            (u) => `
          <tr>
            <td>${u.id}</td>
            <td>${escapeHtml(u.login)}</td>
            <td>${escapeHtml(u.first_name)} ${escapeHtml(u.last_name)}</td>
            <td><span class="badge">${escapeHtml(u.role)}</span></td>
            <td>
              ${u.is_blocked ? '<span class="badge blocked">zablokowany</span>' : "aktywny"}
              ${u.must_change_password ? " · musi zmienić hasło" : ""}
            </td>
            <td class="actions-cell">
              <div class="action-btns">
                <button class="btn secondary" data-block="${u.id}" data-val="${u.is_blocked ? 0 : 1}" type="button">
                  ${u.is_blocked ? "Odblokuj" : "Zablokuj"}
                </button>
                <button class="btn secondary" data-reset="${u.id}" type="button">Reset OTP</button>
                <button class="btn danger" data-del-user="${u.id}" type="button">Usuń</button>
              </div>
            </td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>`;

  wrap.querySelectorAll("[data-block]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.block;
      const user = users.find((u) => String(u.id) === id);
      try {
        await api(`/api/admin/users/${id}`, {
          method: "PUT",
          body: JSON.stringify({
            firstName: user.first_name,
            lastName: user.last_name,
            roleId: state.roles.find((r) => r.name === user.role)?.id,
            isBlocked: btn.dataset.val === "1",
          }),
        });
        await loadUsers();
      } catch (err) {
        showMsg(document.getElementById("admin-msg"), err.message, "error");
      }
    });
  });

  wrap.querySelectorAll("[data-reset]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        const data = await api(`/api/admin/users/${btn.dataset.reset}/reset-password`, {
          method: "POST",
          body: "{}",
        });
        showMsg(
          document.getElementById("admin-msg"),
          `OTP dla ${data.login}: ${data.oneTimePassword} (ważne ${data.otpValidHours} h)`,
          "warn"
        );
        await loadUsers();
      } catch (err) {
        showMsg(document.getElementById("admin-msg"), err.message, "error");
      }
    });
  });

  wrap.querySelectorAll("[data-del-user]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("Na pewno usunąć użytkownika?")) return;
      try {
        await api(`/api/admin/users/${btn.dataset.delUser}`, { method: "DELETE" });
        await loadUsers();
      } catch (err) {
        showMsg(document.getElementById("admin-msg"), err.message, "error");
      }
    });
  });
}

document.getElementById("user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const msg = document.getElementById("admin-msg");
  try {
    const data = await api("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        login: fd.get("login"),
        firstName: fd.get("firstName"),
        lastName: fd.get("lastName"),
        roleId: Number(fd.get("roleId")),
      }),
    });
    showMsg(
      msg,
      `Utworzono ${data.login}. Hasło jednorazowe: ${data.oneTimePassword}\n${data.note}`,
      "warn"
    );
    e.target.reset();
    await loadUsers();
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

async function loadSettings() {
  const s = await api("/api/admin/settings");
  const form = document.getElementById("settings-form");
  form.minPasswordLength.value = s.minPasswordLength;
  form.policyNoTripleRepeat.checked = s.policyNoTripleRepeat;
  form.passwordValidityDays.value = s.passwordValidityDays;
  form.sessionIdleMinutes.value = s.sessionIdleMinutes;
}

document.getElementById("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const msg = document.getElementById("settings-msg");
  try {
    await api("/api/admin/settings", {
      method: "PUT",
      body: JSON.stringify({
        minPasswordLength: Number(fd.get("minPasswordLength")),
        policyNoTripleRepeat: e.target.policyNoTripleRepeat.checked,
        passwordValidityDays: Number(fd.get("passwordValidityDays")),
        sessionIdleMinutes: Number(fd.get("sessionIdleMinutes")),
      }),
    });
    showMsg(msg, "Ustawienia zapisane.", "ok");
    await refreshMe();
  } catch (err) {
    showMsg(msg, err.message, "error");
  }
});

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

(async function boot() {
  try {
    await refreshMe();
    await enterApp();
  } catch {
    show(document.getElementById("login-view"));
    hide(document.getElementById("app-view"));
  }
})();
