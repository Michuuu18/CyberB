import { Router } from "express";
import { verifyRecaptchaToken } from "../captcha";
import { db, getSetting, getUserById, getUserByLogin } from "../db";
import { requireAuth } from "../middleware";
import {
  hashPassword,
  isPasswordReused,
  savePasswordHistory,
  validatePasswordPolicy,
  verifyPassword,
} from "../password";
import {
  addSecurityAlert,
  checkIpRateLimit,
  clearIpFailures,
  clearLoginFailures,
  clientIp,
  formatLockRemaining,
  getLockRemainingSeconds,
  registerFailedLogin,
  registerIpFailure,
} from "../security";
import {
  buildTotpQrDataUrl,
  createTotpSecret,
  verifyTotpCode,
} from "../totp";

export const authRouter = Router();

function establishSession(
  req: import("express").Request,
  res: import("express").Response,
  user: import("../db").UserRow
): void {
  req.session.regenerate((err) => {
    if (err) {
      res.status(500).json({ error: "Błąd sesji." });
      return;
    }

    req.session.userId = user.id;
    req.session.login = user.login;
    req.session.role = user.role_name;
    req.session.mustChangePassword = Boolean(user.must_change_password);
    req.session.lastActivity = Date.now();
    delete req.session.pendingTotpUserId;
    delete req.session.pendingMustChangePassword;

    res.json({
      login: user.login,
      role: user.role_name,
      mustChangePassword: Boolean(user.must_change_password),
      totpEnabled: Boolean(user.totp_enabled),
    });
  });
}

authRouter.post("/login", async (req, res) => {
  const login = String(req.body?.login ?? "").trim();
  const password = String(req.body?.password ?? "");
  const honeypot = String(req.body?.website ?? req.body?.company_url ?? "");
  const captchaToken = String(req.body?.captchaToken ?? "");
  const challengeId = String(req.body?.captchaChallengeId ?? "");
  const ip = clientIp(req);

  // Pułapka na boty — ukryte pole; człowiek go nie wypełnia
  if (honeypot.trim()) {
    addSecurityAlert("honeypot", "Wykryto wypełnienie ukrytego pola formularza logowania.", {
      ip,
      login,
    });
    res.status(401).json({ error: "Login lub hasło niepoprawne" });
    return;
  }

  const captcha = await verifyRecaptchaToken(captchaToken, challengeId, ip);
  if (!captcha.ok) {
    res.status(400).json({ error: captcha.error });
    return;
  }

  if (!login || !password) {
    res.status(400).json({ error: "Login lub hasło niepoprawne" });
    return;
  }

  const ipCheck = checkIpRateLimit(ip);
  if (ipCheck.blocked) {
    res.status(429).json({
      error: `Zbyt wiele nieudanych prób z tego adresu IP. Spróbuj za ${formatLockRemaining(ipCheck.remainingSeconds)}.`,
      locked: true,
      remainingSeconds: ipCheck.remainingSeconds,
      lockScope: "ip",
    });
    return;
  }

  const user = getUserByLogin(login);

  // Konto-pułapka (canarytoken) — każde użycie = alert
  if (user?.is_honeytoken) {
    addSecurityAlert(
      "canary_account",
      `Użycie konta-pułapki „${user.login}” (honeytoken).`,
      { ip, login: user.login }
    );
    res.status(401).json({ error: "Login lub hasło niepoprawne" });
    return;
  }

  const failGeneric = () => {
    registerIpFailure(ip);
    res.status(401).json({ error: "Login lub hasło niepoprawne" });
  };

  if (!user || user.is_blocked) {
    failGeneric();
    return;
  }

  const lockLeft = getLockRemainingSeconds(user.locked_until);
  if (lockLeft > 0) {
    res.status(429).json({
      error: `Konto zablokowane po zbyt wielu błędnych próbach. Pozostały czas: ${formatLockRemaining(lockLeft)}.`,
      locked: true,
      remainingSeconds: lockLeft,
      lockScope: "account",
    });
    return;
  }

  const ok = await verifyPassword(user.password_hash, password);
  if (!ok) {
    const lock = registerFailedLogin(user.id);
    registerIpFailure(ip);
    if (lock.locked) {
      res.status(429).json({
        error: `Konto zablokowane na 15 minut. Pozostały czas: ${formatLockRemaining(lock.remainingSeconds)}.`,
        locked: true,
        remainingSeconds: lock.remainingSeconds,
        lockScope: "account",
      });
      return;
    }
    res.status(401).json({ error: "Login lub hasło niepoprawne" });
    return;
  }

  clearLoginFailures(user.id);
  clearIpFailures(ip);

  if (user.otp_expires_at && user.must_change_password) {
    const expires = new Date(user.otp_expires_at).getTime();
    if (Number.isFinite(expires) && Date.now() > expires) {
      res.status(401).json({
        error: "Hasło jednorazowe wygasło. Skontaktuj się z administratorem.",
      });
      return;
    }
  }

  const validityDays = Number(getSetting("password_validity_days", "90"));
  if (!user.must_change_password && user.password_changed_at && validityDays > 0) {
    const changed = new Date(user.password_changed_at).getTime();
    const maxAge = validityDays * 24 * 60 * 60 * 1000;
    if (Number.isFinite(changed) && Date.now() - changed > maxAge) {
      db.prepare("UPDATE users SET must_change_password = 1 WHERE id = ?").run(user.id);
      user.must_change_password = 1;
    }
  }

  if (user.totp_enabled && user.totp_secret) {
    req.session.regenerate((err) => {
      if (err) {
        res.status(500).json({ error: "Błąd sesji." });
        return;
      }
      req.session.pendingTotpUserId = user.id;
      req.session.pendingMustChangePassword = Boolean(user.must_change_password);
      req.session.lastActivity = Date.now();
      res.json({ requiresTotp: true, login: user.login });
    });
    return;
  }

  establishSession(req, res, user);
});

authRouter.post("/totp/verify-login", (req, res) => {
  const code = String(req.body?.code ?? "");
  const pendingId = req.session.pendingTotpUserId;

  if (!pendingId) {
    res.status(401).json({ error: "Brak oczekującej weryfikacji 2FA." });
    return;
  }

  const user = getUserById(pendingId);
  if (!user || user.is_blocked || !user.totp_enabled || !user.totp_secret) {
    req.session.destroy(() => {
      res.status(401).json({ error: "Login lub hasło niepoprawne" });
    });
    return;
  }

  if (!verifyTotpCode(user.totp_secret, code, user.login)) {
    res.status(401).json({ error: "Niepoprawny kod TOTP." });
    return;
  }

  user.must_change_password = req.session.pendingMustChangePassword
    ? 1
    : user.must_change_password;
  establishSession(req, res, user);
});

authRouter.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

authRouter.get("/me", (req, res) => {
  if (!req.session.userId) {
    res.status(401).json({ error: "Brak sesji." });
    return;
  }

  const user = getUserById(req.session.userId);
  if (!user || user.is_blocked) {
    res.status(401).json({ error: "Brak sesji." });
    return;
  }

  const idleMinutes = Number(getSetting("session_idle_minutes", "10"));
  res.json({
    id: user.id,
    login: user.login,
    firstName: user.first_name,
    lastName: user.last_name,
    role: user.role_name,
    mustChangePassword: Boolean(user.must_change_password),
    totpEnabled: Boolean(user.totp_enabled),
    sessionIdleMinutes: idleMinutes,
  });
});

authRouter.post("/change-password", requireAuth, async (req, res) => {
  const oldPassword = String(req.body?.oldPassword ?? "");
  const newPassword = String(req.body?.newPassword ?? "");
  const confirmPassword = String(req.body?.confirmPassword ?? "");
  const captchaToken = String(req.body?.captchaToken ?? "");
  const challengeId = String(req.body?.captchaChallengeId ?? "");

  const user = getUserById(req.session.userId!);
  if (!user) {
    res.status(401).json({ error: "Brak sesji." });
    return;
  }

  const captcha = await verifyRecaptchaToken(captchaToken, challengeId, clientIp(req));
  if (!captcha.ok) {
    res.status(400).json({ error: captcha.error });
    return;
  }

  if (newPassword !== confirmPassword) {
    res.status(400).json({ error: "Nowe hasła nie są identyczne." });
    return;
  }

  const oldOk = await verifyPassword(user.password_hash, oldPassword);
  if (!oldOk) {
    res.status(400).json({ error: "Stare hasło jest niepoprawne." });
    return;
  }

  const policy = validatePasswordPolicy(newPassword);
  if (!policy.ok) {
    res.status(400).json({ error: policy.errors.join(" ") });
    return;
  }

  if (await isPasswordReused(user.id, newPassword)) {
    res.status(400).json({ error: "Nowe hasło musi różnić się od poprzednich." });
    return;
  }

  const hash = await hashPassword(newPassword);
  db.prepare(
    `UPDATE users
     SET password_hash = ?, must_change_password = 0, password_changed_at = datetime('now'),
         otp_expires_at = NULL
     WHERE id = ?`
  ).run(hash, user.id);
  savePasswordHistory(user.id, hash);

  req.session.mustChangePassword = false;
  res.json({ ok: true });
});

authRouter.post("/totp/setup", requireAuth, async (req, res) => {
  const user = getUserById(req.session.userId!);
  if (!user) {
    res.status(401).json({ error: "Brak sesji." });
    return;
  }

  if (user.totp_enabled) {
    res.status(400).json({ error: "2FA jest już włączone." });
    return;
  }


  let secret = user.totp_secret;
  if (!secret) {
    secret = createTotpSecret();
    db.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?").run(
      secret,
      user.id
    );
  }

  const qrDataUrl = await buildTotpQrDataUrl(user.login, secret);
  res.json({
    secret,
    qrDataUrl,
    note: "1) Usuń stary wpis CyberB z aplikacji authenticator. 2) Zeskanuj ten QR (albo wpisz sekret). 3) Od razu wpisz pokazywany 6-cyfrowy kod.",
  });
});

authRouter.post("/totp/enable", requireAuth, (req, res) => {
  const code = String(req.body?.code ?? "");
  const user = getUserById(req.session.userId!);
  if (!user || !user.totp_secret) {
    res.status(400).json({ error: "Najpierw uruchom konfigurację 2FA." });
    return;
  }

  if (user.totp_enabled) {
    res.status(400).json({ error: "2FA jest już włączone." });
    return;
  }

  if (!verifyTotpCode(user.totp_secret, code, user.login)) {
    res.status(400).json({
      error:
        "Niepoprawny kod TOTP. Upewnij się, że skanujesz QR z tego ekranu i wpisujesz aktualny kod (odświeża się co 30 s).",
    });
    return;
  }

  db.prepare("UPDATE users SET totp_enabled = 1 WHERE id = ?").run(user.id);
  res.json({ ok: true, totpEnabled: true });
});

authRouter.post("/totp/disable", requireAuth, async (req, res) => {
  const password = String(req.body?.password ?? "");
  const code = String(req.body?.code ?? "");
  const user = getUserById(req.session.userId!);

  if (!user) {
    res.status(401).json({ error: "Brak sesji." });
    return;
  }

  if (!user.totp_enabled || !user.totp_secret) {
    res.status(400).json({ error: "2FA nie jest włączone." });
    return;
  }

  const passOk = await verifyPassword(user.password_hash, password);
  if (!passOk) {
    res.status(400).json({ error: "Hasło jest niepoprawne." });
    return;
  }

  if (!verifyTotpCode(user.totp_secret, code, user.login)) {
    res.status(400).json({
      error:
        "Niepoprawny kod TOTP. Wpisz aktualne 6 cyfr z aplikacji (bez spacji). Sprawdź też godzinę w telefonie.",
    });
    return;
  }

  // Kasuj sekret — ponowne włączenie wymaga nowego QR
  db.prepare("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?").run(user.id);
  res.json({ ok: true, totpEnabled: false });
});
