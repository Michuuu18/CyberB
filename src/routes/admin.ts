import { Router } from "express";
import { db, getSetting, getUserById, setSetting } from "../db";
import {
  blockIfMustChangePassword,
  requireAuth,
  requirePermission,
} from "../middleware";
import {
  generateOneTimePassword,
  hashPassword,
  otpExpiresAt,
  savePasswordHistory,
  validatePasswordPolicy,
} from "../password";

export const adminRouter = Router();

adminRouter.use(requireAuth, blockIfMustChangePassword, requirePermission("users.manage"));

adminRouter.get("/users", (_req, res) => {
  const users = db
    .prepare(
      `SELECT u.id, u.login, u.first_name, u.last_name, u.is_blocked,
              u.must_change_password, u.password_changed_at, u.otp_expires_at, u.created_at,
              r.name AS role
       FROM users u
       JOIN roles r ON r.id = u.role_id
       ORDER BY u.id`
    )
    .all();
  res.json(users);
});

adminRouter.get("/roles", (_req, res) => {
  const roles = db.prepare("SELECT id, name FROM roles ORDER BY id").all();
  res.json(roles);
});

adminRouter.get("/settings", (_req, res) => {
  res.json({
    minPasswordLength: Number(getSetting("min_password_length", "15")),
    policyNoTripleRepeat: getSetting("policy_no_triple_repeat", "1") === "1",
    passwordValidityDays: Number(getSetting("password_validity_days", "90")),
    sessionIdleMinutes: Number(getSetting("session_idle_minutes", "10")),
  });
});

adminRouter.put("/settings", (req, res) => {
  const {
    minPasswordLength,
    policyNoTripleRepeat,
    passwordValidityDays,
    sessionIdleMinutes,
  } = req.body ?? {};

  if (minPasswordLength !== undefined) {
    const n = Number(minPasswordLength);
    if (!Number.isFinite(n) || n < 8 || n > 128) {
      res.status(400).json({ error: "Nieprawidłowa minimalna długość hasła." });
      return;
    }
    setSetting("min_password_length", String(n));
  }

  if (policyNoTripleRepeat !== undefined) {
    setSetting("policy_no_triple_repeat", policyNoTripleRepeat ? "1" : "0");
  }

  if (passwordValidityDays !== undefined) {
    const n = Number(passwordValidityDays);
    if (!Number.isFinite(n) || n < 0 || n > 3650) {
      res.status(400).json({ error: "Nieprawidłowa ważność hasła." });
      return;
    }
    setSetting("password_validity_days", String(n));
  }

  if (sessionIdleMinutes !== undefined) {
    const n = Number(sessionIdleMinutes);
    if (!Number.isFinite(n) || n < 1 || n > 1440) {
      res.status(400).json({ error: "Nieprawidłowy czas bezczynności." });
      return;
    }
    setSetting("session_idle_minutes", String(n));
  }

  res.json({ ok: true });
});

adminRouter.post("/users", async (req, res) => {
  const login = String(req.body?.login ?? "").trim();
  const firstName = String(req.body?.firstName ?? "").trim();
  const lastName = String(req.body?.lastName ?? "").trim();
  const roleId = Number(req.body?.roleId);

  if (!login || !firstName || !lastName || !roleId) {
    res.status(400).json({ error: "Wypełnij wszystkie pola." });
    return;
  }

  const role = db.prepare("SELECT id FROM roles WHERE id = ?").get(roleId);
  if (!role) {
    res.status(400).json({ error: "Nieznana rola." });
    return;
  }

  const otp = generateOneTimePassword();
  const hash = await hashPassword(otp);

  try {
    const result = db
      .prepare(
        `INSERT INTO users (
           login, first_name, last_name, password_hash, role_id,
           must_change_password, otp_expires_at
         ) VALUES (?, ?, ?, ?, ?, 1, ?)`
      )
      .run(login, firstName, lastName, hash, roleId, otpExpiresAt(24));

    savePasswordHistory(Number(result.lastInsertRowid), hash);

    res.status(201).json({
      id: result.lastInsertRowid,
      login,
      oneTimePassword: otp,
      otpValidHours: 24,
      note: "Hasło jednorazowe: 12 znaków alfanumerycznych, ważne 24 h (wariant 1).",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "";
    if (message.includes("UNIQUE")) {
      res.status(409).json({ error: "Login już istnieje." });
      return;
    }
    throw err;
  }
});

adminRouter.put("/users/:id", (req, res) => {
  const id = Number(req.params.id);
  const user = getUserById(id);
  if (!user) {
    res.status(404).json({ error: "Nie znaleziono użytkownika." });
    return;
  }

  const firstName = String(req.body?.firstName ?? user.first_name).trim();
  const lastName = String(req.body?.lastName ?? user.last_name).trim();
  const roleId = Number(req.body?.roleId ?? user.role_id);
  const isBlocked =
    req.body?.isBlocked === undefined ? user.is_blocked : req.body.isBlocked ? 1 : 0;

  if (user.login.toUpperCase() === "ADMIN" && isBlocked) {
    res.status(400).json({ error: "Nie można zablokować konta ADMIN." });
    return;
  }

  const role = db.prepare("SELECT id FROM roles WHERE id = ?").get(roleId);
  if (!role) {
    res.status(400).json({ error: "Nieznana rola." });
    return;
  }

  db.prepare(
    `UPDATE users
     SET first_name = ?, last_name = ?, role_id = ?, is_blocked = ?
     WHERE id = ?`
  ).run(firstName, lastName, roleId, isBlocked, id);

  res.json({ ok: true });
});

adminRouter.post("/users/:id/reset-password", async (req, res) => {
  const id = Number(req.params.id);
  const user = getUserById(id);
  if (!user) {
    res.status(404).json({ error: "Nie znaleziono użytkownika." });
    return;
  }

  const otp = generateOneTimePassword();
  const hash = await hashPassword(otp);

  db.prepare(
    `UPDATE users
     SET password_hash = ?, must_change_password = 1, password_changed_at = NULL,
         otp_expires_at = ?
     WHERE id = ?`
  ).run(hash, otpExpiresAt(24), id);
  savePasswordHistory(id, hash);

  res.json({
    login: user.login,
    oneTimePassword: otp,
    otpValidHours: 24,
  });
});

adminRouter.delete("/users/:id", (req, res) => {
  const id = Number(req.params.id);
  const user = getUserById(id);
  if (!user) {
    res.status(404).json({ error: "Nie znaleziono użytkownika." });
    return;
  }

  if (user.login.toUpperCase() === "ADMIN") {
    res.status(400).json({ error: "Nie można usunąć konta ADMIN." });
    return;
  }

  if (req.session.userId === id) {
    res.status(400).json({ error: "Nie możesz usunąć własnego konta." });
    return;
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ ok: true });
});

adminRouter.post("/validate-password", (req, res) => {
  const password = String(req.body?.password ?? "");
  const result = validatePasswordPolicy(password);
  res.json(result);
});
