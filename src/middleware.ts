import type { NextFunction, Request, Response } from "express";
import { db, getSetting, getUserById } from "./db";

export function touchSession(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.userId && !req.session.pendingTotpUserId) {
    next();
    return;
  }

  const idleMinutes = Number(getSetting("session_idle_minutes", "10"));
  const idleMs = idleMinutes * 60 * 1000;
  const now = Date.now();
  const last = req.session.lastActivity ?? now;

  if (now - last > idleMs) {
    req.session.destroy(() => {
      res.status(401).json({ error: "Sesja wygasła z powodu bezczynności." });
    });
    return;
  }

  req.session.lastActivity = now;
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.userId) {
    res.status(401).json({ error: "Wymagane logowanie." });
    return;
  }

  const user = getUserById(req.session.userId);
  if (!user || user.is_blocked) {
    req.session.destroy(() => {
      res.status(401).json({ error: "Konto niedostępne." });
    });
    return;
  }

  next();
}

export function requirePermission(code: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.session.userId) {
      res.status(401).json({ error: "Wymagane logowanie." });
      return;
    }

    const row = db
      .prepare(
        `SELECT 1 AS ok
         FROM users u
         JOIN role_permissions rp ON rp.role_id = u.role_id
         JOIN permissions p ON p.id = rp.permission_id
         WHERE u.id = ? AND p.code = ?`
      )
      .get(req.session.userId, code) as { ok: number } | undefined;

    if (!row) {
      res.status(403).json({ error: "Brak uprawnień (403)." });
      return;
    }

    next();
  };
}

export function blockIfMustChangePassword(req: Request, res: Response, next: NextFunction): void {
  if (req.session.mustChangePassword) {
    res.status(403).json({
      error: "Wymagana zmiana hasła przed dalszym korzystaniem z systemu.",
      mustChangePassword: true,
    });
    return;
  }
  next();
}
