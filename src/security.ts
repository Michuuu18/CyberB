import type { Request } from "express";
import { db, getSetting } from "./db";

export const LOCK_MINUTES = 15;

export function clientIp(req: Request): string {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0]!.trim();
  return req.socket.remoteAddress || "unknown";
}

export function addSecurityAlert(
  type: string,
  message: string,
  meta?: Record<string, unknown>
): void {
  db.prepare(
    `INSERT INTO security_alerts (type, message, meta_json, created_at)
     VALUES (?, ?, ?, datetime('now'))`
  ).run(type, message, meta ? JSON.stringify(meta) : null);
  console.warn(`[ALERT] ${type}: ${message}`, meta ?? "");
}

export function getMaxFailedLogins(): number {
  return Number(getSetting("max_failed_logins", "5"));
}

export function getMaxFailedLoginsPerIp(): number {
  return Number(getSetting("max_failed_logins_per_ip", "20"));
}

export function getLockRemainingSeconds(lockedUntil: string | null | undefined): number {
  if (!lockedUntil) return 0;
  const ms = new Date(lockedUntil).getTime() - Date.now();
  return ms > 0 ? Math.ceil(ms / 1000) : 0;
}

export function formatLockRemaining(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

export function clearLoginFailures(userId: number): void {
  db.prepare(
    `UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?`
  ).run(userId);
}

export function registerFailedLogin(userId: number): {
  locked: boolean;
  lockedUntil: string | null;
  remainingSeconds: number;
} {
  const max = getMaxFailedLogins();
  const row = db
    .prepare("SELECT failed_login_count, locked_until FROM users WHERE id = ?")
    .get(userId) as { failed_login_count: number; locked_until: string | null };

  const stillLocked = getLockRemainingSeconds(row.locked_until);
  if (stillLocked > 0) {
    return {
      locked: true,
      lockedUntil: row.locked_until,
      remainingSeconds: stillLocked,
    };
  }

  const next = (row.failed_login_count || 0) + 1;
  if (next >= max) {
    const lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60 * 1000).toISOString();
    db.prepare(
      `UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?`
    ).run(next, lockedUntil, userId);
    return {
      locked: true,
      lockedUntil,
      remainingSeconds: LOCK_MINUTES * 60,
    };
  }

  db.prepare(`UPDATE users SET failed_login_count = ?, locked_until = NULL WHERE id = ?`).run(
    next,
    userId
  );
  return { locked: false, lockedUntil: null, remainingSeconds: 0 };
}

export function checkIpRateLimit(ip: string): {
  blocked: boolean;
  remainingSeconds: number;
} {
  const max = getMaxFailedLoginsPerIp();
  const row = db
    .prepare("SELECT fail_count, locked_until FROM ip_login_attempts WHERE ip = ?")
    .get(ip) as { fail_count: number; locked_until: string | null } | undefined;

  if (row) {
    const rem = getLockRemainingSeconds(row.locked_until);
    if (rem > 0) return { blocked: true, remainingSeconds: rem };
  }
  return { blocked: false, remainingSeconds: 0 };
}

export function registerIpFailure(ip: string): {
  blocked: boolean;
  remainingSeconds: number;
} {
  const max = getMaxFailedLoginsPerIp();
  const row = db
    .prepare("SELECT fail_count, locked_until FROM ip_login_attempts WHERE ip = ?")
    .get(ip) as { fail_count: number; locked_until: string | null } | undefined;

  if (row) {
    const rem = getLockRemainingSeconds(row.locked_until);
    if (rem > 0) return { blocked: true, remainingSeconds: rem };
  }

  const next = (row?.fail_count || 0) + 1;
  if (next >= max) {
    const lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60 * 1000).toISOString();
    db.prepare(
      `INSERT INTO ip_login_attempts (ip, fail_count, locked_until, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(ip) DO UPDATE SET
         fail_count = excluded.fail_count,
         locked_until = excluded.locked_until,
         updated_at = excluded.updated_at`
    ).run(ip, next, lockedUntil);
    return { blocked: true, remainingSeconds: LOCK_MINUTES * 60 };
  }

  db.prepare(
    `INSERT INTO ip_login_attempts (ip, fail_count, locked_until, updated_at)
     VALUES (?, ?, NULL, datetime('now'))
     ON CONFLICT(ip) DO UPDATE SET
       fail_count = excluded.fail_count,
       locked_until = NULL,
       updated_at = excluded.updated_at`
  ).run(ip, next);
  return { blocked: false, remainingSeconds: 0 };
}

export function clearIpFailures(ip: string): void {
  db.prepare("DELETE FROM ip_login_attempts WHERE ip = ?").run(ip);
}
