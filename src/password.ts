import argon2 from "argon2";
import crypto from "node:crypto";
import { db, getSetting } from "./db";

export const DEFAULT_MIN_LENGTH = 15;

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, { type: argon2.argon2id });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/** Wariant 1: 12 znaków alfanumerycznych, ważne 24 h */
export function generateOneTimePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.randomBytes(12);
  let out = "";
  for (let i = 0; i < 12; i++) {
    out += alphabet[bytes[i]! % alphabet.length];
  }
  return out;
}

export function otpExpiresAt(hours = 24): string {
  const d = new Date(Date.now() + hours * 60 * 60 * 1000);
  return d.toISOString();
}

export type PasswordPolicyResult = { ok: true } | { ok: false; errors: string[] };

export function validatePasswordPolicy(
  password: string,
  options?: { checkRepeatRule?: boolean }
): PasswordPolicyResult {
  const errors: string[] = [];
  const minLength = Number(getSetting("min_password_length", String(DEFAULT_MIN_LENGTH)));
  const repeatRuleEnabled =
    options?.checkRepeatRule ?? getSetting("policy_no_triple_repeat", "1") === "1";

  if (password.length < minLength) {
    errors.push(`Hasło musi mieć co najmniej ${minLength} znaków.`);
  }

  if (repeatRuleEnabled && /(.)\1\1/.test(password)) {
    errors.push("Hasło nie może zawierać 3 lub więcej identycznych znaków z rzędu.");
  }

  return errors.length ? { ok: false, errors } : { ok: true };
}

export async function isPasswordReused(userId: number, newPassword: string): Promise<boolean> {
  const rows = db
    .prepare("SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT 5")
    .all(userId) as { password_hash: string }[];

  for (const row of rows) {
    if (await verifyPassword(row.password_hash, newPassword)) {
      return true;
    }
  }
  return false;
}

export function savePasswordHistory(userId: number, passwordHash: string): void {
  db.prepare("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)").run(
    userId,
    passwordHash
  );
}
