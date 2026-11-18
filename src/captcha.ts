import crypto from "node:crypto";
import { db, getSetting } from "./db";


// 3x…FF = użytkownik musi kliknąć challenge; 1x…AA secret = weryfikacja przechodzi po kliknięciu
export const TURNSTILE_TEST_SITE_KEY = "3x00000000000000000000FF";
export const TURNSTILE_TEST_SECRET = "1x0000000000000000000000000000000AA";

export function getCaptchaSiteKey(): string {
  return (
    process.env.TURNSTILE_SITE_KEY ||
    process.env.RECAPTCHA_SITE_KEY ||
    getSetting("recaptcha_site_key", TURNSTILE_TEST_SITE_KEY)
  );
}

export function getCaptchaSecret(): string {
  return (
    process.env.TURNSTILE_SECRET_KEY ||
    process.env.RECAPTCHA_SECRET_KEY ||
    getSetting("recaptcha_secret_key", TURNSTILE_TEST_SECRET)
  );
}


export const getRecaptchaSiteKey = getCaptchaSiteKey;
export const getRecaptchaSecret = getCaptchaSecret;

export function createCaptchaChallengeId(): string {
  return crypto.randomBytes(16).toString("hex");
}

export function registerCaptchaChallenge(challengeId: string): void {
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  db.prepare(
    `INSERT INTO captcha_challenges (id, expires_at, used) VALUES (?, ?, 0)`
  ).run(challengeId, expires);
}

function consumeCaptchaChallenge(challengeId: string): { ok: true } | { ok: false; error: string } {
  const row = db
    .prepare("SELECT id, expires_at, used FROM captcha_challenges WHERE id = ?")
    .get(challengeId) as { id: string; expires_at: string; used: number } | undefined;

  if (!row) {
    return { ok: false, error: "Brak ważnego wyzwania CAPTCHA. Odśwież stronę." };
  }
  if (row.used) {
    return { ok: false, error: "Wyzwanie CAPTCHA zostało już użyte." };
  }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    return { ok: false, error: "Wyzwanie CAPTCHA wygasło. Odśwież stronę." };
  }

  db.prepare("UPDATE captcha_challenges SET used = 1 WHERE id = ?").run(challengeId);
  return { ok: true };
}

type TurnstileVerifyResponse = {
  success: boolean;
  "error-codes"?: string[];
};

export async function verifyRecaptchaToken(
  token: string,
  challengeId: string,
  remoteIp?: string
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!token || !String(token).trim()) {
    return { ok: false, error: "Brak tokenu CAPTCHA. Potwierdź, że nie jesteś botem." };
  }

  const challenge = consumeCaptchaChallenge(challengeId);
  if (!challenge.ok) return challenge;

  // Lokalny bypass dla skryptu bota (npm run test:bot)
  if (token === "TEST_TOKEN_OK" && getCaptchaSecret() === TURNSTILE_TEST_SECRET) {
    return { ok: true };
  }

  const params = new URLSearchParams();
  params.set("secret", getCaptchaSecret());
  params.set("response", token);
  if (remoteIp) params.set("remoteip", remoteIp);

  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = (await res.json()) as TurnstileVerifyResponse;
    if (!data.success) {
      return { ok: false, error: "Weryfikacja CAPTCHA (Turnstile) nie powiodła się." };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: "Nie udało się połączyć z usługą CAPTCHA." };
  }
}
