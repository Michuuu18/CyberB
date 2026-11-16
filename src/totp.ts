import * as OTPAuth from "otpauth";
import QRCode from "qrcode";

const ISSUER = "CyberB";

function makeTotp(login: string, secretBase32: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: ISSUER,
    label: login,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secretBase32),
  });
}

export function createTotpSecret(): string {
  // 20 bajtów = standard zgodny z Google Authenticator
  return new OTPAuth.Secret({ size: 20 }).base32;
}

export function buildTotpUri(login: string, secret: string): string {
  return makeTotp(login, secret).toString();
}

export async function buildTotpQrDataUrl(login: string, secret: string): Promise<string> {
  const uri = buildTotpUri(login, secret);
  return QRCode.toDataURL(uri, {
    errorCorrectionLevel: "M",
    margin: 2,
    width: 240,
  });
}

export function normalizeTotpInput(token: string): string {
  return String(token ?? "").replace(/\D/g, "");
}

/** window: 1 = bieżący ± 1 okres (30 s) */
export function verifyTotpCode(secret: string, token: string, login = "user"): boolean {
  const code = normalizeTotpInput(token);
  if (code.length !== 6) return false;

  try {
    const delta = makeTotp(login, secret).validate({
      token: code,
      window: 1,
    });
    return delta !== null;
  } catch {
    return false;
  }
}
