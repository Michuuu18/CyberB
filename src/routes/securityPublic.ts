import { Router } from "express";
import {
  createCaptchaChallengeId,
  getRecaptchaSiteKey,
  registerCaptchaChallenge,
} from "../captcha";
import { addSecurityAlert, clientIp } from "../security";

export const securityPublicRouter = Router();

/** Publiczny config CAPTCHA + nowe jednorazowe wyzwanie (ważne 5 min). */
securityPublicRouter.get("/captcha-config", (_req, res) => {
  const challengeId = createCaptchaChallengeId();
  registerCaptchaChallenge(challengeId);
  res.json({
    provider: "cloudflare-turnstile",
    siteKey: getRecaptchaSiteKey(),
    challengeId,
    challengeTtlSeconds: 300,
  });
});


securityPublicRouter.get("/canary/aws-credentials.txt", (req, res) => {
  addSecurityAlert(
    "canary_document",
    "Pobrano honeytoken dokumentu (fałszywe klucze AWS).",
    { ip: clientIp(req), ua: req.headers["user-agent"] || null }
  );

  const body = [
    "# CANARYTOKEN / HONEYTOKEN — NIEUŻYWANY ZASÓB",
    "# Każdy dostęp do tego pliku jest rejestrowany jako incydent bezpieczeństwa.",
    "#",
    "# Symulowane dane w stylu wycieku kluczy AWS (fałszywe):",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7CANARYEX",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARY",
    "AWS_DEFAULT_REGION=eu-central-1",
    "",
    "# Drugi token: konto-pułapka w aplikacji (login: canary_backup).",
    "# Możesz też wygenerować zewnętrzny token na https://canarytokens.org",
    "",
  ].join("\n");

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", 'inline; filename="aws-credentials.txt"');
  res.send(body);
});
