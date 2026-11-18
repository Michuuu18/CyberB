
const BASE = process.env.APP_URL || "http://localhost:3000";

async function getCaptcha() {
  const res = await fetch(`${BASE}/api/security/captcha-config`);
  if (!res.ok) throw new Error("Nie pobrano captcha-config — czy serwer działa?");
  return res.json();
}

async function login(body) {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

function row(name, ok, detail) {
  return {
    zabezpieczenie: name,
    zadzialalo: ok ? "TAK" : "NIE",
    szczegoly: String(detail).slice(0, 120),
  };
}

async function main() {
  console.log(`=== CyberB Moduł 2 — test bota ===`);
  console.log(`Cel: ${BASE}\n`);
  const results = [];


  {
    const cap = await getCaptcha();
    const r = await login({
      login: "ADMIN",
      password: "x",
      website: "",
      captchaToken: "",
      captchaChallengeId: cap.challengeId,
    });
    results.push(
      row("CAPTCHA – odrzucenie bez tokenu", r.status === 400, `${r.status} ${r.data.error || ""}`)
    );
  }


  {
    const cap = await getCaptcha();
    const r = await login({
      login: "ADMIN",
      password: "AdminStartPass15!",
      website: "http://i-am-a-bot.example",
      captchaToken: "TEST_TOKEN_OK",
      captchaChallengeId: cap.challengeId,
    });
    results.push(
      row(
        "Honeypot – ukryte pole website",
        r.status === 401,
        `${r.status} ${r.data.error || ""}`
      )
    );
  }

  
  {
    const doc = await fetch(`${BASE}/api/security/canary/aws-credentials.txt`);
    const text = await doc.text();
    results.push(
      row(
        "Canarytoken dokumentu (AWS)",
        doc.status === 200 && text.includes("CANARYTOKEN"),
        `HTTP ${doc.status}`
      )
    );
  }


  {
    const cap = await getCaptcha();
    const r = await login({
      login: "canary_backup",
      password: "CanaryTrap99xx",
      website: "",
      captchaToken: "TEST_TOKEN_OK",
      captchaChallengeId: cap.challengeId,
    });
    results.push(
      row(
        "Canarytoken konta canary_backup",
        r.status === 401,
        `${r.status} ${r.data.error || ""} (+ alert w panelu admina)`
      )
    );
  }

 
  {
    let last = {};
    const maxTries = 6;
    for (let i = 0; i < maxTries; i++) {
      const cap = await getCaptcha();
      last = await login({
        login: "czytelnik2",
        password: "zle-haslo-bota",
        website: "",
        captchaToken: "TEST_TOKEN_OK",
        captchaChallengeId: cap.challengeId,
      });
      if (last.status === 429) break;
    }
    results.push(
      row(
        "Limit błędnych logowań → blokada 15 min",
        last.status === 429 && last.data.locked === true,
        `${last.status} remaining=${last.data.remainingSeconds ?? "?"}s`
      )
    );
  }


  {
    let last = {};
    for (let i = 0; i < 25; i++) {
      const cap = await getCaptcha();
      last = await login({
        login: `nieistniejacy_${i}`,
        password: "x",
        website: "",
        captchaToken: "TEST_TOKEN_OK",
        captchaChallengeId: cap.challengeId,
      });
      if (last.status === 429 && last.data.lockScope === "ip") break;
    }
    results.push(
      row(
        "Limit prób z jednego IP (password spraying)",
        last.status === 429 && last.data.lockScope === "ip",
        `${last.status} ${last.data.lockScope || ""} ${last.data.error || ""}`
      )
    );
  }

  console.log("Zestawienie — które zabezpieczenia zadziałały:\n");
  console.table(results);

  const passed = results.filter((r) => r.zadzialalo === "TAK").length;
  console.log(`\nWynik: ${passed}/${results.length} testów pozytywnych.`);
  console.log("AlerTy canary zobaczysz w panelu admina (Alerty bezpieczeństwa).");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
