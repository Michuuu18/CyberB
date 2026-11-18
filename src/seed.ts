import fs from "node:fs";
import path from "node:path";
import { db, initSchema, setSetting } from "./db";
import {
  DEFAULT_MIN_LENGTH,
  hashPassword,
  otpExpiresAt,
  savePasswordHistory,
} from "./password";

const RESET = process.argv.includes("--reset");


const DEMO_ACCOUNTS = [
  {
    login: "ADMIN",
    first: "System",
    last: "Administrator",
    role: "Administrator",
    password: "AdminStartPass15!",
    note: "stałe konto ADMIN, wymuszona zmiana hasła",
  },
  {
    login: "redaktor1",
    first: "Anna",
    last: "Nowak",
    role: "Redaktor",
    password: "RedaktorDemo1",
    note: "OTP demo (12 znaków), rola Redaktor",
  },
  {
    login: "redaktor2",
    first: "Piotr",
    last: "Kowalski",
    role: "Redaktor",
    password: "RedaktorDemo2",
    note: "OTP demo (12 znaków), rola Redaktor",
  },
  {
    login: "czytelnik1",
    first: "Ewa",
    last: "Wiśniewska",
    role: "Czytelnik",
    password: "CzytelnikDm1",
    note: "OTP demo (12 znaków), rola Czytelnik",
  },
  {
    login: "czytelnik2",
    first: "Marek",
    last: "Wójcik",
    role: "Czytelnik",
    password: "CzytelnikDm2",
    note: "OTP demo (12 znaków), rola Czytelnik",
  },
  {
    login: "czytelnik3",
    first: "Zofia",
    last: "Kamińska",
    role: "Czytelnik",
    password: "CzytelnikDm3",
    note: "OTP demo (12 znaków), rola Czytelnik",
  },
] as const;

function writeAccountsFile(lines: string[]): void {
  const filePath = path.join(process.cwd(), "ACCOUNTS.txt");
  const body = [
    "Konta startowe CyberB (wariant 1)",
    ,
    `Wygenerowano: ${new Date().toLocaleString("pl-PL")}`,
    "OTP / hasła startowe ważne 24 h od momentu uruchomienia: npm run seed",
    "Po zalogowaniu system wymusza zmianę hasła.",
    "",
    ...lines,
    "",
    "Uruchomienie:",
    "  npm install",
    "  npm run seed -- --reset",
    "  npm start",
    "  http://localhost:3000",
    "",
  ].join("\n");
  fs.writeFileSync(filePath, body, "utf8");
  console.log(`Zapisano dane logowania do: ${filePath}`);
}

async function seed(): Promise<void> {
  initSchema();

  if (RESET) {
    db.exec(`
      DELETE FROM password_history;
      DELETE FROM articles;
      DELETE FROM users;
      DELETE FROM captcha_challenges;
      DELETE FROM ip_login_attempts;
      DELETE FROM security_alerts;
      DELETE FROM sqlite_sequence
        WHERE name IN ('users', 'articles', 'password_history', 'security_alerts');
    `);
    console.log("Tryb --reset: usunięto użytkowników/artykuły i zresetowano ID od 1.");
  }

  const roleCount = db.prepare("SELECT COUNT(*) AS c FROM roles").get() as { c: number };
  if (roleCount.c === 0) {
    const insertRole = db.prepare("INSERT INTO roles (name) VALUES (?)");
    insertRole.run("Administrator");
    insertRole.run("Redaktor");
    insertRole.run("Czytelnik");
  }

  const permCount = db.prepare("SELECT COUNT(*) AS c FROM permissions").get() as { c: number };
  if (permCount.c === 0) {
    const insertPerm = db.prepare("INSERT INTO permissions (code, description) VALUES (?, ?)");
    insertPerm.run("users.manage", "Zarządzanie użytkownikami i polityką haseł");
    insertPerm.run("articles.write", "Tworzenie i edycja artykułów");
    insertPerm.run("articles.read", "Odczyt artykułów");
    insertPerm.run("password.change_own", "Zmiana własnego hasła");

    const roles = db.prepare("SELECT id, name FROM roles").all() as { id: number; name: string }[];
    const perms = db.prepare("SELECT id, code FROM permissions").all() as {
      id: number;
      code: string;
    }[];
    const byCode = Object.fromEntries(perms.map((p) => [p.code, p.id]));
    const link = db.prepare(
      "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)"
    );

    const matrix: Record<string, string[]> = {
      Administrator: [
        "users.manage",
        "articles.write",
        "articles.read",
        "password.change_own",
      ],
      Redaktor: ["articles.write", "articles.read", "password.change_own"],
      Czytelnik: ["articles.read", "password.change_own"],
    };

    for (const role of roles) {
      for (const code of matrix[role.name] ?? []) {
        link.run(role.id, byCode[code]);
      }
    }
  }

  setSetting("min_password_length", String(DEFAULT_MIN_LENGTH));
  setSetting("policy_no_triple_repeat", "1");
  setSetting("password_validity_days", "90");
  setSetting("session_idle_minutes", "10");
  setSetting("max_failed_logins", "5");
  setSetting("max_failed_logins_per_ip", "20");

  const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get() as { c: number };
  if (userCount.c > 0) {
    console.log("Baza już zawiera użytkowników – pomijam tworzenie kont.");
    console.log("Aby odświeżyć hasła startowe (ważne kolejne 24 h), uruchom:");
    console.log("  npm run seed -- --reset");
    return;
  }

  const roleId = (name: string) =>
    (db.prepare("SELECT id FROM roles WHERE name = ?").get(name) as { id: number }).id;

  const insertUser = db.prepare(`
    INSERT INTO users (
      login, first_name, last_name, password_hash, role_id,
      is_blocked, must_change_password, password_changed_at, otp_expires_at, is_honeytoken
    ) VALUES (?, ?, ?, ?, ?, 0, 1, NULL, ?, ?)
  `);

  const accountLines: string[] = [];
  let adminId = 0;

  console.log("\n=== Konta startowe (wariant 1) ===");
  for (const u of DEMO_ACCOUNTS) {
    const hash = await hashPassword(u.password);
    const result = insertUser.run(
      u.login,
      u.first,
      u.last,
      hash,
      roleId(u.role),
      otpExpiresAt(24),
      0
    );
    const id = Number(result.lastInsertRowid);
    savePasswordHistory(id, hash);
    if (u.login === "ADMIN") adminId = id;

    const line = `${u.login} / ${u.password}  (${u.note})`;
    console.log(line);
    accountLines.push(line);
  }

  {
    const canaryPass = "CanaryTrap99xx";
    const hash = await hashPassword(canaryPass);
    const result = insertUser.run(
      "canary_backup",
      "Honeytoken",
      "Canary",
      hash,
      roleId("Administrator"),
      otpExpiresAt(24 * 365),
      1
    );
    savePasswordHistory(Number(result.lastInsertRowid), hash);
    const line =
      "canary_backup / CanaryTrap99xx  (KONTO-PUŁAPKA – każde użycie = alert; nie używać w normalnej pracy)";
    console.log(line);
    accountLines.push(line);
  }

  db.prepare(
    `INSERT INTO articles (title, body, author_id)
     VALUES (?, ?, ?)`
  ).run(
    "Witamy w systemie",
    "To przykładowy artykuł. Redaktor może edytować treści, Czytelnik tylko czytać, Administrator zarządza użytkownikami.",
    adminId
  );

  writeAccountsFile(accountLines);
  console.log("\nSeed zakończony. Baza: data/app.sqlite");
  console.log("Hasła startowe są ważne 24 h od TERAZ (moment seeda).");
  console.log("Canary dokument: GET /api/security/canary/aws-credentials.txt");
}

seed().catch((err) => {
  console.error(err);
  process.exit(1);
});
