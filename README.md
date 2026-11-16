# CyberB – Moduł 1 (wariant 1)

Aplikacja webowa: identyfikacja, uwierzytelnianie i autoryzacja (RBAC) + TOTP (2FA).

## Stack

- Node.js + TypeScript + Express
- SQLite (`data/app.sqlite`)
- Argon2id (hash haseł)
- Sesje cookie (`express-session`)
- TOTP (`otpauth`)

## Uruchomienie:

```bash
npm install
npm run seed -- --reset
npm start
```

Otwórz: http://localhost:3000

Hasła startowe są w pliku **`ACCOUNTS.txt`** (oraz w konsoli po seedzie).  
Są ważne **24 h od momentu uruchomienia `npm run seed`** —  używaj `--reset` przed sprawdzeniem.

Po zalogowaniu system wymusi zmianę hasła.

## Konta demo (po `seed --reset`)

| Login | Hasło startowe | Rola |


| ADMIN | AdminStartPass15! | Administrator |
| redaktor1 | RedaktorDemo1 | Redaktor |
| redaktor2 | RedaktorDemo2 | Redaktor |
| czytelnik1 | CzytelnikDm1 | Czytelnik |
| czytelnik2 | CzytelnikDm2 | Czytelnik |
| czytelnik3 | CzytelnikDm3 | Czytelnik |

## Wariant 1

- Min. długość hasła: 15
- Extra polityka (włączana przez admina): brak 3+ identycznych znaków z rzędu
- Role: Administrator, Redaktor, Czytelnik
- OTP: 12 znaków alfanumerycznych, ważne 24 h
- 5 użytkowników testowych + stałe konto `ADMIN`
- Zadanie dodatkowe: TOTP (2FA) w zakładce Hasło

## Skrypty

- `npm start` – serwer
- `npm run dev` – serwer z auto-reload
- `npm run seed` – inicjalizacja (gdy baza pusta)
- `npm run seed -- --reset` – kasuje użytkowników i tworzy konta demo od nowa
