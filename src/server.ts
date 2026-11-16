import express from "express";
import session from "express-session";
import path from "node:path";
import { initSchema } from "./db";
import { touchSession } from "./middleware";
import { adminRouter } from "./routes/admin";
import { articlesRouter } from "./routes/articles";
import { authRouter } from "./routes/auth";

initSchema();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    name: "connect.sid",
    secret: process.env.SESSION_SECRET || "cyberb-dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

app.use(touchSession);

app.use("/api/auth", authRouter);
app.use("/api/admin", adminRouter);
app.use("/api/articles", articlesRouter);

app.use(express.static(path.join(process.cwd(), "public")));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    res.status(404).json({ error: "Nie znaleziono endpointu." });
    return;
  }
  if (req.method === "GET") {
    res.sendFile(path.join(process.cwd(), "public", "index.html"));
    return;
  }
  next();
});

app.listen(PORT, () => {
  console.log(`CyberB (wariant 1) działa na http://localhost:${PORT}`);
  console.log("Jeśli baza jest pusta, uruchom: npm run seed");
});
