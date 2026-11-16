import { Router } from "express";
import { db } from "../db";
import {
  blockIfMustChangePassword,
  requireAuth,
  requirePermission,
} from "../middleware";

export const articlesRouter = Router();

articlesRouter.use(requireAuth, blockIfMustChangePassword);

articlesRouter.get("/", requirePermission("articles.read"), (_req, res) => {
  const articles = db
    .prepare(
      `SELECT a.id, a.title, a.body, a.created_at, a.updated_at,
              u.login AS author
       FROM articles a
       JOIN users u ON u.id = a.author_id
       ORDER BY a.id DESC`
    )
    .all();
  res.json(articles);
});

articlesRouter.post("/", requirePermission("articles.write"), (req, res) => {
  const title = String(req.body?.title ?? "").trim();
  const body = String(req.body?.body ?? "").trim();

  if (!title || !body) {
    res.status(400).json({ error: "Tytuł i treść są wymagane." });
    return;
  }

  const result = db
    .prepare("INSERT INTO articles (title, body, author_id) VALUES (?, ?, ?)")
    .run(title, body, req.session.userId);

  res.status(201).json({ id: result.lastInsertRowid });
});

articlesRouter.put("/:id", requirePermission("articles.write"), (req, res) => {
  const id = Number(req.params.id);
  const title = String(req.body?.title ?? "").trim();
  const body = String(req.body?.body ?? "").trim();

  const existing = db.prepare("SELECT id FROM articles WHERE id = ?").get(id);
  if (!existing) {
    res.status(404).json({ error: "Nie znaleziono artykułu." });
    return;
  }

  if (!title || !body) {
    res.status(400).json({ error: "Tytuł i treść są wymagane." });
    return;
  }

  db.prepare(
    `UPDATE articles
     SET title = ?, body = ?, updated_at = datetime('now')
     WHERE id = ?`
  ).run(title, body, id);

  res.json({ ok: true });
});

articlesRouter.delete("/:id", requirePermission("articles.write"), (req, res) => {
  const id = Number(req.params.id);
  const result = db.prepare("DELETE FROM articles WHERE id = ?").run(id);
  if (result.changes === 0) {
    res.status(404).json({ error: "Nie znaleziono artykułu." });
    return;
  }
  res.json({ ok: true });
});
