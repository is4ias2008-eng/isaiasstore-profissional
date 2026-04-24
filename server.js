const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("isaiasstore.db");
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "troque_essa_senha_secreta";

// TROQUE SEU ADMIN AQUI
const ADMIN_USER = process.env.ADMIN_USER || "isaias_admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "troque123";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'cliente'
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  price TEXT,
  image TEXT,
  link TEXT,
  category TEXT,
  offer INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1,
  clicks INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

function init() {
  const admin = db.prepare("SELECT * FROM users WHERE username = ?").get(ADMIN_USER);
  if (!admin) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')").run(ADMIN_USER, hash);
  }

  const open = db.prepare("SELECT * FROM settings WHERE key = 'storeOpen'").get();
  if (!open) db.prepare("INSERT INTO settings (key, value) VALUES ('storeOpen', 'true')").run();

  const count = db.prepare("SELECT COUNT(*) as total FROM products").get().total;
  if (count === 0) {
    db.prepare(`INSERT INTO products (name, price, image, link, category, offer, active)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
      "Produto exemplo Shopee",
      "29,90",
      "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?q=80&w=800",
      "https://shopee.com.br",
      "Promoções",
      1,
      1
    );
  }
}
init();

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Sem token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Acesso negado" });
  next();
}

app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Preencha tudo" });

  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'cliente')").run(username, hash);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Usuário já existe" });
  }
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: "Login inválido" });
  }

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, role: user.role, username: user.username });
});

app.get("/api/products", (req, res) => {
  const products = db.prepare("SELECT * FROM products WHERE active = 1 ORDER BY offer DESC, id DESC").all();
  const storeOpen = db.prepare("SELECT value FROM settings WHERE key = 'storeOpen'").get().value === "true";
  res.json({ products, storeOpen });
});

app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
  const totalProducts = db.prepare("SELECT COUNT(*) as total FROM products").get().total;
  const totalClicks = db.prepare("SELECT COALESCE(SUM(clicks),0) as total FROM products").get().total;
  const products = db.prepare("SELECT id, name, clicks FROM products ORDER BY clicks DESC").all();
  res.json({ totalProducts, totalClicks, products });
});

app.post("/api/products", auth, adminOnly, (req, res) => {
  const { name, price, image, link, category, offer } = req.body;
  db.prepare(`INSERT INTO products (name, price, image, link, category, offer, active)
    VALUES (?, ?, ?, ?, ?, ?, 1)`).run(name, price, image, link, category, offer ? 1 : 0);
  res.json({ ok: true });
});

app.put("/api/products/:id", auth, adminOnly, (req, res) => {
  const { name, price, image, link, category, offer, active } = req.body;
  db.prepare(`UPDATE products SET name=?, price=?, image=?, link=?, category=?, offer=?, active=? WHERE id=?`)
    .run(name, price, image, link, category, offer ? 1 : 0, active ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

app.delete("/api/products/:id", auth, adminOnly, (req, res) => {
  db.prepare("DELETE FROM products WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/products/:id/click", (req, res) => {
  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(req.params.id);
  if (!product) return res.status(404).json({ error: "Produto não encontrado" });

  db.prepare("UPDATE products SET clicks = clicks + 1 WHERE id = ?").run(req.params.id);
  res.json({ link: product.link });
});

app.post("/api/admin/store-open", auth, adminOnly, (req, res) => {
  db.prepare("UPDATE settings SET value = ? WHERE key = 'storeOpen'").run(req.body.open ? "true" : "false");
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`IsaiasStore rodando na porta ${PORT}`));
