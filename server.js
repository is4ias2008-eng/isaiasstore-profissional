const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let storeOpen = true;
let users = [];

let products = [
  {
    id: 1,
    name: "Produto exemplo Shopee",
    price: "29,90",
    image: "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?q=80&w=800",
    link: "https://shopee.com.br",
    category: "Promoções",
    offer: true,
    active: true,
    clicks: 0
  }
];

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Sem token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: "admin" }, JWT_SECRET);
    return res.json({ token, role: "admin" });
  }

  return res.status(401).json({ error: "Login inválido" });
});

app.get("/api/products", (req, res) => {
  res.json({ products, storeOpen });
});

app.post("/api/products", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const newProduct = {
    ...req.body,
    id: Date.now(),
    clicks: 0,
    active: true
  };

  products.push(newProduct);
  res.json({ ok: true });
});

app.post("/api/products/:id/click", (req, res) => {
  const product = products.find(p => p.id == req.params.id);
  if (!product) return res.status(404).json({ error: "Não encontrado" });

  product.clicks++;
  res.json({ link: product.link });
});

app.listen(PORT, () => console.log("Servidor rodando 🚀"));