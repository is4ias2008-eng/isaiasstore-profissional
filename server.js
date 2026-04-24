const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER || "isaias_admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "troque123";
const JWT_SECRET = process.env.JWT_SECRET || "troque_esse_segredo";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "660996534145-e2q8aq49f9ch1ll9i2u3chijkqplgb5g.apps.googleusercontent.com";
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("ERRO: MONGO_URI não configurado no Render.");
  process.exit(1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Aguarde alguns minutos e tente novamente." }
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas requisições. Tente novamente em instantes." }
});

app.use("/api", generalLimiter);

mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado com sucesso"))
  .catch((err) => {
    console.error("Erro ao conectar MongoDB:", err.message);
    process.exit(1);
  });

const UserSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true, sparse: true },
  email: { type: String, unique: true, sparse: true },
  password: String,
  role: { type: String, default: "cliente" },
  provider: { type: String, default: "local" },
  picture: String,
  createdAt: { type: Date, default: Date.now }
});

const ProductSchema = new mongoose.Schema({
  name: String,
  price: String,
  image: String,
  link: String,
  category: String,
  offer: { type: Boolean, default: false },
  active: { type: Boolean, default: true },
  clicks: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const SettingSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed
});

const User = mongoose.model("User", UserSchema);
const Product = mongoose.model("Product", ProductSchema);
const Setting = mongoose.model("Setting", SettingSchema);

async function initData() {
  const store = await Setting.findOne({ key: "storeOpen" });
  if (!store) await Setting.create({ key: "storeOpen", value: true });

  const count = await Product.countDocuments();
  if (count === 0) {
    await Product.create([
      {
        name: "Produto em promoção Shopee",
        price: "29,90",
        image: "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?q=80&w=800",
        link: "https://shopee.com.br",
        category: "Promoções",
        offer: true,
        active: true
      },
      {
        name: "Produto eletrônico exemplo",
        price: "59,90",
        image: "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?q=80&w=800",
        link: "https://shopee.com.br",
        category: "Eletrônicos",
        offer: false,
        active: true
      }
    ]);
  }
}
initData();

function sanitize(text) {
  if (typeof text !== "string") return "";
  return text.trim().slice(0, 500);
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Sem autorização" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Sessão inválida. Entre novamente." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "Acesso negado" });
  next();
}

async function getStoreOpen() {
  const setting = await Setting.findOne({ key: "storeOpen" });
  return setting ? !!setting.value : true;
}

async function verifyGoogleToken(credential) {
  const response = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + credential);
  if (!response.ok) return null;

  const data = await response.json();
  if (data.aud !== GOOGLE_CLIENT_ID) return null;
  if (!data.email_verified) return null;

  return data;
}

app.post("/api/google-login", loginLimiter, async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Login Google inválido" });

    const googleUser = await verifyGoogleToken(credential);
    if (!googleUser) return res.status(401).json({ error: "Não foi possível confirmar sua conta Google" });

    let user = await User.findOne({ provider: "google", email: googleUser.email });

    if (!user) {
      user = await User.create({
        name: googleUser.name || googleUser.email,
        username: googleUser.email,
        email: googleUser.email,
        picture: googleUser.picture || "",
        password: "",
        role: "cliente",
        provider: "google"
      });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({ token, role: user.role, username: user.username, name: user.name });
  } catch {
    return res.status(500).json({ error: "Erro ao entrar com Google" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const name = sanitize(req.body.name);
    const username = sanitize(req.body.username).toLowerCase();
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!name || !username || !password || !confirmPassword) return res.status(400).json({ error: "Preencha nome, usuário, senha e confirmação" });
    if (password !== confirmPassword) return res.status(400).json({ error: "As senhas não conferem" });
    if (password.length < 6) return res.status(400).json({ error: "A senha precisa ter pelo menos 6 caracteres" });

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: "Usuário já existe" });

    const hash = await bcrypt.hash(password, 12);

    await User.create({ name, username, password: hash, role: "cliente", provider: "local" });

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: "Erro ao criar conta" });
  }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = sanitize(req.body.username).toLowerCase();
    const password = String(req.body.password || "");

    if (username === ADMIN_USER.toLowerCase() && password === ADMIN_PASSWORD) {
      const token = jwt.sign({ username: ADMIN_USER, name: "Admin", role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
      return res.json({ token, role: "admin", username: ADMIN_USER, name: "Admin" });
    }

    const user = await User.findOne({ username });
    if (!user || user.provider === "google") return res.status(401).json({ error: "Login inválido" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Login inválido" });

    const token = jwt.sign({ id: user._id, username: user.username, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: "7d" });

    return res.json({ token, role: user.role, username: user.username, name: user.name });
  } catch {
    return res.status(500).json({ error: "Erro ao entrar" });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  return res.json({ ok: true, message: "Se essa conta existir, enviaremos instruções de recuperação." });
});

app.get("/api/products", async (req, res) => {
  const storeOpen = await getStoreOpen();
  const products = await Product.find({ active: true }).sort({ offer: -1, createdAt: -1 });
  return res.json({ products, storeOpen });
});

app.get("/api/public-offers", async (req, res) => {
  const storeOpen = await getStoreOpen();
  const products = await Product.find({ active: true, offer: true }).sort({ createdAt: -1 });
  return res.json({ products, storeOpen });
});

app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  const storeOpen = await getStoreOpen();
  const totalProducts = await Product.countDocuments();
  const totalUsers = await User.countDocuments();

  const products = await Product.find();
  const totalClicks = products.reduce((s, p) => s + (p.clicks || 0), 0);
  const best = [...products].sort((a, b) => (b.clicks || 0) - (a.clicks || 0))[0] || null;

  return res.json({
    totalProducts,
    totalClicks,
    totalUsers,
    storeOpen,
    bestProduct: best ? { name: best.name, clicks: best.clicks || 0 } : null
  });
});

app.post("/api/products", auth, adminOnly, async (req, res) => {
  try {
    const name = sanitize(req.body.name);
    const price = sanitize(req.body.price);
    const image = sanitize(req.body.image);
    const link = sanitize(req.body.link);
    const category = sanitize(req.body.category) || "Promoções";
    const offer = !!req.body.offer;

    if (!name || !price || !image || !link) return res.status(400).json({ error: "Preencha nome, preço, imagem e link" });

    await Product.create({ name, price, image, link, category, offer, active: true, clicks: 0 });

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: "Erro ao adicionar produto" });
  }
});

app.delete("/api/products/:id", auth, adminOnly, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  return res.json({ ok: true });
});

app.post("/api/admin/store-open", auth, adminOnly, async (req, res) => {
  const open = !!req.body.open;
  await Setting.findOneAndUpdate({ key: "storeOpen" }, { value: open }, { upsert: true });
  return res.json({ ok: true, storeOpen: open });
});

app.post("/api/products/:id/click", async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ error: "Produto não encontrado" });

  product.clicks = (product.clicks || 0) + 1;
  await product.save();

  return res.json({ ok: true, link: product.link });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`IsaiasStore com MongoDB rodando na porta ${PORT}`));
