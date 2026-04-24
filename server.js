const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER || "isaias_admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "troque123";
const JWT_SECRET = process.env.JWT_SECRET || "segredo_padrao_troque";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "660996534145-e2q8aq49f9ch1ll9i2u3chijkqplgb5g.apps.googleusercontent.com";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let storeOpen = true;
let users = [];
let loginAttempts = {};

let products = [
  { id: 1, name: "Produto em promoção Shopee", price: "29,90", image: "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?q=80&w=800", link: "https://shopee.com.br", category: "Promoções", offer: true, active: true, clicks: 0 },
    { id: 2, name: "Produto eletrônico exemplo", price: "59,90", image: "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?q=80&w=800", link: "https://shopee.com.br", category: "Eletrônicos", offer: false, active: true, clicks: 0 }
    ];

    function getClientIp(req) { return req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown"; }
    function loginBlocked(req) {
      const ip = getClientIp(req);
        const now = Date.now();
          const data = loginAttempts[ip];
            if (!data) return false;
              if (now > data.blockedUntil) { delete loginAttempts[ip]; return false; }
                return data.count >= 5;
                }
                function registerFailedLogin(req) {
                  const ip = getClientIp(req);
                    const now = Date.now();
                      if (!loginAttempts[ip]) { loginAttempts[ip] = { count: 1, blockedUntil: now + 10 * 60 * 1000 }; return; }
                        loginAttempts[ip].count += 1;
                          if (loginAttempts[ip].count >= 5) loginAttempts[ip].blockedUntil = now + 10 * 60 * 1000;
                          }
                          function clearFailedLogin(req) { delete loginAttempts[getClientIp(req)]; }
                          function auth(req, res, next) {
                            const token = (req.headers.authorization || "").replace("Bearer ", "");
                              if (!token) return res.status(401).json({ error: "Sem token" });
                                try { req.user = jwt.verify(token, JWT_SECRET); next(); }
                                  catch { return res.status(401).json({ error: "Token inválido" }); }
                                  }
                                  function adminOnly(req, res, next) {
                                    if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "Acesso negado" });
                                      next();
                                      }
                                      async function verifyGoogleToken(credential) {
                                        const response = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + credential);
                                          if (!response.ok) return null;
                                            const data = await response.json();
                                              if (data.aud !== GOOGLE_CLIENT_ID) return null;
                                                if (!data.email_verified) return null;
                                                  return data;
                                                  }
                                                  app.post("/api/google-login", async (req, res) => {
                                                    try {
                                                        const { credential } = req.body;
                                                            if (!credential) return res.status(400).json({ error: "Login Google inválido" });
                                                                const googleUser = await verifyGoogleToken(credential);
                                                                    if (!googleUser) return res.status(401).json({ error: "Não foi possível confirmar sua conta Google" });
                                                                        let user = users.find(u => u.provider === "google" && u.email === googleUser.email);
                                                                            if (!user) {
                                                                                  user = { id: Date.now(), name: googleUser.name || googleUser.email, username: googleUser.email, email: googleUser.email, picture: googleUser.picture || "", password: "", role: "cliente", provider: "google" };
                                                                                        users.push(user);
                                                                                            }
                                                                                                const token = jwt.sign({ username: user.username, name: user.name, role: "cliente" }, JWT_SECRET, { expiresIn: "7d" });
                                                                                                    res.json({ token, role: "cliente", username: user.username, name: user.name });
                                                                                                      } catch { res.status(500).json({ error: "Erro ao entrar com Google" }); }
                                                                                                      });
                                                                                                      app.post("/api/register", (req, res) => {
                                                                                                        const { name, username, password, confirmPassword } = req.body;
                                                                                                          if (!name || !username || !password || !confirmPassword) return res.status(400).json({ error: "Preencha nome, usuário, senha e confirmação" });
                                                                                                            if (password !== confirmPassword) return res.status(400).json({ error: "As senhas não conferem" });
                                                                                                              if (password.length < 6) return res.status(400).json({ error: "A senha precisa ter pelo menos 6 caracteres" });
                                                                                                                if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: "Usuário já existe" });
                                                                                                                  users.push({ id: Date.now(), name, username, password: bcrypt.hashSync(password, 10), role: "cliente", provider: "local" });
                                                                                                                    res.json({ ok: true });
                                                                                                                    });
                                                                                                                    app.post("/api/login", (req, res) => {
                                                                                                                      const { username, password } = req.body;
                                                                                                                        if (loginBlocked(req)) return res.status(429).json({ error: "Muitas tentativas. Aguarde alguns minutos e tente novamente." });
                                                                                                                          if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
                                                                                                                              clearFailedLogin(req);
                                                                                                                                  const token = jwt.sign({ username: ADMIN_USER, name: "Admin", role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
                                                                                                                                      return res.json({ token, role: "admin", username: ADMIN_USER, name: "Admin" });
                                                                                                                                        }
                                                                                                                                          const user = users.find(u => u.username.toLowerCase() === String(username || "").toLowerCase());
                                                                                                                                            if (!user || user.provider === "google" || !bcrypt.compareSync(password, user.password)) { registerFailedLogin(req); return res.status(401).json({ error: "Login inválido" }); }
                                                                                                                                              clearFailedLogin(req);
                                                                                                                                                const token = jwt.sign({ username: user.username, name: user.name, role: "cliente" }, JWT_SECRET, { expiresIn: "7d" });
                                                                                                                                                  res.json({ token, role: "cliente", username: user.username, name: user.name });
                                                                                                                                                  });
                                                                                                                                                  app.post("/api/forgot-password", (req, res) => {
                                                                                                                                                    return res.json({ ok: true, message: "Se essa conta existir, enviaremos instruções de recuperação." });
                                                                                                                                                    });
                                                                                                                                                    app.get("/api/products", (req, res) => res.json({ products: products.filter(p => p.active !== false), storeOpen }));
                                                                                                                                                    app.get("/api/public-offers", (req, res) => res.json({ products: products.filter(p => p.active !== false && p.offer === true), storeOpen }));
                                                                                                                                                    app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
                                                                                                                                                      const totalClicks = products.reduce((s, p) => s + (p.clicks || 0), 0);
                                                                                                                                                        const best = [...products].sort((a, b) => (b.clicks || 0) - (a.clicks || 0))[0] || null;
                                                                                                                                                          res.json({ totalProducts: products.length, totalClicks, storeOpen, totalUsers: users.length, bestProduct: best ? { name: best.name, clicks: best.clicks || 0 } : null });
                                                                                                                                                          });
                                                                                                                                                          app.post("/api/products", auth, adminOnly, (req, res) => {
                                                                                                                                                            const { name, price, image, link, category, offer } = req.body;
                                                                                                                                                              if (!name || !price || !image || !link) return res.status(400).json({ error: "Preencha nome, preço, imagem e link" });
                                                                                                                                                                products.push({ id: Date.now(), name, price, image, link, category: category || "Promoções", offer: !!offer, active: true, clicks: 0 });
                                                                                                                                                                  res.json({ ok: true });
                                                                                                                                                                  });
                                                                                                                                                                  app.delete("/api/products/:id", auth, adminOnly, (req, res) => { products = products.filter(p => p.id !== Number(req.params.id)); res.json({ ok: true }); });
                                                                                                                                                                  app.post("/api/admin/store-open", auth, adminOnly, (req, res) => { storeOpen = !!req.body.open; res.json({ ok: true, storeOpen }); });
                                                                                                                                                                  app.post("/api/products/:id/click", (req, res) => {
                                                                                                                                                                    const product = products.find(p => p.id === Number(req.params.id));
                                                                                                                                                                      if (!product) return res.status(404).json({ error: "Produto não encontrado" });
                                                                                                                                                                        product.clicks = (product.clicks || 0) + 1;
                                                                                                                                                                          res.json({ ok: true, link: product.link });
                                                                                                                                                                          });
                                                                                                                                                                          app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
                                                                                                                                                                          app.listen(PORT, () => console.log(`IsaiasStore rodando na porta ${PORT}`));
                                                                                                                                                                          