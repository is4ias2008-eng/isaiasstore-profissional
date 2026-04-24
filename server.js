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

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let storeOpen = true;
let users = [];
let products = [{ id: 1, name: "Produto exemplo Shopee", price: "29,90", image: "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?q=80&w=800", link: "https://shopee.com.br", category: "Promoções", offer: true, active: true, clicks: 0 }];

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

            app.post("/api/register", (req, res) => {
              const { username, password } = req.body;
                if (!username || !password) return res.status(400).json({ error: "Preencha usuário e senha" });
                  if (users.find(u => u.username === username)) return res.status(400).json({ error: "Usuário já existe" });
                    users.push({ id: Date.now(), username, password: bcrypt.hashSync(password, 10), role: "cliente" });
                      res.json({ ok: true });
                      });

                      app.post("/api/login", (req, res) => {
                        const { username, password } = req.body;
                          if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
                              const token = jwt.sign({ username: ADMIN_USER, role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
                                  return res.json({ token, role: "admin", username: ADMIN_USER });
                                    }
                                      const user = users.find(u => u.username === username);
                                        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Login inválido" });
                                          const token = jwt.sign({ username: user.username, role: "cliente" }, JWT_SECRET, { expiresIn: "7d" });
                                            res.json({ token, role: "cliente", username: user.username });
                                            });

                                            app.get("/api/products", (req, res) => res.json({ products: products.filter(p => p.active !== false), storeOpen }));

                                            app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
                                              const totalClicks = products.reduce((s,p) => s + (p.clicks || 0), 0);
                                                const best = [...products].sort((a,b) => (b.clicks||0)-(a.clicks||0))[0] || null;
                                                  res.json({ totalProducts: products.length, totalClicks, storeOpen, bestProduct: best ? { name: best.name, clicks: best.clicks || 0 } : null });
                                                  });

                                                  app.post("/api/products", auth, adminOnly, (req, res) => {
                                                    const { name, price, image, link, category, offer } = req.body;
                                                      if (!name || !price || !image || !link) return res.status(400).json({ error: "Preencha nome, preço, imagem e link" });
                                                        products.push({ id: Date.now(), name, price, image, link, category: category || "Promoções", offer: !!offer, active: true, clicks: 0 });
                                                          res.json({ ok: true });
                                                          });

                                                          app.delete("/api/products/:id", auth, adminOnly, (req, res) => {
                                                            products = products.filter(p => p.id !== Number(req.params.id));
                                                              res.json({ ok: true });
                                                              });

                                                              app.post("/api/admin/store-open", auth, adminOnly, (req, res) => {
                                                                storeOpen = !!req.body.open;
                                                                  res.json({ ok: true, storeOpen });
                                                                  });

                                                                  app.post("/api/products/:id/click", (req, res) => {
                                                                    const product = products.find(p => p.id === Number(req.params.id));
                                                                      if (!product) return res.status(404).json({ error: "Produto não encontrado" });
                                                                        product.clicks = (product.clicks || 0) + 1;
                                                                          res.json({ ok: true, link: product.link });
                                                                          });

                                                                          app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
                                                                          app.listen(PORT, () => console.log(`IsaiasStore rodando na porta ${PORT}`));
                                                                          