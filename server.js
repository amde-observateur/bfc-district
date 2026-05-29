'use strict';
const express  = require('express');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const fs       = require('fs').promises;
const path     = require('path');
const cors     = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Secrets JWT ──────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'bfc-district-secret-2024';
const JWT_REFRESH = process.env.JWT_REFRESH || 'bfc-refresh-secret-2024';
const DATA_DIR    = process.env.DATA_DIR    || (process.env.RENDER ? '/tmp/data' : path.join(__dirname, 'data'));

// ════════════════════════════════════════════════════════
//  STOCKAGE JSON (fichiers dans /data)
// ════════════════════════════════════════════════════════
async function readDB(name, def = []) {
  try {
    const raw = await fs.readFile(path.join(DATA_DIR, name + '.json'), 'utf8');
    return JSON.parse(raw);
  } catch { return def; }
}
async function writeDB(name, data) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.writeFile(
    path.join(DATA_DIR, name + '.json'),
    JSON.stringify(data, null, 2)
  );
}

// ── MySQL optionnel ──────────────────────────────────────
let pool = null;
if (process.env.DB_HOST) {
  try {
    const mysql = require('mysql2/promise');
    pool = mysql.createPool({
      host:            process.env.DB_HOST,
      user:            process.env.DB_USER,
      password:        process.env.DB_PASS,
      database:        process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10
    });
    console.log('✅ MySQL connecté');
    // Créer les tables si besoin
    (async () => {
    const c = await pool.getConnection();
    await c.query(`CREATE TABLE IF NOT EXISTS reports (
      id BIGINT PRIMARY KEY, data JSON, createdAt DATETIME DEFAULT NOW()
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS users (
      id BIGINT PRIMARY KEY, data JSON
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS connlog (
      id INT AUTO_INCREMENT PRIMARY KEY, data JSON, createdAt DATETIME DEFAULT NOW()
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS drafts (
      userId BIGINT PRIMARY KEY, data JSON, updatedAt DATETIME DEFAULT NOW()
    )`);
    await c.query(`CREATE TABLE IF NOT EXISTS refresh_tokens (
      token VARCHAR(512) PRIMARY KEY, userId BIGINT, createdAt DATETIME DEFAULT NOW()
    )`);
    c.release();
    })();
  } catch(e) {
    console.warn('⚠️  MySQL indisponible, stockage JSON utilisé :', e.message);
    pool = null;
  }
}

// ── Helpers MySQL / JSON ──────────────────────────────────
async function getReports() {
  if (pool) {
    const [rows] = await pool.query('SELECT data FROM reports ORDER BY createdAt DESC');
    return rows.map(r => JSON.parse(r.data));
  }
  return readDB('reports', []);
}
async function upsertReport(rpt) {
  if (pool) {
    await pool.query(
      'INSERT INTO reports (id, data) VALUES (?,?) ON DUPLICATE KEY UPDATE data=?',
      [rpt.id, JSON.stringify(rpt), JSON.stringify(rpt)]
    );
    return;
  }
  const rpts = await readDB('reports', []);
  const i = rpts.findIndex(r => r.id === rpt.id);
  if (i >= 0) rpts[i] = rpt; else rpts.unshift(rpt);
  await writeDB('reports', rpts);
}
async function deleteReport(id) {
  if (pool) { await pool.query('DELETE FROM reports WHERE id=?', [id]); return; }
  const rpts = (await readDB('reports', [])).filter(r => r.id !== id);
  await writeDB('reports', rpts);
}

// Utilisateurs par défaut (hachés)
const DEF_USERS = [
  { id:1, username:'obs',   password: bcrypt.hashSync('89Sidi-Aich', 10), role:'obs',   nom:'Observateur',    email:'', actif:true },
  { id:2, username:'gest',  password: bcrypt.hashSync('13Sidi-Aich', 10), role:'gest',  nom:'Gestionnaire CDA',email:'', actif:true },
  { id:3, username:'admin', password: bcrypt.hashSync('75Sidi-Aich', 10), role:'admin', nom:'Administrateur',  email:'', actif:true }
];
async function getUsers() {
  if (pool) {
    const [rows] = await pool.query('SELECT data FROM users');
    if (!rows.length) return DEF_USERS;
    return rows.map(r => JSON.parse(r.data));
  }
  return readDB('users', DEF_USERS);
}
async function saveUser(u) {
  if (pool) {
    await pool.query(
      'INSERT INTO users (id, data) VALUES (?,?) ON DUPLICATE KEY UPDATE data=?',
      [u.id, JSON.stringify(u), JSON.stringify(u)]
    );
    return;
  }
  const users = await getUsers();
  const i = users.findIndex(x => x.id === u.id);
  if (i >= 0) users[i] = u; else users.push(u);
  await writeDB('users', users);
}

// ════════════════════════════════════════════════════════
//  MIDDLEWARE AUTH
// ════════════════════════════════════════════════════════
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer '))
    return res.status(401).json({ error:{ message:'Non authentifié' }});
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error:{ message:'Token invalide ou expiré' }});
  }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ error:{ message:"Accès réservé à l'administrateur" }});
  next();
}

// ════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════
app.get('/api/auth/session', auth, (req, res) => {
  res.json({ ok:true, user: req.user });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = await getUsers();
    const user  = users.find(u => u.username === username && u.actif !== false);
    if (!user) return res.status(401).json({ error:{ message:'Identifiant ou mot de passe incorrect.' }});

    // Supporte mot de passe haché (bcrypt) ET texte brut (migration)
    const ok = user.password
      ? await bcrypt.compare(password, user.password).catch(()=>false) || user.pass === password
      : user.pass === password;
    if (!ok) return res.status(401).json({ error:{ message:'Identifiant ou mot de passe incorrect.' }});

    const accessToken  = jwt.sign(
      { id:user.id, username:user.username, role:user.role, nom:user.nom },
      JWT_SECRET, { expiresIn:'8h' }
    );
    const refreshToken = jwt.sign({ id:user.id }, JWT_REFRESH, { expiresIn:'30d' });

    // Sauvegarder refresh token
    if (pool) {
      await pool.query(
        'INSERT INTO refresh_tokens (token, userId) VALUES (?,?) ON DUPLICATE KEY UPDATE userId=userId',
        [refreshToken, user.id]
      );
    } else {
      const tokens = await readDB('refresh_tokens', []);
      tokens.push({ token: refreshToken, userId: user.id, createdAt: new Date().toISOString() });
      if (tokens.length > 200) tokens.splice(0, tokens.length - 200);
      await writeDB('refresh_tokens', tokens);
    }

    // Journal connexions
    const log = await readDB('connlog', []);
    log.unshift({ nom:user.nom, role:user.role, action:'Connexion', timestamp:new Date().toISOString() });
    if (log.length > 200) log.splice(200);
    await writeDB('connlog', log);

    res.json({ data:{ accessToken, refreshToken, role:user.role, nom:user.nom, id:user.id }});
  } catch(e) {
    console.error(e);
    res.status(500).json({ error:{ message:'Erreur serveur' }});
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error:{ message:'Token manquant' }});
  try {
    const payload = jwt.verify(refreshToken, JWT_REFRESH);
    let valid = false;
    if (pool) {
      const [rows] = await pool.query('SELECT 1 FROM refresh_tokens WHERE token=?', [refreshToken]);
      valid = rows.length > 0;
    } else {
      const tokens = await readDB('refresh_tokens', []);
      valid = tokens.some(t => t.token === refreshToken);
    }
    if (!valid) return res.status(401).json({ error:{ message:'Token révoqué' }});
    const users = await getUsers();
    const user  = users.find(u => u.id === payload.id && u.actif !== false);
    if (!user) return res.status(401).json({ error:{ message:'Utilisateur introuvable' }});
    const accessToken = jwt.sign(
      { id:user.id, username:user.username, role:user.role, nom:user.nom },
      JWT_SECRET, { expiresIn:'8h' }
    );
    res.json({ data:{ accessToken }});
  } catch {
    res.status(401).json({ error:{ message:'Refresh token invalide' }});
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    if (pool) {
      await pool.query('DELETE FROM refresh_tokens WHERE token=?', [refreshToken]).catch(()=>{});
    } else {
      const tokens = await readDB('refresh_tokens', []);
      await writeDB('refresh_tokens', tokens.filter(t => t.token !== refreshToken));
    }
  }
  res.json({ ok:true });
});

// ════════════════════════════════════════════════════════
//  RAPPORTS
// ════════════════════════════════════════════════════════
app.get('/api/reports', auth, async (req, res) => {
  try {
    const all = await getReports();
    const filtered = req.user.role === 'admin'
      ? all
      : all.filter(r => r.auteurId === req.user.id);
    res.json({ data: filtered });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.post('/api/reports', auth, async (req, res) => {
  try {
    const rpt = {
      ...req.body,
      id:        Date.now(),
      auteurId:  req.user.id,
      auteurNom: req.user.nom,
      createdAt: new Date().toISOString()
    };
    await upsertReport(rpt);
    res.json({ data: rpt });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.put('/api/reports/:id', auth, async (req, res) => {
  try {
    const id   = parseInt(req.params.id);
    const all  = await getReports();
    const orig = all.find(r => r.id === id);
    if (!orig) return res.status(404).json({ error:{ message:'Rapport introuvable' }});
    if (req.user.role !== 'admin' && orig.auteurId !== req.user.id)
      return res.status(403).json({ error:{ message:'Accès refusé' }});
    const updated = { ...orig, ...req.body, id };
    await upsertReport(updated);
    res.json({ data: updated });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.delete('/api/reports/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin')
      return res.status(403).json({ error:{ message:'Accès refusé' }});
    await deleteReport(parseInt(req.params.id));
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

// ════════════════════════════════════════════════════════
//  UTILISATEURS (admin)
// ════════════════════════════════════════════════════════
app.get('/api/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await getUsers();
    res.json({ data: users.map(u => ({ ...u, password:undefined, pass:undefined })) });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await getUsers();
    const { username, nom, role, email, pass } = req.body;
    if (users.find(u => u.username === username))
      return res.status(400).json({ error:{ message:'Identifiant déjà utilisé.' }});
    const newUser = {
      id:       Date.now(),
      username, nom, role, email,
      password: await bcrypt.hash(pass, 10),
      actif:    true
    };
    await saveUser(newUser);
    res.json({ data:{ ...newUser, password:undefined }});
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const id    = parseInt(req.params.id);
    const users = await getUsers();
    const u     = users.find(x => x.id === id);
    if (!u) return res.status(404).json({ error:{ message:'Utilisateur introuvable' }});
    const { nom, role, email, pass, actif } = req.body;
    if (nom)   u.nom   = nom;
    if (role)  u.role  = role;
    if (email !== undefined) u.email = email;
    if (actif !== undefined) u.actif = actif;
    if (pass)  u.password = await bcrypt.hash(pass, 10);
    await saveUser(u);
    res.json({ data:{ ...u, password:undefined }});
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

// ════════════════════════════════════════════════════════
//  JOURNAL CONNEXIONS (admin)
// ════════════════════════════════════════════════════════
app.get('/api/connlog', auth, adminOnly, async (req, res) => {
  try {
    const log = await readDB('connlog', []);
    res.json({ data: log.slice(0, 50) });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

// ════════════════════════════════════════════════════════
//  BROUILLONS (par utilisateur)
// ════════════════════════════════════════════════════════
app.get('/api/draft', auth, async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query('SELECT data FROM drafts WHERE userId=?', [req.user.id]);
      return res.json({ data: rows.length ? JSON.parse(rows[0].data) : null });
    }
    const drafts = await readDB('drafts', {});
    res.json({ data: drafts[req.user.id] || null });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.post('/api/draft', auth, async (req, res) => {
  try {
    if (pool) {
      await pool.query(
        'INSERT INTO drafts (userId, data) VALUES (?,?) ON DUPLICATE KEY UPDATE data=?, updatedAt=NOW()',
        [req.user.id, JSON.stringify(req.body), JSON.stringify(req.body)]
      );
      return res.json({ ok:true });
    }
    const drafts = await readDB('drafts', {});
    drafts[req.user.id] = { ...req.body, updatedAt: new Date().toISOString() };
    await writeDB('drafts', drafts);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.delete('/api/draft', auth, async (req, res) => {
  try {
    if (pool) {
      await pool.query('DELETE FROM drafts WHERE userId=?', [req.user.id]);
      return res.json({ ok:true });
    }
    const drafts = await readDB('drafts', {});
    delete drafts[req.user.id];
    await writeDB('drafts', drafts);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

// ── Démarrage ────────────────────────────────────────────
app.listen(PORT, () =>
  console.log(`✅ Serveur BFC démarré sur le port ${PORT}`)
);

// ════════════════════════════════════════════════════════
//  ARBITRES — Liste avec licence, nom, prénom, email
// ════════════════════════════════════════════════════════
app.get('/api/arbitres', auth, async (req, res) => {
  try {
    const arbitres = await readDB('arbitres', []);
    res.json({ data: arbitres });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.post('/api/arbitres', auth, adminOnly, async (req, res) => {
  try {
    const arbitres = await readDB('arbitres', []);
    const { licence, nom, prenom, email, categorie, telephone } = req.body;
    if (!nom || !prenom) return res.status(400).json({ error:{ message:'Nom et prénom obligatoires.' }});
    if (arbitres.find(a => a.licence && a.licence === licence))
      return res.status(400).json({ error:{ message:'Numéro de licence déjà utilisé.' }});
    const arb = { id: Date.now(), licence: licence||'', nom, prenom, email: email||'', categorie: categorie||'', telephone: telephone||'', actif: true, createdAt: new Date().toISOString() };
    arbitres.push(arb);
    await writeDB('arbitres', arbitres);
    res.json({ data: arb });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.put('/api/arbitres/:id', auth, adminOnly, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const arbitres = await readDB('arbitres', []);
    const idx = arbitres.findIndex(a => a.id === id);
    if (idx < 0) return res.status(404).json({ error:{ message:'Arbitre introuvable' }});
    arbitres[idx] = { ...arbitres[idx], ...req.body, id };
    await writeDB('arbitres', arbitres);
    res.json({ data: arbitres[idx] });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});

app.delete('/api/arbitres/:id', auth, adminOnly, async (req, res) => {
  try {
    let arbitres = await readDB('arbitres', []);
    arbitres = arbitres.filter(a => a.id !== parseInt(req.params.id));
    await writeDB('arbitres', arbitres);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error:{ message:'Erreur serveur' }}); }
});


app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log("Serveur BFC démarré sur le port " + PORT);
});
