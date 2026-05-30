'use strict';
require('dotenv').config();

const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const sqlite3    = require('sqlite3').verbose();
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const fs         = require('fs');

// ═══════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════
const PORT               = process.env.PORT               || 3000;
const JWT_SECRET         = process.env.JWT_SECRET         || 'dev-secret-change-in-prod-AAAA';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-change-in-prod-BBBB';
const ANTHROPIC_API_KEY  = process.env.ANTHROPIC_API_KEY  || '';
const DB_PATH            = process.env.DB_PATH            || path.join(__dirname, 'data', 'bfc.db');

// ═══════════════════════════════════════
//  BASE DE DONNÉES SQLite
// ═══════════════════════════════════════
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new sqlite3.Database(DB_PATH, err => {
  if (err) { console.error('DB error:', err); process.exit(1); }
  console.log('✅ DB connectée:', DB_PATH);
});

// Helpers promisifiés
const dbRun = (sql, p = []) => new Promise((res, rej) =>
  db.run(sql, p, function(err) { err ? rej(err) : res(this); }));
const dbGet = (sql, p = []) => new Promise((res, rej) =>
  db.get(sql, p, (err, row) => err ? rej(err) : res(row)));
const dbAll = (sql, p = []) => new Promise((res, rej) =>
  db.all(sql, p, (err, rows) => err ? rej(err) : res(rows)));

// Init tables
db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'obs',
    nom TEXT DEFAULT '',
    email TEXT DEFAULT '',
    actif INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ext_id TEXT UNIQUE NOT NULL,
    arbitre TEXT DEFAULT '',
    arb_email TEXT DEFAULT '',
    obs_nom TEXT DEFAULT '',
    categorie TEXT DEFAULT '',
    competition TEXT DEFAULT '',
    equipes TEXT DEFAULT '',
    date_match TEXT DEFAULT '',
    score TEXT DEFAULT '0-0',
    note_20 REAL DEFAULT 0,
    note_100 INTEGER DEFAULT 0,
    statut TEXT DEFAULT '🟡 En attente de validation',
    data_json TEXT DEFAULT '{}',
    auteur_id INTEGER DEFAULT 0,
    auteur_nom TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS conn_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER DEFAULT 0,
    username TEXT DEFAULT '',
    role TEXT DEFAULT '',
    action TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    timestamp TEXT DEFAULT (datetime('now'))
  )`);

  // Seed comptes par défaut
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (!err && row && row.c === 0) {
      const ins = db.prepare('INSERT INTO users (username, password, role, nom) VALUES (?, ?, ?, ?)');
      const defaults = [
        { u: 'obs',   p: '89Sidi-Aich', r: 'obs',   n: 'Observateur' },
        { u: 'gest',  p: '13Sidi-Aich', r: 'gest',  n: 'Gestionnaire CDA' },
        { u: 'admin', p: '75Sidi-Aich', r: 'admin', n: 'Administrateur' }
      ];
      defaults.forEach(d => ins.run(d.u, bcrypt.hashSync(d.p, 12), d.r, d.n));
      ins.finalize();
      console.log('✅ Comptes par défaut créés');
    }
  });
});

// Nettoyage tokens expirés
setInterval(() => {
  db.run("DELETE FROM refresh_tokens WHERE expires_at < datetime('now')");
}, 3600000);

// ═══════════════════════════════════════
//  APP EXPRESS
// ═══════════════════════════════════════
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════
//  HELPERS AUTH
// ═══════════════════════════════════════
const signAccess  = u => jwt.sign({ id: u.id, username: u.username, role: u.role, nom: u.nom }, JWT_SECRET, { expiresIn: '2h' });
const signRefresh = u => jwt.sign({ id: u.id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

async function issueTokens(user) {
  const access  = signAccess(user);
  const refresh = signRefresh(user);
  await dbRun(
    "INSERT OR REPLACE INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))",
    [user.id, refresh]
  );
  return { accessToken: access, refreshToken: refresh };
}

function authMiddleware(req, res, next) {
  const raw = req.headers.authorization || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : '';
  if (!token) return res.status(401).json({ error: { message: 'Token manquant' } });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: { message: 'Token invalide ou expiré' } });
  }
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role))
    return res.status(403).json({ error: { message: 'Accès refusé' } });
  next();
};

// ═══════════════════════════════════════
//  RATE LIMITERS
// ═══════════════════════════════════════
const authLimiter   = rateLimit({ windowMs: 900000, max: 20, message: { error: { message: 'Trop de tentatives.' } } });
const claudeLimiter = rateLimit({ windowMs: 60000,  max: 40, message: { error: { message: 'Limite IA atteinte.' } } });

// ═══════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════
app.get('/api/health', (req, res) =>
  res.json({ status: 'ok', version: '2.1.0', timestamp: new Date().toISOString() }));

// ═══════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════
app.get('/api/auth/session', authMiddleware, (req, res) =>
  res.json({ data: req.user }));

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password)
      return res.status(400).json({ error: { message: 'Identifiant et mot de passe requis.' } });
    const user = await dbGet('SELECT * FROM users WHERE username = ? AND actif = 1', [username]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: { message: 'Identifiant ou mot de passe incorrect.' } });
    await dbRun("UPDATE users SET last_login = datetime('now') WHERE id = ?", [user.id]);
    await dbRun('INSERT INTO conn_log (user_id, username, role, action, ip) VALUES (?, ?, ?, ?, ?)',
      [user.id, user.username, user.role, 'login', req.ip]);
    const tokens = await issueTokens(user);
    res.json({ data: { ...tokens, role: user.role, nom: user.nom, id: user.id } });
  } catch (e) { res.status(500).json({ error: { message: e.message } }); }
});

app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(401).json({ error: { message: 'Refresh token manquant.' } });
    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const stored  = await dbGet(
      "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > datetime('now')", [refreshToken]);
    if (!stored) return res.status(401).json({ error: { message: 'Token révoqué.' } });
    const user = await dbGet('SELECT * FROM users WHERE id = ? AND actif = 1', [payload.id]);
    if (!user) return res.status(401).json({ error: { message: 'Compte introuvable.' } });
    res.json({ data: { accessToken: signAccess(user) } });
  } catch { res.status(401).json({ error: { message: 'Refresh token invalide.' } }); }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) await dbRun('DELETE FROM refresh_tokens WHERE token = ?', [refreshToken]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  REPORTS
// ═══════════════════════════════════════
function parseReport(r) {
  const data = (() => { try { return JSON.parse(r.data_json); } catch { return {}; } })();
  return {
    id: r.ext_id, arbitre: r.arbitre, arbitreEmail: r.arb_email, obsNom: r.obs_nom,
    categorie: r.categorie, competition: r.competition, equipes: r.equipes,
    date: r.date_match, score: r.score, note20: r.note_20, note100: r.note_100,
    statut: r.statut, auteurId: r.auteur_id, auteurNom: r.auteur_nom,
    createdAt: r.created_at, updatedAt: r.updated_at, ...data
  };
}

app.get('/api/reports', authMiddleware, async (req, res) => {
  const rows = await dbAll("SELECT * FROM reports WHERE statut != 'DRAFT' ORDER BY created_at DESC");
  res.json({ data: rows.map(parseReport) });
});

app.get('/api/reports/:id', authMiddleware, async (req, res) => {
  const r = await dbGet('SELECT * FROM reports WHERE ext_id = ?', [req.params.id]);
  if (!r) return res.status(404).json({ error: { message: 'Rapport introuvable.' } });
  res.json({ data: parseReport(r) });
});

app.post('/api/reports', authMiddleware, async (req, res) => {
  try {
    const rpt = req.body;
    const extId = String(rpt.id || Date.now());
    await dbRun(
      `INSERT OR REPLACE INTO reports
       (ext_id, arbitre, arb_email, obs_nom, categorie, competition, equipes,
        date_match, score, note_20, note_100, statut, data_json, auteur_id, auteur_nom, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [extId, rpt.arbitre||'', rpt.arbitreEmail||'', rpt.obsNom||'',
       rpt.categorie||'', rpt.competition||'', rpt.equipes||'',
       rpt.date||'', rpt.score||'0-0', rpt.note20||0, rpt.note100||0,
       rpt.statut||'🟡 En attente de validation',
       JSON.stringify(rpt), req.user.id, req.user.nom]
    );
    res.json({ success: true, id: extId });
  } catch (e) { res.status(500).json({ error: { message: e.message } }); }
});

app.put('/api/reports/:id', authMiddleware, requireRole('admin','gest'), async (req, res) => {
  try {
    const rpt = req.body;
    await dbRun(
      `UPDATE reports SET arbitre=?, arb_email=?, obs_nom=?, categorie=?, competition=?,
       equipes=?, date_match=?, score=?, note_20=?, note_100=?, statut=?, data_json=?,
       updated_at=datetime('now') WHERE ext_id=?`,
      [rpt.arbitre||'', rpt.arbitreEmail||'', rpt.obsNom||'', rpt.categorie||'',
       rpt.competition||'', rpt.equipes||'', rpt.date||'', rpt.score||'0-0',
       rpt.note20||0, rpt.note100||0, rpt.statut||'', JSON.stringify(rpt), req.params.id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: { message: e.message } }); }
});

app.patch('/api/reports/:id/statut', authMiddleware, requireRole('admin','gest'), async (req, res) => {
  await dbRun("UPDATE reports SET statut=?, updated_at=datetime('now') WHERE ext_id=?",
    [req.body.statut, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/reports/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  await dbRun('DELETE FROM reports WHERE ext_id = ?', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  BROUILLON
// ═══════════════════════════════════════
app.get('/api/draft', authMiddleware, async (req, res) => {
  const row = await dbGet("SELECT data_json FROM reports WHERE ext_id = ? AND statut = 'DRAFT'",
    [`draft_${req.user.id}`]);
  res.json({ data: row ? JSON.parse(row.data_json) : null });
});

app.post('/api/draft', authMiddleware, async (req, res) => {
  const extId = `draft_${req.user.id}`;
  await dbRun(
    "INSERT OR REPLACE INTO reports (ext_id, statut, data_json, auteur_id, auteur_nom, updated_at) VALUES (?, 'DRAFT', ?, ?, ?, datetime('now'))",
    [extId, JSON.stringify(req.body), req.user.id, req.user.nom]
  );
  res.json({ success: true });
});

app.delete('/api/draft', authMiddleware, async (req, res) => {
  await dbRun('DELETE FROM reports WHERE ext_id = ?', [`draft_${req.user.id}`]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  USERS (admin)
// ═══════════════════════════════════════
app.get('/api/users', authMiddleware, requireRole('admin'), async (req, res) => {
  const users = await dbAll('SELECT id, username, role, nom, email, actif, created_at, last_login FROM users ORDER BY id');
  res.json({ data: users });
});

app.post('/api/users', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const { username, password, role, nom, email } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: { message: 'Identifiant et mot de passe requis.' } });
    if (!['obs','gest','admin'].includes(role)) return res.status(400).json({ error: { message: 'Rôle invalide.' } });
    const result = await dbRun('INSERT INTO users (username, password, role, nom, email) VALUES (?, ?, ?, ?, ?)',
      [username, bcrypt.hashSync(password, 12), role, nom||'', email||'']);
    res.json({ success: true, id: result.lastID });
  } catch { res.status(409).json({ error: { message: 'Identifiant déjà utilisé.' } }); }
});

app.put('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { username, role, nom, email, actif, password } = req.body || {};
  if (password) {
    await dbRun('UPDATE users SET username=?, role=?, nom=?, email=?, actif=?, password=? WHERE id=?',
      [username, role, nom||'', email||'', actif?1:0, bcrypt.hashSync(password,12), req.params.id]);
  } else {
    await dbRun('UPDATE users SET username=?, role=?, nom=?, email=?, actif=? WHERE id=?',
      [username, role, nom||'', email||'', actif?1:0, req.params.id]);
  }
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: { message: 'Impossible de supprimer votre propre compte.' } });
  await dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  JOURNAL CONNEXIONS (admin)
// ═══════════════════════════════════════
app.get('/api/connlog', authMiddleware, requireRole('admin'), async (req, res) => {
  const log = await dbAll('SELECT * FROM conn_log ORDER BY timestamp DESC LIMIT 100');
  res.json({ data: log });
});

// ═══════════════════════════════════════
//  PROXY CLAUDE
// ═══════════════════════════════════════
app.post('/api/claude', authMiddleware, claudeLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY)
    return res.status(503).json({ error: { message: 'Clé API Anthropic non configurée.' } });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (e) { res.status(500).json({ error: { message: 'Erreur proxy: ' + e.message } }); }
});

// ═══════════════════════════════════════
//  FALLBACK SPA
// ═══════════════════════════════════════
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
app.listen(PORT, () => {
  console.log(`🟡 District BFC — http://localhost:${PORT}`);
  console.log(`   DB : ${DB_PATH}`);
  console.log(`   IA : ${ANTHROPIC_API_KEY ? '✅' : '⚠️  non configurée'}`);
});
