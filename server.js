'use strict';
require('dotenv').config();

const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { Pool }   = require('pg');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

// ═══════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════
const PORT               = process.env.PORT               || 3000;
const JWT_SECRET         = process.env.JWT_SECRET         || 'dev-secret-change-in-prod-AAAA';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-change-in-prod-BBBB';
const GEMINI_API_KEY     = process.env.GEMINI_API_KEY     || '';
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  family: 4
});

// ═══════════════════════════════════════
//  BASE DE DONNÉES PostgreSQL (Supabase)
// ═══════════════════════════════════════
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const dbRun = async (sql, p = []) => { const r = await pool.query(sql, p); return r; };
const dbGet = async (sql, p = []) => { const r = await pool.query(sql, p); return r.rows[0]; };
const dbAll = async (sql, p = []) => { const r = await pool.query(sql, p); return r.rows; };

// Init tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'obs',
      nom TEXT DEFAULT '',
      email TEXT DEFAULT '',
      actif INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW(),
      last_login TIMESTAMP
    )`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
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
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS conn_log (
      id SERIAL PRIMARY KEY,
      user_id INTEGER DEFAULT 0,
      username TEXT DEFAULT '',
      role TEXT DEFAULT '',
      action TEXT DEFAULT '',
      ip TEXT DEFAULT '',
      timestamp TIMESTAMP DEFAULT NOW()
    )`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS arbitres (
      id SERIAL PRIMARY KEY,
      nom TEXT NOT NULL,
      prenom TEXT DEFAULT '',
      licence TEXT DEFAULT '',
      localite TEXT DEFAULT '',
      telephone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      club TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

  // Seed comptes par défaut
  const { rows } = await pool.query('SELECT COUNT(*) as c FROM users');
  if (parseInt(rows[0].c) === 0) {
    const defaults = [
      { u: 'obs',   p: '89Sidi-Aich', r: 'obs',   n: 'Observateur' },
      { u: 'gest',  p: '13Sidi-Aich', r: 'gest',  n: 'Gestionnaire CDA' },
      { u: 'admin', p: '75Sidi-Aich', r: 'admin', n: 'Administrateur' }
    ];
    for (const d of defaults) {
      await pool.query(
        'INSERT INTO users (username, password, role, nom) VALUES ($1, $2, $3, $4)',
        [d.u, bcrypt.hashSync(d.p, 12), d.r, d.n]
      );
    }
    console.log('✅ Comptes par défaut créés');
  }

  console.log('✅ Base de données PostgreSQL prête');
}

// Nettoyage tokens expirés
setInterval(async () => {
  await pool.query("DELETE FROM refresh_tokens WHERE expires_at < NOW()");
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
  await pool.query(
    "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '7 days') ON CONFLICT (token) DO UPDATE SET expires_at = EXCLUDED.expires_at",
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
const geminiLimiter = rateLimit({ windowMs: 60000,  max: 40, message: { error: { message: 'Limite IA atteinte.' } } });

// ═══════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════
app.get('/api/health', (req, res) =>
  res.json({ status: 'ok', version: '3.0.0', db: 'postgresql', timestamp: new Date().toISOString() }));

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
    const user = await dbGet('SELECT * FROM users WHERE username = $1 AND actif = 1', [username]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: { message: 'Identifiant ou mot de passe incorrect.' } });
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    await pool.query('INSERT INTO conn_log (user_id, username, role, action, ip) VALUES ($1, $2, $3, $4, $5)',
      [user.id, user.username, user.role, 'login', req.ip]);
    const tokens = await issueTokens(user);
    res.json({ data: { ...tokens, role: user.role, nom: user.nom, id: user.id } });
  } catch(e) { res.status(500).json({ error: { message: e.message } }); }
});

app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(401).json({ error: { message: 'Refresh token manquant.' } });
    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const stored  = await dbGet('SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()', [refreshToken]);
    if (!stored) return res.status(401).json({ error: { message: 'Token révoqué.' } });
    const user = await dbGet('SELECT * FROM users WHERE id = $1 AND actif = 1', [payload.id]);
    if (!user) return res.status(401).json({ error: { message: 'Compte introuvable.' } });
    res.json({ data: { accessToken: signAccess(user) } });
  } catch { res.status(401).json({ error: { message: 'Refresh token invalide.' } }); }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
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
  const r = await dbGet('SELECT * FROM reports WHERE ext_id = $1', [req.params.id]);
  if (!r) return res.status(404).json({ error: { message: 'Rapport introuvable.' } });
  res.json({ data: parseReport(r) });
});

app.post('/api/reports', authMiddleware, async (req, res) => {
  try {
    const rpt = req.body;
    const extId = String(rpt.id || Date.now());
    await pool.query(
      `INSERT INTO reports (ext_id, arbitre, arb_email, obs_nom, categorie, competition, equipes,
       date_match, score, note_20, note_100, statut, data_json, auteur_id, auteur_nom, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW())
       ON CONFLICT (ext_id) DO UPDATE SET
       arbitre=$2, arb_email=$3, obs_nom=$4, categorie=$5, competition=$6, equipes=$7,
       date_match=$8, score=$9, note_20=$10, note_100=$11, statut=$12, data_json=$13,
       auteur_id=$14, auteur_nom=$15, updated_at=NOW()`,
      [extId, rpt.arbitre||'', rpt.arbitreEmail||'', rpt.obsNom||'',
       rpt.categorie||'', rpt.competition||'', rpt.equipes||'',
       rpt.date||'', rpt.score||'0-0', rpt.note20||0, rpt.note100||0,
       rpt.statut||'🟡 En attente de validation',
       JSON.stringify(rpt), req.user.id, req.user.nom]
    );
    res.json({ success: true, id: extId });
  } catch(e) { res.status(500).json({ error: { message: e.message } }); }
});

app.put('/api/reports/:id', authMiddleware, requireRole('admin','gest'), async (req, res) => {
  try {
    const rpt = req.body;
    await pool.query(
      `UPDATE reports SET arbitre=$1, arb_email=$2, obs_nom=$3, categorie=$4, competition=$5,
       equipes=$6, date_match=$7, score=$8, note_20=$9, note_100=$10, statut=$11, data_json=$12,
       updated_at=NOW() WHERE ext_id=$13`,
      [rpt.arbitre||'', rpt.arbitreEmail||'', rpt.obsNom||'', rpt.categorie||'',
       rpt.competition||'', rpt.equipes||'', rpt.date||'', rpt.score||'0-0',
       rpt.note20||0, rpt.note100||0, rpt.statut||'', JSON.stringify(rpt), req.params.id]
    );
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: { message: e.message } }); }
});

app.patch('/api/reports/:id/statut', authMiddleware, requireRole('admin','gest'), async (req, res) => {
  await pool.query('UPDATE reports SET statut=$1, updated_at=NOW() WHERE ext_id=$2',
    [req.body.statut, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/reports/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  await pool.query('DELETE FROM reports WHERE ext_id = $1', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  BROUILLON
// ═══════════════════════════════════════
app.get('/api/draft', authMiddleware, async (req, res) => {
  const row = await dbGet("SELECT data_json FROM reports WHERE ext_id = $1 AND statut = 'DRAFT'",
    [`draft_${req.user.id}`]);
  res.json({ data: row ? JSON.parse(row.data_json) : null });
});

app.post('/api/draft', authMiddleware, async (req, res) => {
  const extId = `draft_${req.user.id}`;
  await pool.query(
    `INSERT INTO reports (ext_id, statut, data_json, auteur_id, auteur_nom, updated_at)
     VALUES ($1, 'DRAFT', $2, $3, $4, NOW())
     ON CONFLICT (ext_id) DO UPDATE SET data_json=$2, updated_at=NOW()`,
    [extId, JSON.stringify(req.body), req.user.id, req.user.nom]
  );
  res.json({ success: true });
});

app.delete('/api/draft', authMiddleware, async (req, res) => {
  await pool.query('DELETE FROM reports WHERE ext_id = $1', [`draft_${req.user.id}`]);
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
    const result = await pool.query(
      'INSERT INTO users (username, password, role, nom, email) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [username, bcrypt.hashSync(password, 12), role, nom||'', email||'']
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch { res.status(409).json({ error: { message: 'Identifiant déjà utilisé.' } }); }
});

app.put('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { username, role, nom, email, actif, password } = req.body || {};
  if (password) {
    await pool.query('UPDATE users SET username=$1, role=$2, nom=$3, email=$4, actif=$5, password=$6 WHERE id=$7',
      [username, role, nom||'', email||'', actif?1:0, bcrypt.hashSync(password,12), req.params.id]);
  } else {
    await pool.query('UPDATE users SET username=$1, role=$2, nom=$3, email=$4, actif=$5 WHERE id=$6',
      [username, role, nom||'', email||'', actif?1:0, req.params.id]);
  }
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: { message: 'Impossible de supprimer votre propre compte.' } });
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
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
//  ARBITRES
// ═══════════════════════════════════════
app.get('/api/arbitres', authMiddleware, async (req, res) => {
  const rows = await dbAll('SELECT * FROM arbitres ORDER BY nom, prenom');
  res.json({ data: rows });
});

app.post('/api/arbitres', authMiddleware, requireRole('gest','admin'), async (req, res) => {
  try {
    const { nom, prenom, licence, localite, telephone, email, club } = req.body || {};
    if (!nom) return res.status(400).json({ error: { message: 'Le nom est requis.' } });
    const result = await pool.query(
      'INSERT INTO arbitres (nom,prenom,licence,localite,telephone,email,club) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [nom.toUpperCase(), prenom||'', licence||'', localite||'', telephone||'', email||'', club||'']
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch(e) { res.status(500).json({ error: { message: e.message } }); }
});

app.put('/api/arbitres/:id', authMiddleware, requireRole('gest','admin'), async (req, res) => {
  const { nom, prenom, licence, localite, telephone, email, club } = req.body || {};
  await pool.query(
    'UPDATE arbitres SET nom=$1, prenom=$2, licence=$3, localite=$4, telephone=$5, email=$6, club=$7, updated_at=NOW() WHERE id=$8',
    [nom.toUpperCase(), prenom||'', licence||'', localite||'', telephone||'', email||'', club||'', req.params.id]
  );
  res.json({ success: true });
});

app.delete('/api/arbitres/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  await pool.query('DELETE FROM arbitres WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════════════════════════════
//  PROXY GEMINI
// ═══════════════════════════════════════
app.post('/api/claude', authMiddleware, geminiLimiter, async (req, res) => {
  if (!GEMINI_API_KEY)
    return res.status(503).json({ error: { message: 'Clé API Gemini non configurée.' } });
  try {
    const messages = req.body.messages || [];
    const contents = messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: typeof m.content === 'string' ? m.content : JSON.stringify(m.content) }]
    }));
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents, generationConfig: { maxOutputTokens: req.body.max_tokens || 1000 } }) }
    );
    const data = await response.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    res.json({ content: [{ type: 'text', text }] });
  } catch(e) { res.status(500).json({ error: { message: 'Erreur Gemini: ' + e.message } }); }
});

// ═══════════════════════════════════════
//  FALLBACK SPA
// ═══════════════════════════════════════
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🟢 District BFC — http://localhost:${PORT}`);
    console.log(`   DB  : PostgreSQL (Supabase)`);
    console.log(`   IA  : ${GEMINI_API_KEY ? '✅ Gemini' : '⚠️  non configurée'}`);
  });
}).catch(err => {
  console.error('❌ Erreur connexion base de données:', err.message);
  process.exit(1);
});
