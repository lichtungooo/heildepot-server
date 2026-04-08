import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { marked } from 'marked'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import db from './db.js'
import { initMail, reloadMail, verifyEmail, orderNotification, orderConfirmation, sendNewsletter, sendTestMail } from './mail.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.PORT || 3001
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret'

app.use(cors())
app.use(express.json({ limit: '5mb' }))

// Serve admin panel
import { readFileSync } from 'fs'
const adminHtml = readFileSync(join(__dirname, 'public', 'admin.html'), 'utf-8')
app.get('/admin', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(adminHtml),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  })
  res.end(adminHtml)
})

// Init mail
initMail()

// ─── MIDDLEWARE ──────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) return res.status(401).json({ error: 'Nicht angemeldet' })
  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'Token ungueltig' })
  }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (!req.user.admin) return res.status(403).json({ error: 'Kein Admin' })
    next()
  })
}

// ═══════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════

// Registrierung
app.post('/api/auth/register', async (req, res) => {
  const { email, passwort } = req.body
  if (!email || !passwort) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' })
  if (passwort.length < 4) return res.status(400).json({ error: 'Passwort muss mindestens 4 Zeichen haben' })

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  if (existing) return res.status(409).json({ error: 'Diese E-Mail ist bereits registriert' })

  const hash = bcrypt.hashSync(passwort, 10)
  const token = crypto.randomBytes(32).toString('hex')

  const result = db.prepare(
    'INSERT INTO users (email, passwort, verify_token) VALUES (?, ?, ?)'
  ).run(email, hash, token)

  // Send verification email
  try {
    await verifyEmail(email, token, process.env.FRONTEND_URL)
  } catch (err) {
    console.error('[Auth] Verify-Mail Fehler:', err.message)
  }

  const user = db.prepare('SELECT id, email, vorname, nachname, verifiziert, erstellt FROM users WHERE id = ?').get(result.lastInsertRowid)
  const jwtToken = jwt.sign({ id: user.id, email: user.email, admin: false }, JWT_SECRET, { expiresIn: '30d' })

  res.json({ user, token: jwtToken })
})

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, passwort } = req.body
  if (!email || !passwort) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' })

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  if (!user || !bcrypt.compareSync(passwort, user.passwort)) {
    return res.status(401).json({ error: 'E-Mail oder Passwort falsch' })
  }

  db.prepare('UPDATE users SET letzter_login = datetime("now") WHERE id = ?').run(user.id)

  const token = jwt.sign({ id: user.id, email: user.email, admin: false }, JWT_SECRET, { expiresIn: '30d' })
  const { passwort: _, verify_token: __, ...safe } = user

  res.json({ user: safe, token })
})

// E-Mail verifizieren
app.get('/api/auth/verify/:token', (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE verify_token = ?').get(req.params.token)
  if (!user) return res.status(404).json({ error: 'Token ungueltig' })

  db.prepare('UPDATE users SET verifiziert = 1, verify_token = NULL WHERE id = ?').run(user.id)
  res.json({ ok: true, message: 'E-Mail bestaetigt!' })
})

// Profil abrufen
app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, vorname, nachname, strasse, plz, ort, land, telefon, verifiziert, newsletter, erstellt FROM users WHERE id = ?').get(req.user.id)
  if (!user) return res.status(404).json({ error: 'User nicht gefunden' })
  res.json(user)
})

// Profil aktualisieren
app.put('/api/auth/me', auth, (req, res) => {
  const { vorname, nachname, strasse, plz, ort, land, telefon, newsletter } = req.body
  db.prepare(`
    UPDATE users SET vorname=?, nachname=?, strasse=?, plz=?, ort=?, land=?, telefon=?, newsletter=?
    WHERE id = ?
  `).run(vorname || '', nachname || '', strasse || '', plz || '', ort || '', land || 'DE', telefon || '', newsletter ?? 1, req.user.id)

  const user = db.prepare('SELECT id, email, vorname, nachname, strasse, plz, ort, land, telefon, verifiziert, newsletter FROM users WHERE id = ?').get(req.user.id)
  res.json(user)
})

// ═══════════════════════════════════════════════════════════
// ANFRAGEN (Bestellungen)
// ═══════════════════════════════════════════════════════════

// Neue Anfrage senden
app.post('/api/anfragen', auth, async (req, res) => {
  const { items, total, adresse, optionen, nachricht } = req.body
  if (!items || !items.length) return res.status(400).json({ error: 'Keine Produkte' })

  const result = db.prepare(`
    INSERT INTO anfragen (user_id, items, total, adresse, optionen, nachricht)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(req.user.id, JSON.stringify(items), total || '', adresse || '', JSON.stringify(optionen || {}), nachricht || '')

  const anfrage = db.prepare('SELECT * FROM anfragen WHERE id = ?').get(result.lastInsertRowid)
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)

  // Mails senden
  try {
    await orderNotification(anfrage, user)
    if (user.verifiziert) {
      await orderConfirmation(anfrage, user)
    }
  } catch (err) {
    console.error('[Anfrage] Mail-Fehler:', err.message)
  }

  res.json({ id: anfrage.id, status: 'gesendet' })
})

// Meine Anfragen
app.get('/api/anfragen', auth, (req, res) => {
  const anfragen = db.prepare('SELECT * FROM anfragen WHERE user_id = ? ORDER BY erstellt DESC LIMIT 50').all(req.user.id)
  res.json(anfragen.map(a => ({ ...a, items: JSON.parse(a.items), optionen: a.optionen ? JSON.parse(a.optionen) : {} })))
})

// ═══════════════════════════════════════════════════════════
// BLOG (öffentlich lesbar, Admin zum Schreiben)
// ═══════════════════════════════════════════════════════════

// Alle veröffentlichten Blog-Posts
app.get('/api/blog', (req, res) => {
  const posts = db.prepare('SELECT id, titel, slug, auszug, autor, erstellt FROM blog WHERE veroeffentlicht = 1 ORDER BY erstellt DESC LIMIT 50').all()
  res.json(posts)
})

// Einzelner Blog-Post
app.get('/api/blog/:slug', (req, res) => {
  const post = db.prepare('SELECT * FROM blog WHERE slug = ? AND veroeffentlicht = 1').get(req.params.slug)
  if (!post) return res.status(404).json({ error: 'Post nicht gefunden' })
  res.json({ ...post, inhalt_html: marked(post.inhalt) })
})

// ═══════════════════════════════════════════════════════════
// ADMIN
// ═══════════════════════════════════════════════════════════

// Seed default super-admin if no admins exist
const adminCount = db.prepare('SELECT COUNT(*) as count FROM admins').get()
if (!adminCount || adminCount.count === 0) {
  const defaultEmail = process.env.ADMIN_EMAIL || 'timo.martin@heildepot.de'
  const defaultPass = process.env.ADMIN_PASS || 'admin123'
  const hash = bcrypt.hashSync(defaultPass, 10)
  db.prepare('INSERT INTO admins (email, passwort, name, rolle, rechte) VALUES (?, ?, ?, ?, ?)').run(
    defaultEmail, hash, 'Timo', 'superadmin',
    JSON.stringify({ anfragen: true, users: true, blog: true, newsletter: true, settings: true, admins: true })
  )
  console.log('[Admin] Standard-Superadmin erstellt:', defaultEmail)
}

// Admin Login (aus Datenbank)
app.post('/api/admin/login', (req, res) => {
  const { email, passwort } = req.body
  if (!email || !passwort) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' })

  const admin = db.prepare('SELECT * FROM admins WHERE email = ? AND aktiv = 1').get(email)
  if (!admin || !bcrypt.compareSync(passwort, admin.passwort)) {
    return res.status(401).json({ error: 'Falsche Zugangsdaten' })
  }

  db.prepare('UPDATE admins SET letzter_login = datetime("now") WHERE id = ?').run(admin.id)

  const rechte = JSON.parse(admin.rechte || '{}')
  const token = jwt.sign({ id: admin.id, email: admin.email, admin: true, rolle: admin.rolle, rechte }, JWT_SECRET, { expiresIn: '7d' })
  res.json({ token, admin: true, name: admin.name, rolle: admin.rolle, rechte })
})

// Admin: Eigenes Profil
app.get('/api/admin/me', adminAuth, (req, res) => {
  const admin = db.prepare('SELECT id, email, name, rolle, rechte, erstellt, letzter_login FROM admins WHERE id = ?').get(req.user.id)
  if (!admin) return res.status(404).json({ error: 'Admin nicht gefunden' })
  res.json({ ...admin, rechte: JSON.parse(admin.rechte || '{}') })
})

// Admin: Passwort aendern
app.put('/api/admin/me/password', adminAuth, (req, res) => {
  const { altes_passwort, neues_passwort } = req.body
  if (!altes_passwort || !neues_passwort) return res.status(400).json({ error: 'Altes und neues Passwort erforderlich' })
  if (neues_passwort.length < 4) return res.status(400).json({ error: 'Passwort muss mindestens 4 Zeichen haben' })

  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.user.id)
  if (!bcrypt.compareSync(altes_passwort, admin.passwort)) {
    return res.status(401).json({ error: 'Altes Passwort falsch' })
  }

  db.prepare('UPDATE admins SET passwort = ? WHERE id = ?').run(bcrypt.hashSync(neues_passwort, 10), req.user.id)
  res.json({ ok: true })
})

// Admin-Verwaltung (nur Superadmin)
function superAdminAuth(req, res, next) {
  adminAuth(req, res, () => {
    if (req.user.rolle !== 'superadmin') return res.status(403).json({ error: 'Nur Superadmin darf Admins verwalten' })
    next()
  })
}

// Alle Admins auflisten
app.get('/api/admin/admins', superAdminAuth, (req, res) => {
  const admins = db.prepare('SELECT id, email, name, rolle, rechte, aktiv, erstellt, letzter_login FROM admins ORDER BY erstellt').all()
  res.json(admins.map(a => ({ ...a, rechte: JSON.parse(a.rechte || '{}') })))
})

// Neuen Admin anlegen
app.post('/api/admin/admins', superAdminAuth, (req, res) => {
  const { email, passwort, name, rolle, rechte } = req.body
  if (!email || !passwort) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich' })

  const existing = db.prepare('SELECT id FROM admins WHERE email = ?').get(email)
  if (existing) return res.status(409).json({ error: 'E-Mail bereits vergeben' })

  const hash = bcrypt.hashSync(passwort, 10)
  const result = db.prepare('INSERT INTO admins (email, passwort, name, rolle, rechte) VALUES (?, ?, ?, ?, ?)').run(
    email, hash, name || '', rolle || 'redakteur', JSON.stringify(rechte || {})
  )
  res.json({ id: result.lastInsertRowid })
})

// Admin bearbeiten
app.put('/api/admin/admins/:id', superAdminAuth, (req, res) => {
  const { name, rolle, rechte, aktiv } = req.body
  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.params.id)
  if (!admin) return res.status(404).json({ error: 'Admin nicht gefunden' })

  db.prepare('UPDATE admins SET name=?, rolle=?, rechte=?, aktiv=? WHERE id=?').run(
    name ?? admin.name, rolle ?? admin.rolle, JSON.stringify(rechte ?? JSON.parse(admin.rechte || '{}')), aktiv ?? admin.aktiv, req.params.id
  )
  res.json({ ok: true })
})

// Admin Passwort zuruecksetzen (Superadmin)
app.put('/api/admin/admins/:id/password', superAdminAuth, (req, res) => {
  const { passwort } = req.body
  if (!passwort || passwort.length < 4) return res.status(400).json({ error: 'Passwort muss mindestens 4 Zeichen haben' })
  db.prepare('UPDATE admins SET passwort = ? WHERE id = ?').run(bcrypt.hashSync(passwort, 10), req.params.id)
  res.json({ ok: true })
})

// Admin loeschen
app.delete('/api/admin/admins/:id', superAdminAuth, (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Du kannst dich nicht selbst loeschen' })
  db.prepare('DELETE FROM admins WHERE id = ?').run(req.params.id)
  res.json({ ok: true })
})

// Admin: Alle Anfragen
app.get('/api/admin/anfragen', adminAuth, (req, res) => {
  const anfragen = db.prepare(`
    SELECT a.*, u.email, u.vorname, u.nachname, u.telefon
    FROM anfragen a LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.erstellt DESC LIMIT 100
  `).all()
  res.json(anfragen.map(a => ({ ...a, items: JSON.parse(a.items) })))
})

// Admin: Anfrage-Status ändern
app.put('/api/admin/anfragen/:id', adminAuth, (req, res) => {
  const { status } = req.body
  db.prepare('UPDATE anfragen SET status = ? WHERE id = ?').run(status, req.params.id)
  res.json({ ok: true })
})

// Admin: Alle User
app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, email, vorname, nachname, verifiziert, newsletter, erstellt, letzter_login FROM users ORDER BY erstellt DESC').all()
  res.json(users)
})

// Admin: Blog erstellen/bearbeiten
app.post('/api/admin/blog', adminAuth, (req, res) => {
  const { titel, inhalt, auszug, autor, veroeffentlicht } = req.body
  if (!titel || !inhalt) return res.status(400).json({ error: 'Titel und Inhalt erforderlich' })

  const slug = titel.toLowerCase()
    .replace(/[^a-z0-9äöüß]+/g, '-')
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/-+/g, '-').replace(/^-|-$/g, '')

  const result = db.prepare(`
    INSERT INTO blog (titel, slug, inhalt, auszug, autor, veroeffentlicht)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(titel, slug + '-' + Date.now(), inhalt, auszug || '', autor || 'Freundeskreis', veroeffentlicht ? 1 : 0)

  res.json({ id: result.lastInsertRowid, slug })
})

app.put('/api/admin/blog/:id', adminAuth, (req, res) => {
  const { titel, inhalt, auszug, autor, veroeffentlicht } = req.body
  db.prepare(`
    UPDATE blog SET titel=?, inhalt=?, auszug=?, autor=?, veroeffentlicht=?, aktualisiert=datetime('now')
    WHERE id = ?
  `).run(titel, inhalt, auszug || '', autor || 'Freundeskreis', veroeffentlicht ? 1 : 0, req.params.id)
  res.json({ ok: true })
})

app.delete('/api/admin/blog/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM blog WHERE id = ?').run(req.params.id)
  res.json({ ok: true })
})

// Admin: Alle Blog-Posts (inkl. unveröffentlichte)
app.get('/api/admin/blog', adminAuth, (req, res) => {
  const posts = db.prepare('SELECT * FROM blog ORDER BY erstellt DESC').all()
  res.json(posts)
})

// Admin: Newsletter erstellen
app.post('/api/admin/newsletter', adminAuth, (req, res) => {
  const { betreff, inhalt } = req.body
  if (!betreff || !inhalt) return res.status(400).json({ error: 'Betreff und Inhalt erforderlich' })

  const result = db.prepare('INSERT INTO newsletter (betreff, inhalt) VALUES (?, ?)').run(betreff, inhalt)
  res.json({ id: result.lastInsertRowid })
})

// Admin: Newsletter senden
app.post('/api/admin/newsletter/:id/send', adminAuth, async (req, res) => {
  const nl = db.prepare('SELECT * FROM newsletter WHERE id = ?').get(req.params.id)
  if (!nl) return res.status(404).json({ error: 'Newsletter nicht gefunden' })
  if (nl.gesendet) return res.status(400).json({ error: 'Newsletter wurde bereits gesendet' })

  const subscribers = db.prepare('SELECT email FROM users WHERE newsletter = 1 AND verifiziert = 1').all()

  const sent = await sendNewsletter(nl, subscribers)

  db.prepare('UPDATE newsletter SET gesendet = 1, empfaenger_count = ?, gesendet_am = datetime("now") WHERE id = ?').run(sent, nl.id)

  res.json({ gesendet: sent, empfaenger: subscribers.length })
})

// Admin: Alle Newsletter
app.get('/api/admin/newsletter', adminAuth, (req, res) => {
  const nls = db.prepare('SELECT * FROM newsletter ORDER BY erstellt DESC').all()
  res.json(nls)
})

// Admin: Dashboard Stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const users = db.prepare('SELECT COUNT(*) as count FROM users').get()
  const verified = db.prepare('SELECT COUNT(*) as count FROM users WHERE verifiziert = 1').get()
  const newsletter = db.prepare('SELECT COUNT(*) as count FROM users WHERE newsletter = 1 AND verifiziert = 1').get()
  const anfragen = db.prepare('SELECT COUNT(*) as count FROM anfragen').get()
  const neue = db.prepare("SELECT COUNT(*) as count FROM anfragen WHERE status = 'neu'").get()
  const posts = db.prepare('SELECT COUNT(*) as count FROM blog WHERE veroeffentlicht = 1').get()

  res.json({
    users: users.count,
    verifiziert: verified.count,
    newsletter_abonnenten: newsletter.count,
    anfragen: anfragen.count,
    neue_anfragen: neue.count,
    blog_posts: posts.count,
  })
})

// ═══════════════════════════════════════════════════════════
// SMTP CONFIG (Admin)
// ═══════════════════════════════════════════════════════════
app.put('/api/admin/smtp', adminAuth, (req, res) => {
  const { host, port, user, pass, from } = req.body
  // Save to env-like config in DB
  db.exec(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`)
  const upsert = db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)')
  if (host) upsert.run('MAIL_HOST', host)
  if (port) upsert.run('MAIL_PORT', port)
  if (user) upsert.run('MAIL_USER', user)
  if (pass) upsert.run('MAIL_PASS', pass)
  if (from) upsert.run('MAIL_FROM', from)

  // Reload mail transporter
  process.env.MAIL_HOST = host || process.env.MAIL_HOST
  process.env.MAIL_PORT = port || process.env.MAIL_PORT
  process.env.MAIL_USER = user || process.env.MAIL_USER
  process.env.MAIL_PASS = pass || process.env.MAIL_PASS
  process.env.MAIL_FROM = from || process.env.MAIL_FROM
  reloadMail()

  res.json({ ok: true, message: 'SMTP-Einstellungen gespeichert und aktiviert' })
})

app.post('/api/admin/smtp/test', adminAuth, async (req, res) => {
  try {
    await sendTestMail(process.env.ADMIN_EMAIL)
    res.json({ message: `Test-Mail an ${process.env.ADMIN_EMAIL} gesendet!` })
  } catch (err) {
    res.status(500).json({ error: 'Mail-Fehler: ' + err.message })
  }
})

// ═══════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', time: new Date().toISOString() })
})

// ═══════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════╗
  ║   HEILDEPOT SERVER                        ║
  ║   http://localhost:${PORT}                    ║
  ║                                           ║
  ║   API:    /api/health                     ║
  ║   Admin:  /api/admin/login                ║
  ╚═══════════════════════════════════════════╝
  `)
})
