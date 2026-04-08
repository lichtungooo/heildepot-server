import initSqlJs from 'sql.js'
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DB_PATH = join(__dirname, 'data.db')

const SQL = await initSqlJs()

// Load existing DB or create new
let db
if (existsSync(DB_PATH)) {
  const buffer = readFileSync(DB_PATH)
  db = new SQL.Database(buffer)
} else {
  db = new SQL.Database()
}

// ─── SCHEMA ──────────────────────────────────────────────
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    passwort TEXT NOT NULL,
    vorname TEXT DEFAULT '',
    nachname TEXT DEFAULT '',
    strasse TEXT DEFAULT '',
    plz TEXT DEFAULT '',
    ort TEXT DEFAULT '',
    land TEXT DEFAULT 'DE',
    telefon TEXT DEFAULT '',
    verifiziert INTEGER DEFAULT 0,
    verify_token TEXT,
    newsletter INTEGER DEFAULT 1,
    erstellt TEXT DEFAULT (datetime('now')),
    letzter_login TEXT
  )
`)
db.run(`
  CREATE TABLE IF NOT EXISTS anfragen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    items TEXT NOT NULL,
    total TEXT,
    adresse TEXT,
    optionen TEXT,
    nachricht TEXT DEFAULT '',
    status TEXT DEFAULT 'neu',
    erstellt TEXT DEFAULT (datetime('now'))
  )
`)
db.run(`
  CREATE TABLE IF NOT EXISTS blog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titel TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    inhalt TEXT NOT NULL,
    auszug TEXT DEFAULT '',
    autor TEXT DEFAULT 'Freundeskreis',
    veroeffentlicht INTEGER DEFAULT 0,
    erstellt TEXT DEFAULT (datetime('now')),
    aktualisiert TEXT DEFAULT (datetime('now'))
  )
`)
db.run(`
  CREATE TABLE IF NOT EXISTS newsletter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    betreff TEXT NOT NULL,
    inhalt TEXT NOT NULL,
    gesendet INTEGER DEFAULT 0,
    empfaenger_count INTEGER DEFAULT 0,
    erstellt TEXT DEFAULT (datetime('now')),
    gesendet_am TEXT
  )
`)

db.run(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    passwort TEXT NOT NULL,
    name TEXT DEFAULT '',
    rolle TEXT DEFAULT 'redakteur',
    rechte TEXT DEFAULT '{}',
    aktiv INTEGER DEFAULT 1,
    erstellt TEXT DEFAULT (datetime('now')),
    letzter_login TEXT
  )
`)

// Save to disk periodically
function save() {
  const data = db.export()
  writeFileSync(DB_PATH, Buffer.from(data))
}

// Auto-save every 30 seconds
setInterval(save, 30000)

// Wrap db with helper methods matching better-sqlite3 API
const wrapper = {
  prepare(sql) {
    return {
      run(...params) {
        db.run(sql, params)
        save()
        const lastId = db.exec('SELECT last_insert_rowid() as id')[0]?.values[0]?.[0]
        return { lastInsertRowid: lastId, changes: db.getRowsModified() }
      },
      get(...params) {
        const stmt = db.prepare(sql)
        stmt.bind(params)
        if (stmt.step()) {
          const cols = stmt.getColumnNames()
          const vals = stmt.get()
          stmt.free()
          const row = {}
          cols.forEach((c, i) => row[c] = vals[i])
          return row
        }
        stmt.free()
        return undefined
      },
      all(...params) {
        const results = []
        const stmt = db.prepare(sql)
        stmt.bind(params)
        while (stmt.step()) {
          const cols = stmt.getColumnNames()
          const vals = stmt.get()
          const row = {}
          cols.forEach((c, i) => row[c] = vals[i])
          results.push(row)
        }
        stmt.free()
        return results
      }
    }
  },
  exec(sql) { db.run(sql); save() },
  close() { save(); db.close() },
}

export default wrapper
