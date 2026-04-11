-- ═══════════════════════════════════════════════════════════
-- FiltresDNS — Schéma D1
-- ═══════════════════════════════════════════════════════════

-- Filleuls (utilisateurs du DNS)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  hostname TEXT NOT NULL UNIQUE,
  invite_code TEXT UNIQUE,
  parrain_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (parrain_id) REFERENCES parrains(id)
);

-- Parrains
CREATE TABLE IF NOT EXISTS parrains (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Suggestions d'URLs par les filleuls (ajoutées automatiquement à AdGuard)
CREATE TABLE IF NOT EXISTS suggestions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  category TEXT NOT NULL,
  category_other TEXT,
  added_to_adguard INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Choix de catégories par filleul
-- blocked = 1 → la catégorie est bloquée (irréversible par le filleul)
-- blocked = 0 → la catégorie n'est pas bloquée
-- locked_by = 'user' → verrouillé par le filleul (irréversible)
-- locked_by = 'parrain' → activé/désactivé par le parrain (réversible par le parrain)
CREATE TABLE IF NOT EXISTS user_categories (
  user_id TEXT NOT NULL,
  category TEXT NOT NULL,
  blocked INTEGER DEFAULT 0,
  locked_by TEXT DEFAULT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, category),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
