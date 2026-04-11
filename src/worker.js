// ═══════════════════════════════════════════════════════════════
// FiltresDNS — Worker Cloudflare complet
// Parrain/Filleul · D1 · AdGuard Home API
// ═══════════════════════════════════════════════════════════════

const OPTIONAL_CATS = ['manga', 'gambling', 'search_engines', 'ai_mixed', 'yt_safesearch'];
const CAT_LABELS = {
  manga: { name: 'Manga / Webtoon / Scantrad', icon: '📚', desc: 'Sites de lecture manga en ligne' },
  gambling: { name: "Jeux d'argent / Paris sportifs", icon: '🎰', desc: 'Sites de paris et casinos en ligne' },
  search_engines: { name: 'Moteurs de recherche alternatifs', icon: '🔍', desc: 'Bloque tous les moteurs sauf Google' },
  ai_mixed: { name: 'IA mixtes', icon: '🤖', desc: 'Plateformes IA à usage général avec contenu adulte possible' },
  yt_safesearch: { name: 'SafeSearch YouTube', icon: '▶️', desc: 'Force les résultats restreints sur YouTube' }
};
const MANDATORY_CATS = [
  { name: 'Contenus pour adultes', icon: '🔞', count: 157 },
  { name: 'Webcams adultes', icon: '📹', count: 37 },
  { name: 'Hentai / Comics adultes', icon: '🎨', count: 55 },
  { name: 'IA suggestive / NSFW', icon: '⚠️', count: 26 },
  { name: 'Tor / Anonymisation', icon: '🧅', count: 9 }
];

const SUGGEST_CATS = [
  { value: 'adulte', label: 'Contenus pour adultes' },
  { value: 'webcam', label: 'Webcams adultes' },
  { value: 'hentai', label: 'Hentai / Comics adultes' },
  { value: 'ia_nsfw', label: 'IA suggestive / NSFW' },
  { value: 'manga', label: 'Manga / Webtoon / Scantrad' },
  { value: 'gambling', label: "Jeux d'argent / Paris sportifs" },
  { value: 'search', label: 'Moteurs de recherche' },
  { value: 'ai_mixed', label: 'IA mixtes' },
  { value: 'tor', label: 'Tor / Anonymisation' },
  { value: 'autre', label: 'Autre (préciser)' }
];

// Map category keys to their comment markers in AdGuard rules
const CAT_MARKERS = {
  manga: '# === Manga / Webtoon / Scantrad ===',
  gambling: "# === Jeux d'argent ===",
  search_engines: '# === Moteurs de recherche ===',
  ai_mixed: '# === IA mixtes'
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return handleAPI(request, url, env);
    return new Response(HTML(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  }
};

// ── Helpers ──────────────────────────────────────────────────

async function hashPin(pin) {
  const data = new TextEncoder().encode('filtredns_salt_' + pin);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function genId() { return crypto.randomUUID().slice(0, 8); }

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

// ── AdGuard Home API ─────────────────────────────────────────

async function agFetch(env, path, method = 'GET', body = null) {
  const url = (env.ADGUARD_URL || 'http://89.168.40.235:3000') + path;
  const auth = btoa(`${env.ADGUARD_USER || 'admin'}:${env.ADGUARD_PASS || 'admin'}`);
  const opts = { method, headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (method === 'GET') return res.json();
  return res;
}

// Parse AdGuard custom rules to extract domains per optional category
async function getOptionalDomains(env) {
  const data = await agFetch(env, '/control/filtering/status');
  const rules = data.user_rules || [];
  const cats = {};
  let currentCat = null;

  for (const rule of rules) {
    // Check if line is a category marker
    for (const [key, marker] of Object.entries(CAT_MARKERS)) {
      if (rule.startsWith(marker)) { currentCat = key; cats[key] = []; break; }
    }
    // If we're in an optional category and line is a rule
    if (currentCat && rule.startsWith('||') && rule.endsWith('^')) {
      cats[currentCat].push(rule); // e.g., ||domain.com^
    }
    // Empty line or new mandatory category resets
    if (rule.startsWith('# === Pornographie') || rule.startsWith('# === Webcams') ||
        rule.startsWith('# === Hentai') || rule.startsWith('# === IA suggestive') ||
        rule.startsWith('# === Tor')) {
      currentCat = null;
    }
  }
  return cats;
}

// Add @@ allow rules for a user's optional categories
async function addAllowRules(env, userId, categories) {
  const domains = await getOptionalDomains(env);
  const data = await agFetch(env, '/control/filtering/status');
  let rules = data.user_rules || [];

  for (const cat of categories) {
    if (cat === 'yt_safesearch') continue; // handled via client API
    const catDomains = domains[cat] || [];
    for (const domain of catDomains) {
      // ||domain.com^ → @@||domain.com^$client=userId
      const allowRule = `@@${domain}$client=${userId}`;
      if (!rules.includes(allowRule)) rules.push(allowRule);
    }
  }

  await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
}

// Remove @@ allow rules for a specific category for a user
async function removeAllowRules(env, userId, category) {
  if (category === 'yt_safesearch') return;
  const domains = await getOptionalDomains(env);
  const catDomains = domains[category] || [];
  const data = await agFetch(env, '/control/filtering/status');
  let rules = data.user_rules || [];

  const toRemove = new Set(catDomains.map(d => `@@${d}$client=${userId}`));
  rules = rules.filter(r => !toRemove.has(r));

  await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
}

// Re-add @@ allow rules for a category (parrain unblocking)
async function reAddAllowRules(env, userId, category) {
  if (category === 'yt_safesearch') return;
  await addAllowRules(env, userId, [category]);
}

// Create AdGuard client
async function createAGClient(env, userId) {
  try {
    await agFetch(env, '/control/clients/add', 'POST', {
      name: userId, ids: [userId],
      use_global_settings: true, use_global_blocked_services: true,
      filtering_enabled: true, safebrowsing_enabled: true, parental_enabled: true
    });
  } catch (e) { /* client may already exist */ }
}

// Toggle YouTube SafeSearch per client
async function setYTSafeSearch(env, userId, enabled) {
  const data = await agFetch(env, '/control/clients');
  const client = data.clients?.find(c => c.name === userId);
  if (!client) return;
  await agFetch(env, '/control/clients/update', 'POST', {
    name: userId,
    data: { ...client, use_global_settings: false,
      safesearch: { enabled: true, bing: true, duckduckgo: true, ecosia: true,
        google: true, pixabay: true, yandex: true, youtube: enabled }
    }
  });
}

// ── API Routes ───────────────────────────────────────────────

async function handleAPI(request, url, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: {
      'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST',
      'Access-Control-Allow-Headers': 'Content-Type'
    }});
  }

  const db = env.DB;

  try {
    // ── FILLEUL : Créer un profil ────────────────────────────
    if (url.pathname === '/api/register' && request.method === 'POST') {
      const { name } = await request.json();
      const id = name.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!id || id.length < 2 || id.length > 20) return jsonRes({ error: 'Prénom invalide' }, 400);

      // Check duplicate
      const existing = await db.prepare('SELECT id FROM users WHERE id = ?').bind(id).first();
      if (existing) {
        // Suggest alternative
        let alt = id + '2';
        let n = 2;
        while (await db.prepare('SELECT id FROM users WHERE id = ?').bind(alt).first()) {
          n++; alt = id + n;
        }
        return jsonRes({ error: `Ce prénom est déjà pris. Essaie "${alt}"`, suggestion: alt }, 409);
      }

      const inviteCode = id.toUpperCase().slice(0, 4) + '-' + genCode();
      const hostname = `${id}.dns.rpisimon.uk`;

      await db.prepare('INSERT INTO users (id, display_name, hostname, invite_code) VALUES (?, ?, ?, ?)')
        .bind(id, name, hostname, inviteCode).run();

      // Create AdGuard client + add allow rules for all optional categories
      await createAGClient(env, id);
      await addAllowRules(env, id, OPTIONAL_CATS.filter(c => c !== 'yt_safesearch'));

      // Init category prefs (all unblocked by default)
      for (const cat of OPTIONAL_CATS) {
        await db.prepare('INSERT INTO user_categories (user_id, category, blocked, locked_by) VALUES (?, ?, 0, NULL)')
          .bind(id, cat).run();
      }

      return jsonRes({ id, hostname, invite_code: inviteCode });
    }

    // ── FILLEUL : Récupérer profil ───────────────────────────
    if (url.pathname === '/api/profile' && request.method === 'GET') {
      const id = url.searchParams.get('id');
      if (!id) return jsonRes({ error: 'ID manquant' }, 400);

      const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
      if (!user) return jsonRes({ error: 'Profil introuvable' }, 404);

      const cats = await db.prepare('SELECT * FROM user_categories WHERE user_id = ?').bind(id).all();
      const parrain = user.parrain_id
        ? await db.prepare('SELECT display_name FROM parrains WHERE id = ?').bind(user.parrain_id).first()
        : null;

      return jsonRes({
        id: user.id, name: user.display_name, hostname: user.hostname,
        invite_code: user.parrain_id ? null : user.invite_code,
        parrain: parrain?.display_name || null,
        has_parrain: !!user.parrain_id,
        categories: Object.fromEntries((cats.results || []).map(c => [c.category, {
          ...CAT_LABELS[c.category], blocked: !!c.blocked, locked_by: c.locked_by
        }])),
        mandatory: MANDATORY_CATS
      });
    }

    // ── FILLEUL : Activer une catégorie (sens unique) ────────
    if (url.pathname === '/api/toggle' && request.method === 'POST') {
      const { user_id, category } = await request.json();
      if (!user_id || !OPTIONAL_CATS.includes(category)) return jsonRes({ error: 'Paramètres invalides' }, 400);

      const current = await db.prepare('SELECT * FROM user_categories WHERE user_id = ? AND category = ?')
        .bind(user_id, category).first();
      if (!current) return jsonRes({ error: 'Catégorie introuvable' }, 404);
      if (current.blocked) return jsonRes({ error: 'Déjà bloquée — seul ton parrain peut la débloquer' }, 403);

      // Block it (one-way)
      await db.prepare('UPDATE user_categories SET blocked = 1, locked_by = ?, updated_at = datetime(?) WHERE user_id = ? AND category = ?')
        .bind('user', new Date().toISOString(), user_id, category).run();

      // Remove allow rules in AdGuard
      if (category === 'yt_safesearch') {
        await setYTSafeSearch(env, user_id, true);
      } else {
        await removeAllowRules(env, user_id, category);
      }

      return jsonRes({ ok: true });
    }

    // ── FILLEUL : Proposer une URL à bloquer ─────────────────
    if (url.pathname === '/api/suggest' && request.method === 'POST') {
      const { user_id, url: suggestedUrl, category, category_other } = await request.json();
      if (!user_id || !suggestedUrl) return jsonRes({ error: 'Données manquantes' }, 400);

      // Nettoyer l'URL : extraire le domaine
      let domain = suggestedUrl.trim().toLowerCase();
      domain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split('?')[0];
      if (!domain || !domain.includes('.')) return jsonRes({ error: 'URL invalide' }, 400);

      // Vérifier que l'utilisateur existe
      const user = await db.prepare('SELECT id FROM users WHERE id = ?').bind(user_id).first();
      if (!user) return jsonRes({ error: 'Profil introuvable' }, 404);

      // Enregistrer la suggestion en base
      await db.prepare('INSERT INTO suggestions (user_id, url, category, category_other) VALUES (?, ?, ?, ?)')
        .bind(user_id, domain, category || 'autre', category_other || null).run();

      // Ajouter directement dans AdGuard Home (pas de validation nécessaire)
      const adguardRule = `||${domain}^`;
      try {
        const data = await agFetch(env, '/control/filtering/status');
        let rules = data.user_rules || [];
        if (!rules.includes(adguardRule)) {
          // Ajouter avec un commentaire pour traçabilité
          rules.push(`# Ajouté par ${user_id} le ${new Date().toISOString().split('T')[0]}`);
          rules.push(adguardRule);
          await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
        }
      } catch (e) {
        return jsonRes({ error: 'Ajout au DNS échoué : ' + e.message }, 500);
      }

      return jsonRes({ ok: true, domain });
    }

    // ── PARRAIN : S'inscrire via code d'invitation ───────────
    if (url.pathname === '/api/parrain/register' && request.method === 'POST') {
      const { invite_code, name, pin } = await request.json();
      if (!invite_code || !name || !pin || pin.length < 4) return jsonRes({ error: 'Données manquantes' }, 400);

      const user = await db.prepare('SELECT * FROM users WHERE invite_code = ? AND parrain_id IS NULL')
        .bind(invite_code.toUpperCase()).first();
      if (!user) return jsonRes({ error: "Code d'invitation invalide ou déjà utilisé" }, 404);

      const parrainId = 'p_' + genId();
      const pinHash = await hashPin(pin);

      await db.prepare('INSERT INTO parrains (id, display_name, pin_hash) VALUES (?, ?, ?)')
        .bind(parrainId, name, pinHash).run();
      await db.prepare('UPDATE users SET parrain_id = ?, invite_code = NULL WHERE id = ?')
        .bind(parrainId, user.id).run();

      return jsonRes({ ok: true, parrain_id: parrainId, filleul: user.display_name });
    }

    // ── PARRAIN : Connexion ──────────────────────────────────
    if (url.pathname === '/api/parrain/login' && request.method === 'POST') {
      const { name, pin } = await request.json();
      if (!name || !pin) return jsonRes({ error: 'Données manquantes' }, 400);

      const pinHash = await hashPin(pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE display_name = ? AND pin_hash = ?')
        .bind(name, pinHash).first();
      if (!parrain) return jsonRes({ error: 'Nom ou code incorrect' }, 401);

      const filleuls = await db.prepare('SELECT id, display_name, hostname, created_at FROM users WHERE parrain_id = ?')
        .bind(parrain.id).all();

      return jsonRes({ ok: true, parrain_id: parrain.id, name: parrain.display_name,
        filleuls: filleuls.results || [] });
    }

    // ── PARRAIN : Voir un filleul ────────────────────────────
    if (url.pathname === '/api/parrain/filleul' && request.method === 'GET') {
      const parrainId = url.searchParams.get('parrain_id');
      const userId = url.searchParams.get('user_id');

      const user = await db.prepare('SELECT * FROM users WHERE id = ? AND parrain_id = ?')
        .bind(userId, parrainId).first();
      if (!user) return jsonRes({ error: 'Filleul introuvable ou non associé' }, 404);

      const cats = await db.prepare('SELECT * FROM user_categories WHERE user_id = ?').bind(userId).all();

      // Get stats from AdGuard
      let stats = { blocked: 0, total: 0 };
      try {
        const agStats = await agFetch(env, '/control/stats');
        stats.blocked = agStats.num_blocked_filtering || 0;
        stats.total = agStats.num_dns_queries || 0;
      } catch (e) {}

      return jsonRes({
        id: user.id, name: user.display_name, hostname: user.hostname,
        categories: Object.fromEntries((cats.results || []).map(c => [c.category, {
          ...CAT_LABELS[c.category], blocked: !!c.blocked, locked_by: c.locked_by
        }])),
        mandatory: MANDATORY_CATS, stats
      });
    }

    // ── PARRAIN : Toggle catégorie d'un filleul (bidirectionnel) ─
    if (url.pathname === '/api/parrain/toggle' && request.method === 'POST') {
      const { parrain_id, pin, user_id, category, blocked } = await request.json();
      if (!parrain_id || !pin || !user_id || !OPTIONAL_CATS.includes(category))
        return jsonRes({ error: 'Paramètres invalides' }, 400);

      // Verify PIN
      const pinHash = await hashPin(pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE id = ? AND pin_hash = ?')
        .bind(parrain_id, pinHash).first();
      if (!parrain) return jsonRes({ error: 'Code incorrect' }, 401);

      // Verify ownership
      const user = await db.prepare('SELECT * FROM users WHERE id = ? AND parrain_id = ?')
        .bind(user_id, parrain_id).first();
      if (!user) return jsonRes({ error: 'Filleul non associé' }, 403);

      await db.prepare('UPDATE user_categories SET blocked = ?, locked_by = ?, updated_at = datetime(?) WHERE user_id = ? AND category = ?')
        .bind(blocked ? 1 : 0, 'parrain', new Date().toISOString(), user_id, category).run();

      if (category === 'yt_safesearch') {
        await setYTSafeSearch(env, user_id, blocked);
      } else if (blocked) {
        await removeAllowRules(env, user_id, category);
      } else {
        await reAddAllowRules(env, user_id, category);
      }

      return jsonRes({ ok: true });
    }

    // ── PARRAIN : Changer son PIN ────────────────────────────
    if (url.pathname === '/api/parrain/change-pin' && request.method === 'POST') {
      const { parrain_id, old_pin, new_pin } = await request.json();
      if (!parrain_id || !old_pin || !new_pin || new_pin.length < 4)
        return jsonRes({ error: 'Données manquantes' }, 400);

      const oldHash = await hashPin(old_pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE id = ? AND pin_hash = ?')
        .bind(parrain_id, oldHash).first();
      if (!parrain) return jsonRes({ error: 'Ancien code incorrect' }, 401);

      const newHash = await hashPin(new_pin);
      await db.prepare('UPDATE parrains SET pin_hash = ? WHERE id = ?').bind(newHash, parrain_id).run();

      return jsonRes({ ok: true });
    }

    return jsonRes({ error: 'Route inconnue' }, 404);
  } catch (err) {
    return jsonRes({ error: err.message }, 500);
  }
}

// ── HTML Frontend ────────────────────────────────────────────

function HTML() {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FiltresDNS</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono&display=swap" rel="stylesheet">
<style>
:root{--bg:#0c0f14;--bg2:#151921;--bg3:#1c2230;--tx:#e4e7ed;--tx2:#7c839a;--tx3:#52566a;--g:#22c55e;--g2:#16a34a;--r:#ef4444;--am:#f59e0b;--bd:rgba(255,255,255,0.08);--rd:12px}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'DM Sans',sans-serif;min-height:100vh}
.c{max-width:500px;margin:0 auto;padding:2rem 1rem}
.hd{text-align:center;margin-bottom:1.5rem}
.hd h1{font-size:1.5rem;font-weight:600}
.hd p{color:var(--tx2);font-size:.82rem;margin-top:.3rem}
.bx{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--rd);padding:1.5rem;margin-bottom:1rem}
input[type=text],input[type=password]{width:100%;padding:11px 14px;border-radius:8px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx);font-family:'DM Sans';font-size:.95rem;outline:0;margin-bottom:8px}
input:focus{border-color:var(--g)}
input::placeholder{color:var(--tx3)}
.btn{width:100%;padding:11px;border-radius:8px;border:none;background:var(--g);color:#fff;font-family:'DM Sans';font-size:.92rem;font-weight:600;cursor:pointer}
.btn:hover{background:var(--g2)}
.btn2{background:transparent;border:1px solid var(--bd);color:var(--tx2)}
.btn2:hover{border-color:var(--tx2);color:var(--tx)}
.btn-r{background:var(--r)}
.btn-r:hover{background:#dc2626}
.st{font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:var(--tx3);font-weight:500;margin-bottom:8px;padding-left:2px}
.cd{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--rd);padding:11px 13px;margin-bottom:5px;display:flex;align-items:center;gap:10px}
.cd:hover{border-color:rgba(255,255,255,.15)}
.cd .i{font-size:1.2rem;width:28px;text-align:center;flex-shrink:0}
.cd .inf{flex:1;min-width:0}
.cd .nm{font-size:.88rem;font-weight:500}
.cd .ds{font-size:.72rem;color:var(--tx2);margin-top:1px}
.badge{font-size:.68rem;padding:2px 8px;border-radius:4px;font-weight:600;white-space:nowrap}
.badge-r{background:rgba(239,68,68,.15);color:var(--r)}
.badge-g{background:rgba(34,197,94,.15);color:var(--g)}
.badge-a{background:rgba(245,158,11,.15);color:var(--am)}
.tg{position:relative;width:40px;height:22px;flex-shrink:0}
.tg input{opacity:0;width:0;height:0;position:absolute}
.tg-s{position:absolute;inset:0;background:var(--bg3);border-radius:11px;cursor:pointer;transition:.25s;border:1px solid var(--bd)}
.tg-s::before{content:'';position:absolute;width:16px;height:16px;left:2px;top:2px;background:var(--tx2);border-radius:50%;transition:.25s}
.tg input:checked+.tg-s{background:var(--g);border-color:var(--g)}
.tg input:checked+.tg-s::before{transform:translateX(18px);background:#fff}
.tg input:disabled+.tg-s{opacity:.4;cursor:not-allowed}
.host{font-family:'DM Mono',monospace;font-size:.95rem;color:var(--g);background:var(--bg3);padding:7px 14px;border-radius:6px;display:inline-block;cursor:pointer}
.or{text-align:center;color:var(--tx3);font-size:.78rem;margin:8px 0}
.hint{font-size:.72rem;color:var(--tx3);margin-top:6px;text-align:center}
.setup{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--rd);padding:1rem;font-size:.8rem;color:var(--tx2);line-height:1.6;margin-top:1rem}
.setup h3{color:var(--tx);font-size:.85rem;margin-bottom:5px;font-weight:500}
.setup ol{padding-left:1.1rem}
.setup code{font-family:'DM Mono';font-size:.75rem;background:var(--bg3);padding:1px 5px;border-radius:3px;color:var(--g)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:1rem}
.stat{background:var(--bg3);border-radius:8px;padding:10px;text-align:center}
.stat .n{font-size:1.2rem;font-weight:500}
.stat .l{font-size:.68rem;color:var(--tx3);margin-top:2px}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:var(--bg2);border:1px solid var(--bd);border-radius:var(--rd);padding:1.5rem;max-width:360px;width:90%;text-align:center}
.modal h3{font-size:1rem;font-weight:500;margin-bottom:.8rem}
.modal p{font-size:.85rem;color:var(--tx2);margin-bottom:1rem;line-height:1.5}
.modal .btns{display:flex;gap:8px}
.modal .btns .btn{flex:1}
.back{font-size:.82rem;color:var(--tx2);cursor:pointer;margin-bottom:1rem;display:inline-block}
.back:hover{color:var(--tx)}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="c">
  <div class="hd"><h1>🛡️ FiltresDNS</h1><p>Filtrage DNS personnel</p></div>
  <div id="app"></div>
</div>

<div class="modal-bg" id="confirmModal">
  <div class="modal">
    <h3 id="confirmTitle"></h3>
    <p id="confirmMsg"></p>
    <input type="password" id="confirmPin" placeholder="Code secret du parrain" class="hidden" style="margin-bottom:12px"/>
    <div class="btns">
      <button class="btn btn2" onclick="closeModal()">Annuler</button>
      <button class="btn" id="confirmBtn" onclick="confirmAction()">Confirmer</button>
    </div>
  </div>
</div>

<script>
const API = '/api';
let state = { screen: 'home', user: null, parrain: null, filleulDetail: null };
let pendingAction = null;

function $(id) { return document.getElementById(id); }

function render() {
  const app = $('app');
  switch(state.screen) {
    case 'home': app.innerHTML = homeScreen(); break;
    case 'register': app.innerHTML = registerScreen(); break;
    case 'profile': app.innerHTML = profileScreen(); break;
    case 'parrain_login': app.innerHTML = parrainLoginScreen(); break;
    case 'parrain_invite': app.innerHTML = parrainInviteScreen(); break;
    case 'parrain_dashboard': app.innerHTML = parrainDashScreen(); break;
    case 'parrain_detail': app.innerHTML = parrainDetailScreen(); break;
  }
}

// ── Screens ─────────────────────────────────────────────────

function homeScreen() {
  return \`<div class="bx" style="text-align:center">
    <h3 style="font-size:1.05rem;margin-bottom:1rem">Bienvenue</h3>
    <button class="btn" onclick="go('register')" style="margin-bottom:8px">Créer mon profil</button>
    <button class="btn btn2" onclick="go('parrain_login')" style="margin-bottom:8px">Je suis parrain</button>
    <div class="or">— ou —</div>
    <div style="margin-top:8px">
      <p style="font-size:.82rem;color:var(--tx2);margin-bottom:8px">Utiliser le DNS de base (tout bloqué, sans profil) :</p>
      <div class="host">dns.rpisimon.uk</div>
    </div>
    <div class="hint" style="margin-top:12px">Le DNS de base bloque toutes les catégories par défaut. Crée un profil pour personnaliser.</div>
  </div>
  <div class="bx" style="text-align:center">
    <p style="font-size:.82rem;color:var(--tx2);margin-bottom:6px">Tu as déjà un profil ?</p>
    <input type="text" id="loginId" placeholder="Ton identifiant" />
    <button class="btn btn2" onclick="loginUser()">Accéder à mon profil</button>
  </div>\`;
}

function registerScreen() {
  return \`<span class="back" onclick="go('home')">← Retour</span>
  <div class="bx">
    <h3 style="font-size:1rem;margin-bottom:1rem;text-align:center">Créer mon profil</h3>
    <input type="text" id="regName" placeholder="Ton prénom (sans accent)" />
    <div class="hint" style="margin-bottom:12px">Ce prénom sera ton identifiant. Ex: paul, marc, lucas</div>
    <button class="btn" onclick="registerUser()">Créer</button>
  </div>\`;
}

function profileScreen() {
  const u = state.user;
  if (!u) return '';
  let catsHtml = '';
  for (const [key, cat] of Object.entries(u.categories || {})) {
    const locked = cat.blocked && cat.locked_by;
    const lockInfo = locked ? (cat.locked_by === 'user' ? 'Activé par toi · verrouillé' : 'Géré par ton parrain') : 'Non activé';
    catsHtml += \`<div class="cd">
      <div class="i">\${CAT_LABELS[key]?.icon||''}</div>
      <div class="inf"><div class="nm">\${cat.name}</div><div class="ds">\${lockInfo}</div></div>
      <label class="tg"><input type="checkbox" \${cat.blocked?'checked':''} \${locked?'disabled':''}
        onchange="userToggle('\${key}',this)" /><span class="tg-s"></span></label>
    </div>\`;
  }

  const inviteHtml = u.has_parrain
    ? \`<div class="cd"><div class="inf"><div class="nm">Parrain : \${u.parrain}</div></div><span class="badge badge-g">Associé</span></div>\`
    : \`<div class="cd" style="cursor:pointer" onclick="copyInvite()">
        <div class="inf"><div class="nm">Code d'invitation</div><div class="ds">Envoie ce code à ton parrain</div></div>
        <span class="host" style="font-size:.8rem">\${u.invite_code}</span>
      </div>\`;

  return \`<span class="back" onclick="state.user=null;go('home')">← Déconnexion</span>
  <div style="text-align:center;margin-bottom:1rem">
    <div class="host" onclick="navigator.clipboard.writeText('\${u.hostname}')" style="cursor:pointer">\${u.hostname}</div>
    <div class="hint">Tape dans DNS Privé Android · clique pour copier</div>
  </div>
  \${inviteHtml}
  <div style="margin-top:1rem"><div class="st">Catégories toujours actives</div>
  \${u.mandatory.map(m=>\`<div class="cd"><div class="i">\${m.icon}</div><div class="inf"><div class="nm">\${m.name}</div><div class="ds">\${m.count} domaines</div></div><span class="badge badge-r">Obligatoire</span></div>\`).join('')}
  </div>
  <div style="margin-top:1rem"><div class="st">Catégories optionnelles</div>\${catsHtml}</div>
  <div style="margin-top:1rem"><div class="st">Proposer un site à bloquer</div>
    <div class="bx">
      <input type="text" id="suggestUrl" placeholder="URL du site (ex: exemple.com)" />
      <select id="suggestCat" style="width:100%;padding:11px 14px;border-radius:8px;border:1px solid var(--bd);background:var(--bg3);color:var(--tx);font-family:'DM Sans';font-size:.92rem;margin-bottom:8px;outline:0">
        <option value="" disabled selected>Catégorie du site</option>
        <option value="adulte">Contenus pour adultes</option>
        <option value="webcam">Webcams adultes</option>
        <option value="hentai">Hentai / Comics adultes</option>
        <option value="ia_nsfw">IA suggestive / NSFW</option>
        <option value="manga">Manga / Webtoon / Scantrad</option>
        <option value="gambling">Jeux d'argent / Paris sportifs</option>
        <option value="search">Moteurs de recherche</option>
        <option value="ai_mixed">IA mixtes</option>
        <option value="tor">Tor / Anonymisation</option>
        <option value="autre">Autre (préciser ci-dessous)</option>
      </select>
      <input type="text" id="suggestOther" placeholder="Précise le type de site (si Autre)" style="display:none" />
      <button class="btn" onclick="suggestSite()">Ajouter au filtre</button>
      <div class="hint">Le site sera bloqué immédiatement pour tous les utilisateurs.</div>
    </div>
  </div>
  <div class="setup"><h3>📱 Installation (30 secondes)</h3><ol>
    <li><strong>Paramètres</strong> → <strong>Réseau et Internet</strong> → <strong>DNS Privé</strong></li>
    <li>Nom d'hôte : <code>\${u.hostname}</code></li>
    <li>Sauvegarder → <strong>Redémarrer le téléphone</strong></li>
  </ol></div>\`;
}

function parrainLoginScreen() {
  return \`<span class="back" onclick="go('home')">← Retour</span>
  <div class="bx" style="text-align:center">
    <h3 style="font-size:1rem;margin-bottom:1rem">Je suis parrain</h3>
    <input type="text" id="pName" placeholder="Mon prénom" />
    <input type="password" id="pPin" placeholder="Mon code secret" />
    <button class="btn" onclick="parrainLogin()" style="margin-bottom:8px">Accéder</button>
    <div class="or">— ou —</div>
    <button class="btn btn2" onclick="go('parrain_invite')">J'ai un code d'invitation</button>
    <div class="hint" style="margin-top:10px"><a href="mailto:simon.deboeuf.1@gmail.com?subject=FiltresDNS%20-%20PIN%20oubli%C3%A9&body=Bonjour%2C%20j%27ai%20oubli%C3%A9%20mon%20code%20secret%20parrain.%20Mon%20pr%C3%A9nom%20%3A%20" style="color:var(--am);text-decoration:none">PIN oublié ? Contacter l'admin</a></div>
  </div>\`;
}

function parrainInviteScreen() {
  return \`<span class="back" onclick="go('parrain_login')">← Retour</span>
  <div class="bx" style="text-align:center">
    <h3 style="font-size:1rem;margin-bottom:1rem">Devenir parrain</h3>
    <input type="text" id="invCode" placeholder="Code d'invitation (ex: PAUL-7X3K)" style="font-family:'DM Mono';text-align:center;letter-spacing:2px" />
    <input type="text" id="invName" placeholder="Mon prénom" />
    <input type="password" id="invPin1" placeholder="Choisis un code secret (4+ chiffres)" />
    <input type="password" id="invPin2" placeholder="Confirme le code secret" />
    <button class="btn" onclick="parrainRegister()">Devenir parrain</button>
  </div>\`;
}

function parrainDashScreen() {
  const p = state.parrain;
  if (!p) return '';
  return \`<span class="back" onclick="state.parrain=null;go('home')">← Déconnexion</span>
  <div style="text-align:center;margin-bottom:1rem">
    <div style="font-size:1.1rem;font-weight:500">\${p.name}</div>
    <div style="font-size:.78rem;color:var(--tx2)">Espace parrain</div>
  </div>
  <div class="st">Mes filleuls</div>
  \${(p.filleuls||[]).map(f=>\`<div class="cd" style="cursor:pointer" onclick="viewFilleul('\${f.id}')">
    <div class="inf"><div class="nm">\${f.display_name}</div><div class="ds">\${f.hostname}</div></div>
    <span style="color:var(--tx2);font-size:.85rem">→</span>
  </div>\`).join('')||'<div class="hint">Aucun filleul associé pour l\\'instant</div>'}
  <button class="btn btn2" onclick="changePin()" style="margin-top:1rem">Changer mon code secret</button>\`;
}

function parrainDetailScreen() {
  const f = state.filleulDetail;
  if (!f) return '';
  let catsHtml = '';
  for (const [key, cat] of Object.entries(f.categories || {})) {
    const info = cat.blocked ? (cat.locked_by === 'user' ? 'Activé par le filleul' : 'Activé par toi') : 'Non activé';
    catsHtml += \`<div class="cd">
      <div class="i">\${CAT_LABELS[key]?.icon||''}</div>
      <div class="inf"><div class="nm">\${cat.name}</div><div class="ds">\${info}</div></div>
      <label class="tg"><input type="checkbox" \${cat.blocked?'checked':''}
        onchange="parrainToggle('\${key}',this.checked,this)" /><span class="tg-s"></span></label>
    </div>\`;
  }
  const pct = f.stats.total > 0 ? ((f.stats.blocked/f.stats.total)*100).toFixed(1) : '0';
  return \`<span class="back" onclick="go('parrain_dashboard')">← Retour</span>
  <div style="text-align:center;margin-bottom:1rem">
    <div style="font-size:1.1rem;font-weight:500">\${f.name}</div>
    <div style="font-family:'DM Mono';font-size:.85rem;color:var(--g)">\${f.hostname}</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="n">\${f.stats.blocked.toLocaleString()}</div><div class="l">Bloquées</div></div>
    <div class="stat"><div class="n">\${f.stats.total.toLocaleString()}</div><div class="l">Total</div></div>
    <div class="stat"><div class="n">\${pct}%</div><div class="l">Taux</div></div>
  </div>
  <div class="st">Catégories obligatoires</div>
  \${f.mandatory.map(m=>\`<div class="cd"><div class="i">\${m.icon}</div><div class="inf"><div class="nm">\${m.name}</div></div><span class="badge badge-r">Obligatoire</span></div>\`).join('')}
  <div style="margin-top:1rem"><div class="st">Catégories optionnelles</div>\${catsHtml}</div>\`;
}

// ── CAT_LABELS reference for frontend ────────────────────────
const CAT_LABELS = ${JSON.stringify(CAT_LABELS)};

// ── Actions ──────────────────────────────────────────────────

function go(screen) { state.screen = screen; render(); }

async function registerUser() {
  const name = $('regName')?.value?.trim();
  if (!name) return alert('Remplis ton prénom');
  const res = await fetch(API+'/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name}) });
  const data = await res.json();
  if (data.error) { alert(data.error + (data.suggestion ? ' → '+data.suggestion : '')); return; }
  // Load profile
  const pRes = await fetch(API+'/profile?id='+data.id);
  state.user = await pRes.json();
  localStorage.setItem('fdns_id', data.id);
  go('profile');
}

async function loginUser() {
  const id = $('loginId')?.value?.trim()?.toLowerCase();
  if (!id) return;
  const res = await fetch(API+'/profile?id='+id);
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  state.user = data;
  localStorage.setItem('fdns_id', id);
  go('profile');
}

function userToggle(cat, el) {
  el.checked = false; // Reset until confirmed
  pendingAction = { type: 'user_toggle', cat, el };
  $('confirmTitle').textContent = 'Activer le blocage ?';
  $('confirmMsg').textContent = CAT_LABELS[cat].name + ' sera bloqué. Seul ton parrain pourra le débloquer.';
  $('confirmPin').classList.add('hidden');
  $('confirmBtn').classList.remove('btn-r');
  $('confirmModal').classList.add('show');
}

async function confirmAction() {
  closeModal();
  if (!pendingAction) return;
  const a = pendingAction;
  pendingAction = null;

  if (a.type === 'user_toggle') {
    const res = await fetch(API+'/toggle', { method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ user_id: state.user.id, category: a.cat }) });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    // Reload profile
    const pRes = await fetch(API+'/profile?id='+state.user.id);
    state.user = await pRes.json();
    render();
  }

  if (a.type === 'parrain_toggle') {
    const pin = $('confirmPin').value;
    if (!pin) { alert('Code secret requis'); return; }
    const res = await fetch(API+'/parrain/toggle', { method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ parrain_id: state.parrain.parrain_id, pin, user_id: state.filleulDetail.id, category: a.cat, blocked: a.blocked }) });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    await viewFilleul(state.filleulDetail.id);
  }
}

function parrainToggle(cat, blocked, el) {
  el.checked = !blocked; // Reset until confirmed
  const action = blocked ? 'activer le blocage de' : 'désactiver le blocage de';
  pendingAction = { type: 'parrain_toggle', cat, blocked };
  $('confirmTitle').textContent = 'Confirmation requise';
  $('confirmMsg').textContent = 'Tu vas ' + action + ' "' + CAT_LABELS[cat].name + '" pour ' + state.filleulDetail.name + '. Entre ton code secret pour confirmer.';
  $('confirmPin').classList.remove('hidden');
  $('confirmPin').value = '';
  $('confirmBtn').classList.toggle('btn-r', !blocked);
  $('confirmModal').classList.add('show');
  setTimeout(() => $('confirmPin').focus(), 100);
}

function closeModal() { $('confirmModal').classList.remove('show'); $('confirmPin').value = ''; }

async function suggestSite() {
  const urlInput = $('suggestUrl');
  const catSelect = $('suggestCat');
  const otherInput = $('suggestOther');
  if (!urlInput || !catSelect) return;
  const url = urlInput.value.trim();
  const cat = catSelect.value;
  const other = otherInput?.value?.trim() || '';
  if (!url) return alert('Entre une URL');
  if (!cat) return alert('Choisis une catégorie');
  if (cat === 'autre' && !other) return alert('Précise le type de site');

  const res = await fetch(API+'/suggest', { method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ user_id: state.user.id, url, category: cat, category_other: other }) });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  alert(data.domain + ' a été ajouté au filtre !');
  urlInput.value = '';
  catSelect.value = '';
  if (otherInput) { otherInput.value = ''; otherInput.style.display = 'none'; }
}

// Show/hide "Autre" text field based on category selection
document.addEventListener('change', function(e) {
  if (e.target.id === 'suggestCat') {
    const otherInput = $('suggestOther');
    if (otherInput) otherInput.style.display = e.target.value === 'autre' ? 'block' : 'none';
  }
});

async function parrainLogin() {
  const name = $('pName')?.value?.trim();
  const pin = $('pPin')?.value;
  if (!name || !pin) return alert('Remplis tout');
  const res = await fetch(API+'/parrain/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,pin}) });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  state.parrain = data;
  go('parrain_dashboard');
}

async function parrainRegister() {
  const code = $('invCode')?.value?.trim();
  const name = $('invName')?.value?.trim();
  const pin1 = $('invPin1')?.value;
  const pin2 = $('invPin2')?.value;
  if (!code || !name || !pin1) return alert('Remplis tout');
  if (pin1 !== pin2) return alert('Les codes ne correspondent pas');
  if (pin1.length < 4) return alert('Code secret trop court (4 chiffres minimum)');
  const res = await fetch(API+'/parrain/register', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({invite_code:code,name,pin:pin1}) });
  const data = await res.json();
  if (data.error) { alert(data.error); return; }
  alert('Tu es maintenant parrain de ' + data.filleul + ' !');
  // Auto-login
  const lRes = await fetch(API+'/parrain/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name,pin:pin1}) });
  state.parrain = await lRes.json();
  go('parrain_dashboard');
}

async function viewFilleul(userId) {
  const res = await fetch(API+'/parrain/filleul?parrain_id='+state.parrain.parrain_id+'&user_id='+userId);
  state.filleulDetail = await res.json();
  go('parrain_detail');
}

async function changePin() {
  const old = prompt('Ancien code secret :');
  if (!old) return;
  const nw = prompt('Nouveau code secret (4+ chiffres) :');
  if (!nw || nw.length < 4) return alert('Code trop court');
  const nw2 = prompt('Confirme le nouveau code :');
  if (nw !== nw2) return alert('Les codes ne correspondent pas');
  const res = await fetch(API+'/parrain/change-pin', { method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ parrain_id: state.parrain.parrain_id, old_pin: old, new_pin: nw }) });
  const data = await res.json();
  if (data.error) alert(data.error); else alert('Code secret changé !');
}

function copyInvite() {
  if (state.user?.invite_code) navigator.clipboard.writeText(state.user.invite_code);
}

// Auto-login if saved
const savedId = localStorage.getItem('fdns_id');
if (savedId) {
  fetch(API+'/profile?id='+savedId).then(r=>r.json()).then(d=>{
    if(!d.error){state.user=d;go('profile')}else{localStorage.removeItem('fdns_id');render()}
  }).catch(()=>render());
} else render();
</script>
</body>
</html>`;
}
