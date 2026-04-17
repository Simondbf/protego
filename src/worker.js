// ═══════════════════════════════════════════════════════════════
// FiltresDNS — Worker Cloudflare complet
// Parrain/Filleul · D1 · AdGuard Home API
// ═══════════════════════════════════════════════════════════════

const OPTIONAL_CATS = ['manga', 'gambling', 'search_engines', 'ai_mixed', 'yt_safesearch'];
const MAX_EXCEPTIONS_PER_CAT = 0;
const DOMAIN_DEPENDENCIES = {
  'webtoon.com': ['webtoons.com', 'apis.naver.com'],
  'webtoons.com': ['webtoon.com', 'apis.naver.com'],
};
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

async function getOptionalDomains(env) {
  const data = await agFetch(env, '/control/filtering/status');
  const rules = data.user_rules || [];
  const cats = {};
  let currentCat = null;

  for (const rule of rules) {
    for (const [key, marker] of Object.entries(CAT_MARKERS)) {
      if (rule.startsWith(marker)) { currentCat = key; cats[key] = []; break; }
    }
    if (currentCat && rule.startsWith('||') && rule.endsWith('^')) {
      cats[currentCat].push(rule);
    }
    if (rule.startsWith('# === Pornographie') || rule.startsWith('# === Webcams') ||
        rule.startsWith('# === Hentai') || rule.startsWith('# === IA suggestive') ||
        rule.startsWith('# === Tor')) {
      currentCat = null;
    }
  }
  return cats;
}

async function addAllowRules(env, userId, categories) {
  const domains = await getOptionalDomains(env);
  const data = await agFetch(env, '/control/filtering/status');
  let rules = data.user_rules || [];

  for (const cat of categories) {
    if (cat === 'yt_safesearch') continue;
    const catDomains = domains[cat] || [];
    for (const domain of catDomains) {
      const allowRule = `@@${domain}$client=${userId}`;
      if (!rules.includes(allowRule)) rules.push(allowRule);
    }
  }

  await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
}

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

async function reAddAllowRules(env, userId, category) {
  if (category === 'yt_safesearch') return;
  await addAllowRules(env, userId, [category]);
}

async function addSingleException(env, userId, domain) {
  const data = await agFetch(env, '/control/filtering/status');
  let rules = data.user_rules || [];
  const allowRule = `@@||${domain}^$client=${userId}`;
  if (!rules.includes(allowRule)) {
    rules.push(allowRule);
    await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
  }
}

async function removeSingleException(env, userId, domain) {
  const data = await agFetch(env, '/control/filtering/status');
  let rules = data.user_rules || [];
  const allowRule = `@@||${domain}^$client=${userId}`;
  rules = rules.filter(r => r !== allowRule);
  await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
}

async function createAGClient(env, userId) {
  try {
    await agFetch(env, '/control/clients/add', 'POST', {
      name: userId, ids: [userId],
      use_global_settings: true, use_global_blocked_services: true,
      filtering_enabled: true, safebrowsing_enabled: true, parental_enabled: true
    });
  } catch (e) { /* client may already exist */ }
}

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
    // ── FILLEUL : Créer un profil
    if (url.pathname === '/api/register' && request.method === 'POST') {
      const { name, pin } = await request.json();
      if (!pin || pin.length < 4) return jsonRes({ error: 'Code secret requis (4 chiffres minimum)' }, 400);
      const id = name.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!id || id.length < 2 || id.length > 20) return jsonRes({ error: 'Prénom invalide' }, 400);

      const existing = await db.prepare('SELECT id FROM users WHERE id = ?').bind(id).first();
      if (existing) {
        let alt = id + '2';
        let n = 2;
        while (await db.prepare('SELECT id FROM users WHERE id = ?').bind(alt).first()) {
          n++; alt = id + n;
        }
        return jsonRes({ error: `Ce prénom est déjà pris. Essaie "${alt}"`, suggestion: alt }, 409);
      }

      const inviteCode = id.toUpperCase().slice(0, 4) + '-' + genCode();
      const hostname = `${id}.dns.rpisimon.uk`;

      const userPinHash = await hashPin(pin);
      await db.prepare('INSERT INTO users (id, display_name, hostname, invite_code, pin_hash) VALUES (?, ?, ?, ?, ?)')
        .bind(id, name, hostname, inviteCode, userPinHash).run();

      try {
        await createAGClient(env, id);
        await addAllowRules(env, id, OPTIONAL_CATS.filter(c => c !== 'yt_safesearch'));
      } catch (e) { /* AdGuard API indisponible, on continue */ }

      for (const cat of OPTIONAL_CATS) {
        await db.prepare('INSERT INTO user_categories (user_id, category, blocked, locked_by) VALUES (?, ?, 0, NULL)')
          .bind(id, cat).run();
      }

      return jsonRes({ id, hostname, invite_code: inviteCode });
    }

    // ── FILLEUL : Connexion
    if (url.pathname === '/api/login' && request.method === 'POST') {
      const { id, pin } = await request.json();
      if (!id) return jsonRes({ error: 'Identifiant requis' }, 400);
      const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
      if (!user) return jsonRes({ error: 'Profil introuvable' }, 404);
      if (!user.pin_hash) return jsonRes({ ok: true, id: user.id, needs_pin: true });
      if (!pin) return jsonRes({ error: 'Code secret requis' }, 401);
      const pinHash = await hashPin(pin);
      if (pinHash !== user.pin_hash) return jsonRes({ error: 'Code secret incorrect' }, 401);
      return jsonRes({ ok: true, id: user.id });
    }

    // ── FILLEUL : Changer son code secret
    if (url.pathname === '/api/change-pin' && request.method === 'POST') {
      const { user_id, old_pin, new_pin } = await request.json();
      if (!user_id || !new_pin || new_pin.length < 4) return jsonRes({ error: 'Donnees manquantes' }, 400);
      const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
      if (!user) return jsonRes({ error: 'Profil introuvable' }, 404);
      if (user.pin_hash) {
        if (!old_pin) return jsonRes({ error: 'Ancien code requis' }, 400);
        const oldHash = await hashPin(old_pin);
        if (oldHash !== user.pin_hash) return jsonRes({ error: 'Ancien code incorrect' }, 401);
      }
      const newHash = await hashPin(new_pin);
      await db.prepare('UPDATE users SET pin_hash = ? WHERE id = ?').bind(newHash, user_id).run();
      return jsonRes({ ok: true });
    }

    // ── FILLEUL : Récupérer profil
    if (url.pathname === '/api/profile' && request.method === 'GET') {
      const id = url.searchParams.get('id');
      if (!id) return jsonRes({ error: 'ID manquant' }, 400);

      const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
      if (!user) return jsonRes({ error: 'Profil introuvable' }, 404);

      const cats = await db.prepare('SELECT * FROM user_categories WHERE user_id = ?').bind(id).all();
      const parrain = user.parrain_id
        ? await db.prepare('SELECT display_name FROM parrains WHERE id = ?').bind(user.parrain_id).first()
        : null;

      const exceptions = await db.prepare('SELECT category, approved, COUNT(*) as count FROM user_exceptions WHERE user_id = ? GROUP BY category, approved').bind(id).all();
      const exceptionCounts = {};
      const pendingCounts = {};
      for (const e of (exceptions.results || [])) {
        if (e.approved === 1) exceptionCounts[e.category] = (exceptionCounts[e.category] || 0) + e.count;
        else pendingCounts[e.category] = (pendingCounts[e.category] || 0) + e.count;
      }
      return jsonRes({
        id: user.id, name: user.display_name, hostname: user.hostname, parrain_id: user.parrain_id || null,
        invite_code: user.parrain_id ? null : user.invite_code,
        parrain: parrain?.display_name || null,
        has_parrain: !!user.parrain_id,
        categories: Object.fromEntries((cats.results || []).map(c => [c.category, {
          ...CAT_LABELS[c.category], blocked: !!c.blocked, locked_by: c.locked_by, exceptions: exceptionCounts[c.category] || 0, pending: pendingCounts[c.category] || 0
        }])),
        mandatory: MANDATORY_CATS
      });
    }

    // ── FILLEUL : Activer une catégorie (sens unique)
    if (url.pathname === '/api/toggle' && request.method === 'POST') {
      const { user_id, category } = await request.json();
      if (!user_id || !OPTIONAL_CATS.includes(category)) return jsonRes({ error: 'Paramètres invalides' }, 400);

      const current = await db.prepare('SELECT * FROM user_categories WHERE user_id = ? AND category = ?')
        .bind(user_id, category).first();
      if (!current) return jsonRes({ error: 'Catégorie introuvable' }, 404);
      if (current.blocked) return jsonRes({ error: 'Déjà bloquée — seul ton parrain peut la débloquer' }, 403);

      await db.prepare('UPDATE user_categories SET blocked = 1, locked_by = ?, updated_at = datetime(?) WHERE user_id = ? AND category = ?')
        .bind('user', new Date().toISOString(), user_id, category).run();

      if (category === 'yt_safesearch') {
        await setYTSafeSearch(env, user_id, true);
      } else {
        await removeAllowRules(env, user_id, category);
      }

      return jsonRes({ ok: true });
    }

    // ── FILLEUL : Lister domaines d'une catégorie (pour exceptions)
    if (url.pathname === '/api/category-domains' && request.method === 'GET') {
      const userId = url.searchParams.get('user_id');
      const category = url.searchParams.get('category');
      if (!userId || !category) return jsonRes({ error: 'Param\u00e8tres manquants' }, 400);
      const domains = await getOptionalDomains(env);
      const catDomains = (domains[category] || []).map(d => d.replace('||', '').replace('^', ''));
      const userExceptions = await db.prepare('SELECT domain FROM user_exceptions WHERE user_id = ? AND category = ?').bind(userId, category).all();
      const exceptedDomains = new Set((userExceptions.results || []).map(e => e.domain));
      const pendingExcs = await db.prepare('SELECT domain, approved FROM user_exceptions WHERE user_id = ? AND category = ?').bind(userId, category).all();
      const approvedDomains = new Set((pendingExcs.results || []).filter(e => e.approved === 1).map(e => e.domain));
      const pendingDomains = new Set((pendingExcs.results || []).filter(e => e.approved === 0).map(e => e.domain));
      return jsonRes({ category, domains: catDomains.map(d => ({ domain: d, excepted: approvedDomains.has(d), pending: pendingDomains.has(d) })) });
    }

    // ── FILLEUL : Ajouter/retirer une exception individuelle
    if (url.pathname === '/api/exception' && request.method === 'POST') {
      const { user_id, category, domain, excepted } = await request.json();
      if (!user_id || !category || !domain) return jsonRes({ error: 'Param\u00e8tres manquants' }, 400);
      const cat = await db.prepare('SELECT * FROM user_categories WHERE user_id = ? AND category = ?').bind(user_id, category).first();
      if (!cat || !cat.blocked) return jsonRes({ error: 'Cette cat\u00e9gorie n\'est pas bloqu\u00e9e' }, 400);
      if (excepted) {
        const deps = DOMAIN_DEPENDENCIES[domain] || [];
        const allDomains = [domain, ...deps];
        for (const d of allDomains) {
          await db.prepare('INSERT OR IGNORE INTO user_exceptions (user_id, category, domain, approved) VALUES (?, ?, ?, 0)').bind(user_id, category, d).run();
        }
        return jsonRes({ ok: true, pending: true, message: 'Demande envoy\u00e9e. Ton parrain doit approuver.' });
      } else {
        const deps = DOMAIN_DEPENDENCIES[domain] || [];
        const allDomains = [domain, ...deps];
        for (const d of allDomains) {
          const exc = await db.prepare('SELECT approved FROM user_exceptions WHERE user_id = ? AND category = ? AND domain = ?').bind(user_id, category, d).first();
          if (exc) {
            if (exc.approved === 1) { try { await removeSingleException(env, user_id, d); } catch (e) {} }
            await db.prepare('DELETE FROM user_exceptions WHERE user_id = ? AND category = ? AND domain = ?').bind(user_id, category, d).run();
          }
        }
        return jsonRes({ ok: true });
      }
    }

    // ── FILLEUL : Proposer une URL à bloquer
    if (url.pathname === '/api/suggest' && request.method === 'POST') {
      const { user_id, url: suggestedUrl, category, category_other } = await request.json();
      if (!user_id || !suggestedUrl) return jsonRes({ error: 'Données manquantes' }, 400);

      let domain = suggestedUrl.trim().toLowerCase();
      domain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split('?')[0];
      if (!domain || !domain.includes('.')) return jsonRes({ error: 'URL invalide' }, 400);

      const user = await db.prepare('SELECT id FROM users WHERE id = ?').bind(user_id).first();
      if (!user) return jsonRes({ error: 'Profil introuvable' }, 404);

      await db.prepare('INSERT INTO suggestions (user_id, url, category, category_other) VALUES (?, ?, ?, ?)')
        .bind(user_id, domain, category || 'autre', category_other || null).run();

      const catLabelsMap = { adulte:'Contenus pour adultes', webcam:'Webcams adultes', hentai:'Hentai / Comics adultes', ia_nsfw:'IA suggestive / NSFW', manga:'Manga / Webtoon / Scantrad', gambling:"Jeux d'argent / Paris sportifs", search:'Moteurs de recherche', ai_mixed:'IA mixtes', tor:'Tor / Anonymisation', autre:'Autre' };
      const catLabel = catLabelsMap[category] || category || 'Autre';
      const commentLine = `# Ajout\u00e9 par ${user_id} le ${new Date().toISOString().split('T')[0]} - ${catLabel}${category_other ? ' (' + category_other + ')' : ''}`;
      const adguardRule = `||${domain}^`;
      try {
        const data = await agFetch(env, '/control/filtering/status');
        let rules = data.user_rules || [];
        if (!rules.includes(adguardRule)) {
          rules.push(commentLine);
          rules.push(adguardRule);
          await agFetch(env, '/control/filtering/set_rules', 'POST', { rules });
        }
      } catch (e) {
        return jsonRes({ error: 'Ajout au DNS échoué : ' + e.message }, 500);
      }

      return jsonRes({ ok: true, domain });
    }

    // ── PARRAIN : S'inscrire via code d'invitation
    if (url.pathname === '/api/parrain/register' && request.method === 'POST') {
      const { invite_code, name, pin } = await request.json();
      if (!invite_code || !name || !pin || pin.length < 4) return jsonRes({ error: 'Données manquantes' }, 400);

      const user = await db.prepare('SELECT * FROM users WHERE invite_code = ? AND parrain_id IS NULL')
        .bind(invite_code.toUpperCase()).first();
      if (!user) return jsonRes({ error: "Code d'invitation invalide ou déjà utilisé" }, 404);
      if (name.toLowerCase().replace(/[^a-z0-9]/g, '') === user.id) return jsonRes({ error: "Tu ne peux pas être ton propre parrain" }, 400);

      const parrainId = 'p_' + genId();
      const pinHash = await hashPin(pin);

      await db.prepare('INSERT INTO parrains (id, display_name, pin_hash) VALUES (?, ?, ?)')
        .bind(parrainId, name, pinHash).run();
      await db.prepare('UPDATE users SET parrain_id = ?, invite_code = NULL WHERE id = ?')
        .bind(parrainId, user.id).run();

      return jsonRes({ ok: true, parrain_id: parrainId, filleul: user.display_name });
    }

    // ── PARRAIN : Connexion
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

    // ── PARRAIN : Voir un filleul
    if (url.pathname === '/api/parrain/filleul' && request.method === 'GET') {
      const parrainId = url.searchParams.get('parrain_id');
      const userId = url.searchParams.get('user_id');

      const user = await db.prepare('SELECT * FROM users WHERE id = ? AND parrain_id = ?')
        .bind(userId, parrainId).first();
      if (!user) return jsonRes({ error: 'Filleul introuvable ou non associé' }, 404);

      const cats = await db.prepare('SELECT * FROM user_categories WHERE user_id = ?').bind(userId).all();

      let stats = { blocked: 0, total: 0 };
      try {
        const agStats = await agFetch(env, '/control/stats');
        stats.blocked = agStats.num_blocked_filtering || 0;
        stats.total = agStats.num_dns_queries || 0;
      } catch (e) {}

      const exceps = await db.prepare('SELECT category, domain, approved FROM user_exceptions WHERE user_id = ?').bind(userId).all();
      const excCounts = {}; const pendCounts = {}; const excNames = {};
      for (const e of (exceps.results || [])) {
        if (e.approved === 1) { excCounts[e.category] = (excCounts[e.category]||0) + 1; if (!excNames[e.category]) excNames[e.category] = []; excNames[e.category].push(e.domain); }
        else if (e.approved === 0) { pendCounts[e.category] = (pendCounts[e.category]||0) + 1; }
      }
      return jsonRes({
        id: user.id, name: user.display_name, hostname: user.hostname,
        categories: Object.fromEntries((cats.results || []).map(c => [c.category, {
          ...CAT_LABELS[c.category], blocked: !!c.blocked, locked_by: c.locked_by, exceptions: excCounts[c.category]||0, pending: pendCounts[c.category]||0, exception_domains: excNames[c.category]||[]
        }])),
        mandatory: MANDATORY_CATS, stats
      });
    }

    // ── PARRAIN : Toggle catégorie d'un filleul (bidirectionnel)
    if (url.pathname === '/api/parrain/toggle' && request.method === 'POST') {
      const { parrain_id, pin, user_id, category, blocked } = await request.json();
      if (!parrain_id || !pin || !user_id || !OPTIONAL_CATS.includes(category))
        return jsonRes({ error: 'Paramètres invalides' }, 400);

      const pinHash = await hashPin(pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE id = ? AND pin_hash = ?')
        .bind(parrain_id, pinHash).first();
      if (!parrain) return jsonRes({ error: 'Code incorrect' }, 401);

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

    // ── PARRAIN : Changer son PIN
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

    // \u2500\u2500 PARRAIN : Ajouter une exception pour un filleul (sans limite)
    if (url.pathname === '/api/parrain/exception' && request.method === 'POST') {
      const { parrain_id, pin, user_id, category, domain, excepted } = await request.json();
      if (!parrain_id || !pin || !user_id || !category || !domain) return jsonRes({ error: 'Param\u00e8tres manquants' }, 400);
      const pinHash = await hashPin(pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE id = ? AND pin_hash = ?').bind(parrain_id, pinHash).first();
      if (!parrain) return jsonRes({ error: 'Code PIN incorrect' }, 401);
      const user = await db.prepare('SELECT * FROM users WHERE id = ? AND parrain_id = ?').bind(user_id, parrain_id).first();
      if (!user) return jsonRes({ error: 'Filleul non associ\u00e9' }, 403);
      const cat = await db.prepare('SELECT * FROM user_categories WHERE user_id = ? AND category = ?').bind(user_id, category).first();
      if (!cat || !cat.blocked) return jsonRes({ error: 'Cat\u00e9gorie non bloqu\u00e9e' }, 400);
      const deps = DOMAIN_DEPENDENCIES[domain] || [];
      const allDomains = [domain, ...deps];
      if (excepted) {
        for (const d of allDomains) {
          await db.prepare('INSERT OR REPLACE INTO user_exceptions (user_id, category, domain, approved) VALUES (?, ?, ?, 1)').bind(user_id, category, d).run();
          try { await addSingleException(env, user_id, d); } catch (e) {}
        }
      } else {
        for (const d of allDomains) {
          await db.prepare('DELETE FROM user_exceptions WHERE user_id = ? AND category = ? AND domain = ?').bind(user_id, category, d).run();
          try { await removeSingleException(env, user_id, d); } catch (e) {}
        }
      }
      return jsonRes({ ok: true });
    }

    // \u2500\u2500 PARRAIN : Approuver ou refuser une exception en attente
    if (url.pathname === '/api/parrain/approve' && request.method === 'POST') {
      const { parrain_id, pin, user_id, category, domain, approved } = await request.json();
      if (!parrain_id || !pin || !user_id || !domain) return jsonRes({ error: 'Param\u00e8tres manquants' }, 400);
      const pinHash = await hashPin(pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE id = ? AND pin_hash = ?').bind(parrain_id, pinHash).first();
      if (!parrain) return jsonRes({ error: 'Code PIN incorrect' }, 401);
      const user = await db.prepare('SELECT * FROM users WHERE id = ? AND parrain_id = ?').bind(user_id, parrain_id).first();
      if (!user) return jsonRes({ error: 'Filleul non associ\u00e9' }, 403);
      const deps = DOMAIN_DEPENDENCIES[domain] || [];
      const allDomains = [domain, ...deps];
      if (approved) {
        for (const d of allDomains) {
          await db.prepare('UPDATE user_exceptions SET approved = 1 WHERE user_id = ? AND category = ? AND domain = ?').bind(user_id, category || '', d).run();
          try { await addSingleException(env, user_id, d); } catch (e) {}
        }
      } else {
        for (const d of allDomains) {
          const exc = await db.prepare('SELECT approved FROM user_exceptions WHERE user_id = ? AND domain = ?').bind(user_id, d).first();
          if (exc && exc.approved === 1) { try { await removeSingleException(env, user_id, d); } catch (e) {} }
          await db.prepare('DELETE FROM user_exceptions WHERE user_id = ? AND domain = ?').bind(user_id, d).run();
        }
      }
      return jsonRes({ ok: true });
    }

    // \u2500\u2500 PARRAIN : Lister les demandes en attente
    if (url.pathname === '/api/parrain/pending' && request.method === 'GET') {
      const parrainId = url.searchParams.get('parrain_id');
      if (!parrainId) return jsonRes({ error: 'ID manquant' }, 400);
      const filleuls = await db.prepare('SELECT id FROM users WHERE parrain_id = ?').bind(parrainId).all();
      const userIds = (filleuls.results || []).map(f => f.id);
      let pending = [];
      for (const uid of userIds) {
        const excs = await db.prepare('SELECT * FROM user_exceptions WHERE user_id = ? AND approved = 0').bind(uid).all();
        const userName = await db.prepare('SELECT display_name FROM users WHERE id = ?').bind(uid).first();
        for (const exc of (excs.results || [])) {
          pending.push({ user_id: uid, user_name: userName?.display_name || uid, category: exc.category, domain: exc.domain, created_at: exc.created_at });
        }
      }
      return jsonRes({ pending });
    }

    if (url.pathname === '/api/parrain/revoke-filleul' && request.method === 'POST') {
      const { parrain_id, pin, user_id } = await request.json();
      if (!parrain_id || !pin || !user_id) return jsonRes({ error: 'Params manquants' }, 400);
      const pinHash = await hashPin(pin);
      const parrain = await db.prepare('SELECT * FROM parrains WHERE id = ? AND pin_hash = ?').bind(parrain_id, pinHash).first();
      if (!parrain) return jsonRes({ error: 'Code PIN incorrect' }, 401);
      const user = await db.prepare('SELECT * FROM users WHERE id = ? AND parrain_id = ?').bind(user_id, parrain_id).first();
      if (!user) return jsonRes({ error: 'Filleul non associe' }, 403);
      const newInvite = user_id.toUpperCase().slice(0, 4) + '-' + genCode();
      await db.prepare('UPDATE users SET parrain_id = NULL, invite_code = ? WHERE id = ?').bind(newInvite, user_id).run();
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
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>FiltresDNS</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f4f6fa;
  --surface:#ffffff;
  --surface-2:#f8fafc;
  --primary:#6366f1;
  --primary-d:#4f46e5;
  --primary-light:#eef2ff;
  --success:#10b981;
  --success-light:#d1fae5;
  --danger:#ef4444;
  --danger-light:#fee2e2;
  --warning:#f59e0b;
  --warning-light:#ffedd5;
  --text:#0f172a;
  --text-2:#475569;
  --text-3:#94a3b8;
  --border:#e2e8f0;
  --shadow:0 1px 3px rgba(0,0,0,0.05),0 4px 12px rgba(0,0,0,0.04);
  --radius:16px;
  --radius-sm:10px;
}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
body{
  background:var(--bg);
  color:var(--text);
  font-family:'Inter',system-ui,sans-serif;
  font-size:15px;
  line-height:1.5;
  min-height:100vh;
  padding:0;
  background-image:radial-gradient(circle at 100% 0%,rgba(99,102,241,0.08) 0%,transparent 50%);
  background-attachment:fixed;
}
.c{max-width:560px;margin:0 auto;padding:1rem 1rem 5rem}

/* Header */
.hd{text-align:center;padding:1.5rem 0 1rem}
.hd-logo{display:inline-flex;align-items:center;gap:10px;font-weight:700;font-size:1.5rem;color:var(--text)}
.hd-logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--primary),var(--primary-d));border-radius:10px;display:flex;align-items:center;justify-content:center;color:white;font-size:1.2rem;box-shadow:0 4px 12px rgba(99,102,241,0.3)}
.hd-sub{color:var(--text-2);font-size:.85rem;margin-top:6px}

/* Cards */
.card{background:var(--surface);border-radius:var(--radius);padding:1.25rem;margin-bottom:1rem;box-shadow:var(--shadow);border:1px solid var(--border)}
.card-title{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--text-3);margin-bottom:.75rem;padding-left:2px}

/* Inputs */
input[type=text],input[type=password],select{
  width:100%;padding:12px 14px;border-radius:var(--radius-sm);border:1.5px solid var(--border);
  background:var(--surface);color:var(--text);font-family:inherit;font-size:.92rem;outline:none;
  margin-bottom:8px;transition:border-color .15s, box-shadow .15s;
}
input:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}
input::placeholder{color:var(--text-3)}

/* Buttons */
.btn{
  width:100%;padding:12px;border-radius:var(--radius-sm);border:none;
  background:var(--primary);color:white;font-family:inherit;font-size:.92rem;font-weight:600;
  cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;justify-content:center;gap:6px;
}
.btn:hover{background:var(--primary-d);transform:translateY(-1px);box-shadow:0 6px 14px rgba(99,102,241,0.25)}
.btn:active{transform:translateY(0)}
.btn-2{background:var(--surface);color:var(--text);border:1.5px solid var(--border);box-shadow:none}
.btn-2:hover{background:var(--surface-2);border-color:var(--text-3);box-shadow:none}
.btn-danger{background:var(--danger)}
.btn-danger:hover{background:#dc2626;box-shadow:0 6px 14px rgba(239,68,68,0.25)}
.btn-ghost{background:transparent;color:var(--text-2);border:none;box-shadow:none;padding:8px 12px;width:auto;font-size:.82rem}
.btn-ghost:hover{background:var(--surface-2);color:var(--text);transform:none;box-shadow:none}

/* List items */
.row{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:var(--radius-sm);transition:background .15s}
.row+.row{margin-top:2px}
.row:hover{background:var(--surface-2)}
.row-icon{width:36px;height:36px;background:var(--surface-2);border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;font-size:1.1rem;flex-shrink:0;border:1px solid var(--border)}
.row-body{flex:1;min-width:0}
.row-title{font-weight:600;font-size:.9rem;color:var(--text)}
.row-sub{font-size:.72rem;color:var(--text-2);margin-top:2px}
.row-sub-accent{color:var(--success);font-size:.68rem;margin-top:2px;font-family:'JetBrains Mono',monospace}

/* Badges */
.badge{display:inline-block;font-size:.68rem;font-weight:600;padding:3px 8px;border-radius:6px;letter-spacing:.02em}
.badge-req{background:var(--danger-light);color:var(--danger)}
.badge-ok{background:var(--success-light);color:#065f46}
.badge-warn{background:var(--warning-light);color:#92400e}
.badge-info{background:var(--primary-light);color:var(--primary-d)}

/* Toggle */
.tg{position:relative;width:42px;height:24px;flex-shrink:0}
.tg input{opacity:0;width:0;height:0;position:absolute}
.tg-s{position:absolute;inset:0;background:#cbd5e1;border-radius:12px;cursor:pointer;transition:.2s}
.tg-s::before{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;background:white;border-radius:50%;transition:.2s;box-shadow:0 2px 4px rgba(0,0,0,0.15)}
.tg input:checked+.tg-s{background:var(--success)}
.tg input:checked+.tg-s::before{transform:translateX(18px)}
.tg input:disabled+.tg-s{opacity:.5;cursor:not-allowed}

/* Host code */
.host{display:inline-flex;align-items:center;gap:6px;font-family:'JetBrains Mono',monospace;font-size:.85rem;background:var(--primary-light);color:var(--primary-d);padding:8px 14px;border-radius:999px;cursor:pointer;font-weight:500;border:1px solid transparent;transition:.15s}
.host:hover{border-color:var(--primary)}
.host.success{background:var(--success-light);color:#065f46}

/* Back link */
.back{display:inline-flex;align-items:center;gap:4px;font-size:.85rem;color:var(--text-2);cursor:pointer;margin-bottom:1rem;font-weight:500}
.back:hover{color:var(--text)}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:1rem 0}
.stat{background:var(--surface-2);border-radius:var(--radius-sm);padding:12px 8px;text-align:center;border:1px solid var(--border)}
.stat-n{font-size:1.3rem;font-weight:700;color:var(--text);font-family:'JetBrains Mono',monospace}
.stat-l{font-size:.65rem;color:var(--text-2);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}

/* Modal */
.modal-bg{position:fixed;inset:0;background:rgba(15,23,42,0.5);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:200;padding:1rem}
.modal-bg.show{display:flex}
.modal{background:var(--surface);border-radius:20px;width:100%;max-width:380px;padding:1.5rem;box-shadow:0 20px 40px rgba(0,0,0,0.15)}
.modal h3{font-size:1.05rem;font-weight:600;margin-bottom:.5rem}
.modal p{color:var(--text-2);font-size:.88rem;margin-bottom:1rem}
.modal-btns{display:flex;gap:8px;margin-top:1rem}
.modal-btns .btn{flex:1}

/* Toast */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--text);color:white;padding:12px 20px;border-radius:12px;font-size:.88rem;font-weight:500;z-index:300;opacity:0;transition:.25s;box-shadow:0 10px 25px rgba(0,0,0,0.2);pointer-events:none;max-width:90%}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{background:var(--danger)}
.toast.success{background:var(--success)}

/* Loader */
.loader-bg{position:fixed;inset:0;background:rgba(255,255,255,0.75);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:250}
.loader-bg.show{display:flex}
.spin{width:40px;height:40px;border:3px solid var(--border);border-top-color:var(--primary);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Exceptions modal */
.exc-item{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--border)}
.exc-item:last-child{border-bottom:none}
.exc-dom{flex:1;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.exc-dom.excepted{color:var(--success);font-weight:600}
.exc-dom.pending{color:var(--warning);font-style:italic}
.exc-link{display:inline-block;font-size:.72rem;color:var(--warning);cursor:pointer;margin-top:4px;font-weight:500}
.exc-link:hover{text-decoration:underline}

/* Misc */
.hidden{display:none!important}
.warn{font-size:.78rem;background:var(--warning-light);color:#92400e;padding:10px 12px;border-radius:var(--radius-sm);margin-bottom:10px;line-height:1.45}
.or{text-align:center;color:var(--text-3);font-size:.78rem;margin:12px 0;position:relative}
.or::before,.or::after{content:'';position:absolute;top:50%;width:40%;height:1px;background:var(--border)}
.or::before{left:0}.or::after{right:0}
.hint{font-size:.72rem;color:var(--text-3);margin-top:8px;text-align:center}
.mt{margin-top:12px}
.mt-lg{margin-top:1.5rem}

/* Setup guide */
.setup{background:var(--primary-light);border-radius:var(--radius);padding:1rem;font-size:.82rem;color:var(--text);line-height:1.6;margin-top:1rem;border:1px solid #c7d2fe}
.setup h3{color:var(--primary-d);font-size:.85rem;margin-bottom:8px;font-weight:700;display:flex;align-items:center;gap:6px}
.setup ol{padding-left:1.2rem;color:var(--text-2)}
.setup code{font-family:'JetBrains Mono',monospace;font-size:.75rem;background:white;padding:2px 6px;border-radius:4px;color:var(--primary-d);border:1px solid #c7d2fe;font-weight:500}

/* Suggestion */
.sugg{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--surface-2);border-radius:var(--radius-sm);margin-top:8px;font-size:.78rem;color:var(--text-2);border:1px solid var(--border)}
.sugg-dep{color:var(--success);font-family:'JetBrains Mono',monospace;font-size:.72rem;margin-top:2px}
</style>
</head>
<body>

<div class="c">
  <div class="hd">
    <div class="hd-logo">
      <div class="hd-logo-icon">\u{1F6E1}\uFE0F</div>
      FiltresDNS
    </div>
    <div class="hd-sub">Filtrage DNS personnalisé</div>
  </div>
  <div id="app"></div>
</div>

<div class="loader-bg" id="loader"><div class="spin"></div></div>

<div class="modal-bg" id="excModal">
  <div class="modal" style="max-width:460px;max-height:82vh;overflow-y:auto">
    <h3 id="excTitle"></h3>
    <div class="warn">Débloquer un domaine le rend accessible sur le site et l\u2019appli. Le DNS ne peut pas les différencier.</div>
    <input type="text" id="excSearch" placeholder="Rechercher..." oninput="filterExcDomains()">
    <div id="excList" style="max-height:340px;overflow-y:auto;margin-top:8px"></div>
    <button class="btn btn-2 mt" onclick="closeExcModal()">Fermer</button>
  </div>
</div>

<div class="modal-bg" id="confirmModal">
  <div class="modal">
    <h3 id="confirmTitle"></h3>
    <p id="confirmMsg"></p>
    <input type="password" id="confirmPin" placeholder="Code secret" class="hidden">
    <div class="modal-btns">
      <button class="btn btn-2" onclick="closeModal()">Annuler</button>
      <button class="btn" id="confirmBtn" onclick="confirmAction()">Confirmer</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const API='/api';
let state={screen:'home',user:null,parrain:null,filleulDetail:null};
let pendingAction=null;
let excDomains=[];
let excCategory='';

function $(id){return document.getElementById(id)}
function showLoader(){$('loader').classList.add('show')}
function hideLoader(){$('loader').classList.remove('show')}

function toast(msg,type){
  const t=$('toast');
  t.textContent=msg;
  t.className='toast show '+(type||'');
  setTimeout(()=>t.className='toast',2800);
}

function render(){
  const app=$('app');
  switch(state.screen){
    case'home':app.innerHTML=homeScreen();break;
    case'register':app.innerHTML=registerScreen();break;
    case'profile':app.innerHTML=profileScreen();break;
    case'parrain_login':app.innerHTML=parrainLoginScreen();break;
    case'parrain_invite':app.innerHTML=parrainInviteScreen();break;
    case'parrain_dashboard':app.innerHTML=parrainDashScreen();break;
    case'parrain_detail':app.innerHTML=parrainDetailScreen();break;
  }
}

function homeScreen(){
  return \`
  <div class="card" style="text-align:center">
    <div style="font-size:2.5rem;margin-bottom:8px">\u{1F44B}</div>
    <h3 style="font-size:1.1rem;margin-bottom:4px">Bienvenue</h3>
    <p style="color:var(--text-2);font-size:.85rem;margin-bottom:1rem">Crée ton profil ou accède à ton espace</p>
    <button class="btn" onclick="go('register')" style="margin-bottom:8px">Créer mon profil</button>
    <button class="btn btn-2" onclick="go('parrain_login')">Je suis parrain</button>
    <div class="or">ou</div>
    <p style="font-size:.78rem;color:var(--text-2);margin-bottom:8px">DNS de base (sans profil) :</p>
    <div class="host" onclick="navigator.clipboard.writeText('dns.rpisimon.uk');toast('Copié !','success')">dns.rpisimon.uk</div>
    <div class="hint">Toutes les catégories bloquées par défaut</div>
  </div>
  <div class="card">
    <div class="card-title">\u{1F511} J\u2019ai déjà un profil</div>
    <input type="text" id="loginId" placeholder="Identifiant (ex: paul)">
    <input type="password" id="loginPin" placeholder="Code secret">
    <button class="btn btn-2" onclick="loginUser()">Se connecter</button>
    <div class="hint mt"><a href="mailto:simon.deboeuf.1@gmail.com?subject=PIN%20Filleul%20perdu%20-%20FiltreDNS&body=Bonjour%2C%0A%0AJ%27ai%20perdu%20mon%20code%20secret%20filleul.%0A%0AMon%20identifiant%20%3A%20%0A%0AMerci%20de%20m%27aider%20%C3%A0%20le%20r%C3%A9cup%C3%A9rer." style="color:var(--warning);text-decoration:underline;font-weight:500;cursor:pointer">PIN oublié ? Me contacter</a></div>
  </div>
  <div class="hint" style="margin-top:1rem;padding:0 1rem">\u{1F4AC} Des idées, un bug ou autres choses, n\u2019hésites pas à m\u2019en faire part :)</div>
  \`;
}

function registerScreen(){
  return \`
  <span class="back" onclick="go('home')">\u2190 Retour</span>
  <div class="card">
    <h3 style="margin-bottom:1rem">Créer mon profil</h3>
    <input type="text" id="regName" placeholder="Ton prénom (sans accent)">
    <div class="hint" style="text-align:left;margin-bottom:12px">Ce prénom sera ton identifiant. Ex: paul, marc, lucas</div>
    <input type="password" id="regPin1" placeholder="Code secret (4+ chiffres)">
    <input type="password" id="regPin2" placeholder="Confirme le code secret">
    <button class="btn mt" onclick="registerUser()">Créer mon profil</button>
  </div>
  \`;
}

function profileScreen(){
  const u=state.user;
  if(!u)return'';
  let catsHtml='';
  for(const[key,cat]of Object.entries(u.categories||{})){
    const locked=cat.blocked&&cat.locked_by;
    const lockInfo=locked?(cat.locked_by==='user'?'Activé par toi · verrouillé':'Géré par ton parrain'):'Non activé';
    const excInfo=(cat.blocked&&cat.exceptions>0)?' · '+cat.exceptions+' exception(s)':'';
    const pendInfo=(cat.blocked&&cat.pending>0)?' · '+cat.pending+' en attente':'';
    const excLink=(cat.blocked&&key!=='yt_safesearch')?'<span class="exc-link" onclick="openExceptions(\\''+key+'\\')">Gérer les exceptions \u2192</span>':'';
    const statusBadge=locked?'<span class="badge badge-info">Actif</span>':'';
    catsHtml+=\`<div class="row">
      <div class="row-icon">\${CAT_LABELS[key]?.icon||''}</div>
      <div class="row-body">
        <div class="row-title">\${cat.name}</div>
        <div class="row-sub">\${lockInfo}\${excInfo}\${pendInfo}</div>
        \${excLink}
      </div>
      <label class="tg"><input type="checkbox" \${cat.blocked?'checked':''} \${locked?'disabled':''} onchange="userToggle('\${key}',this)"><span class="tg-s"></span></label>
    </div>\`;
  }

  const inviteHtml=u.has_parrain
    ?\`<div class="row"><div class="row-icon">\u{1F464}</div><div class="row-body"><div class="row-title">Parrain : \${u.parrain}</div></div><span class="badge badge-ok">Associé</span></div>\`
    :\`<div class="row"><div class="row-icon">\u{1F4E9}</div><div class="row-body"><div class="row-title">Code d\u2019invitation</div><div class="row-sub">Envoie ce code à ton parrain</div></div><span class="host" onclick="event.stopPropagation();navigator.clipboard.writeText('\${u.invite_code}');this.textContent='Copié !';this.classList.add('success');setTimeout(()=>{this.textContent='\${u.invite_code}';this.classList.remove('success')},1500)">\${u.invite_code}</span></div>\`;

  return \`
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
    <span class="back" onclick="logout()">\u2190 Déconnexion</span>
    <span class="host" onclick="navigator.clipboard.writeText('\${u.hostname}');this.textContent='Copié !';this.classList.add('success');setTimeout(()=>{this.textContent='\${u.hostname}';this.classList.remove('success')},1500)">\${u.hostname}</span>
  </div>
  <div class="card">
    <div class="card-title">\u{1F464} Mon profil</div>
    \${inviteHtml}
  </div>
  <div class="card">
    <div class="card-title">\u{1F512} Blocages obligatoires</div>
    \${u.mandatory.map(m=>\`<div class="row"><div class="row-icon">\${m.icon}</div><div class="row-body"><div class="row-title">\${m.name}</div><div class="row-sub">\${m.count} domaines</div></div><span class="badge badge-req">Obligatoire</span></div>\`).join('')}
  </div>
  <div class="card">
    <div class="card-title">\u2699\uFE0F Catégories optionnelles</div>
    \${catsHtml}
  </div>
  <div class="card">
    <div class="card-title">\u{1F4A1} Proposer un site à bloquer</div>
    <input type="text" id="suggestUrl" placeholder="URL du site (ex: exemple.com)">
    <select id="suggestCat">
      <option value="" disabled selected>Catégorie du site</option>
      <option value="adulte">Contenus pour adultes</option>
      <option value="webcam">Webcams adultes</option>
      <option value="hentai">Hentai / Comics adultes</option>
      <option value="ia_nsfw">IA suggestive / NSFW</option>
      <option value="manga">Manga / Webtoon / Scantrad</option>
      <option value="gambling">Jeux d\u2019argent / Paris sportifs</option>
      <option value="search">Moteurs de recherche</option>
      <option value="ai_mixed">IA mixtes</option>
      <option value="tor">Tor / Anonymisation</option>
      <option value="autre">Autre (préciser)</option>
    </select>
    <input type="text" id="suggestOther" placeholder="Précise le type de site" style="display:none">
    <button class="btn" onclick="suggestSite()">Ajouter au filtre</button>
    <div class="hint" style="text-align:left">Le site sera bloqué immédiatement pour tous les utilisateurs.</div>
  </div>
  <button class="btn btn-2 mt" onclick="changeUserPin()">\u{1F511} Changer mon code secret</button>
  <div class="setup">
    <h3>\u{1F4F1} Installation (30 secondes)</h3>
    <ol>
      <li><strong>Paramètres</strong> \u2192 <strong>Réseau et Internet</strong> \u2192 <strong>DNS Privé</strong></li>
      <li>Nom d\u2019hôte : <code>\${u.hostname}</code></li>
      <li>Sauvegarder \u2192 <strong>Redémarrer le téléphone</strong></li>
    </ol>
  </div>
  \`;
}

function parrainLoginScreen(){
  return \`
  <span class="back" onclick="go('home')">\u2190 Retour</span>
  <div class="card">
    <h3 style="margin-bottom:1rem">Espace parrain</h3>
    <input type="text" id="pName" placeholder="Mon prénom">
    <input type="password" id="pPin" placeholder="Mon code secret">
    <button class="btn" onclick="parrainLogin()" style="margin-bottom:8px">Accéder</button>
    <div class="or">ou</div>
    <button class="btn btn-2" onclick="go('parrain_invite')">J\u2019ai un code d\u2019invitation</button>
    <div class="hint mt"><a href="mailto:simon.deboeuf.1@gmail.com?subject=PIN%20Parrain%20perdu%20-%20FiltreDNS&body=Bonjour%2C%0A%0AJ%27ai%20perdu%20mon%20code%20secret%20parrain.%0A%0AMon%20pr%C3%A9nom%20parrain%20%3A%20%0AMon%20filleul%20%3A%20%0A%0AMerci%20de%20m%27aider%20%C3%A0%20le%20r%C3%A9cup%C3%A9rer." style="color:var(--warning);text-decoration:underline;font-weight:500;cursor:pointer">PIN oublié ? Me contacter</a></div>
  </div>
  \`;
}

function parrainInviteScreen(){
  return \`
  <span class="back" onclick="go('parrain_login')">\u2190 Retour</span>
  <div class="card">
    <h3 style="margin-bottom:1rem">Devenir parrain</h3>
    <input type="text" id="invCode" placeholder="Code d\u2019invitation (ex: PAUL-7X3K)" style="font-family:'JetBrains Mono',monospace;text-align:center;letter-spacing:2px">
    <input type="text" id="invName" placeholder="Mon prénom">
    <input type="password" id="invPin1" placeholder="Choisis un code secret (4+)">
    <input type="password" id="invPin2" placeholder="Confirme le code">
    <button class="btn" onclick="parrainRegister()">Devenir parrain</button>
  </div>
  \`;
}

function parrainDashScreen(){
  const p=state.parrain;
  if(!p)return'';
  return \`
  <span class="back" onclick="state.parrain=null;go('home')">\u2190 Déconnexion</span>
  <div class="card" style="text-align:center">
    <div style="font-size:2rem;margin-bottom:4px">\u{1F451}</div>
    <h3 style="font-size:1.1rem">\${p.name}</h3>
    <div style="font-size:.78rem;color:var(--text-2)">Espace parrain</div>
  </div>
  <div class="card">
    <div class="card-title">\u{1F465} Mes filleuls</div>
    \${(p.filleuls||[]).map(f=>\`<div class="row" style="cursor:pointer" onclick="viewFilleul('\${f.id}')">
      <div class="row-icon" style="background:var(--primary-light);color:var(--primary-d);font-weight:700">\${f.display_name[0].toUpperCase()}</div>
      <div class="row-body"><div class="row-title">\${f.display_name}</div><div class="row-sub">\${f.hostname}</div></div>
      <span style="color:var(--text-3)">\u2192</span>
    </div>\`).join('')||'<div class="hint" style="padding:1rem">Aucun filleul associé</div>'}
    <button class="btn btn-2 mt" onclick="go('parrain_invite')">\u2795 Ajouter un filleul</button>
  </div>
  <div id="pendingSection"></div>
  <button class="btn btn-2 mt" onclick="changePin()">\u{1F511} Changer mon code secret</button>
  \`;
}

function parrainDetailScreen(){
  const f=state.filleulDetail;
  if(!f)return'';
  let catsHtml='';
  for(const[key,cat]of Object.entries(f.categories||{})){
    const info=cat.blocked?(cat.locked_by==='user'?'Activé par le filleul':'Activé par toi'):'Non activé';
    const excDetail=(cat.exceptions>0?' · '+cat.exceptions+' exception(s)':'')+(cat.pending>0?' · '+cat.pending+' en attente':'');
    const excList=(cat.exception_domains||[]).length>0?'<div class="row-sub-accent">'+cat.exception_domains.join(', ')+'</div>':'';
    catsHtml+=\`<div class="row">
      <div class="row-icon">\${CAT_LABELS[key]?.icon||''}</div>
      <div class="row-body"><div class="row-title">\${cat.name}</div><div class="row-sub">\${info}\${excDetail}</div>\${excList}</div>
      <label class="tg"><input type="checkbox" \${cat.blocked?'checked':''} onchange="parrainToggle('\${key}',this.checked,this)"><span class="tg-s"></span></label>
    </div>\`;
  }
  const pct=f.stats.total>0?((f.stats.blocked/f.stats.total)*100).toFixed(1):'0';
  return \`
  <span class="back" onclick="go('parrain_dashboard')">\u2190 Retour</span>
  <div class="card" style="text-align:center">
    <div style="font-size:2rem;margin-bottom:4px">\u{1F464}</div>
    <h3 style="font-size:1.1rem">\${f.name}</h3>
    <span class="host">\${f.hostname}</span>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-n">\${f.stats.blocked.toLocaleString()}</div><div class="stat-l">Bloquées</div></div>
    <div class="stat"><div class="stat-n">\${f.stats.total.toLocaleString()}</div><div class="stat-l">Total</div></div>
    <div class="stat"><div class="stat-n">\${pct}%</div><div class="stat-l">Taux</div></div>
  </div>
  <div class="card">
    <div class="card-title">\u{1F512} Obligatoires</div>
    \${f.mandatory.map(m=>\`<div class="row"><div class="row-icon">\${m.icon}</div><div class="row-body"><div class="row-title">\${m.name}</div></div><span class="badge badge-req">Obligatoire</span></div>\`).join('')}
  </div>
  <div class="card">
    <div class="card-title">\u2699\uFE0F Catégories optionnelles</div>
    \${catsHtml}
  </div>
  <button class="btn btn-danger mt" onclick="revokeFilleul('\${f.id}','\${f.name}')">Se retirer comme parrain</button>
  \`;
}

const CAT_LABELS=${JSON.stringify(CAT_LABELS)};

function go(screen){state.screen=screen;render();if(screen==='parrain_dashboard')setTimeout(loadPending,100)}

function logout(){state.user=null;localStorage.removeItem('fdns_id');localStorage.removeItem('fdns_pin');go('home')}

async function registerUser(){
  const name=$('regName')?.value?.trim();
  if(!name)return toast('Remplis ton prénom','error');
  const pin1=$('regPin1')?.value;
  const pin2=$('regPin2')?.value;
  if(!pin1||pin1.length<4)return toast('Code secret requis (4 chiffres mini)','error');
  if(pin1!==pin2)return toast('Les codes ne correspondent pas','error');
  showLoader();
  try{
    const res=await fetch(API+'/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,pin:pin1})});
    const data=await res.json();
    if(data.error){hideLoader();toast(data.error+(data.suggestion?' \u2192 '+data.suggestion:''),'error');return;}
    localStorage.setItem('fdns_id',data.id);
    localStorage.setItem('fdns_pin',pin1);
    await new Promise(r=>setTimeout(r,300));
    const pRes=await fetch(API+'/profile?id='+data.id);
    state.user=await pRes.json();
    hideLoader();
    toast('Profil créé !','success');
    go('profile');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function loginUser(){
  const id=$('loginId')?.value?.trim()?.toLowerCase();
  const pin=$('loginPin')?.value||'';
  if(!id)return toast('Entre ton identifiant','error');
  showLoader();
  try{
    const authRes=await fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,pin})});
    const authData=await authRes.json();
    if(authData.error){hideLoader();toast(authData.error,'error');return;}
    const res=await fetch(API+'/profile?id='+id);
    const data=await res.json();
    if(data.error){hideLoader();toast(data.error,'error');return;}
    state.user=data;
    localStorage.setItem('fdns_id',id);
    localStorage.setItem('fdns_pin',pin);
    hideLoader();
    go('profile');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function changeUserPin(){
  var old=prompt('Ancien code secret (vide si premier code) :');
  if(old===null)return;
  var nw=prompt('Nouveau code secret (4+ chiffres) :');
  if(!nw||nw.length<4)return toast('Code trop court','error');
  var nw2=prompt('Confirme le nouveau code :');
  if(nw!==nw2)return toast('Les codes ne correspondent pas','error');
  showLoader();
  try{
    const res=await fetch(API+'/change-pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:state.user.id,old_pin:old,new_pin:nw})});
    const data=await res.json();hideLoader();
    if(data.error){toast(data.error,'error');return;}
    localStorage.setItem('fdns_pin',nw);
    toast('Code secret mis à jour !','success');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

function userToggle(cat,el){
  el.checked=false;
  pendingAction={type:'user_toggle',cat,el};
  $('confirmTitle').textContent='Activer le blocage ?';
  $('confirmMsg').textContent=CAT_LABELS[cat].name+' sera bloqué. Seul ton parrain pourra le débloquer.';
  $('confirmPin').classList.add('hidden');
  $('confirmBtn').classList.remove('btn-danger');
  $('confirmModal').classList.add('show');
}

async function confirmAction(){
  const pinValue=$('confirmPin')?$('confirmPin').value:'';
  closeModal();
  if(!pendingAction)return;
  const a=pendingAction;pendingAction=null;
  showLoader();
  try{
    if(a.type==='user_toggle'){
      const res=await fetch(API+'/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:state.user.id,category:a.cat})});
      const data=await res.json();
      if(data.error){hideLoader();toast(data.error,'error');return;}
      await new Promise(r=>setTimeout(r,300));
      const pRes=await fetch(API+'/profile?id='+state.user.id);
      state.user=await pRes.json();
      hideLoader();
      toast('Blocage activé','success');
      go('profile');
    }
    if(a.type==='parrain_toggle'){
      if(!pinValue){hideLoader();toast('Code secret requis','error');return;}
      const res=await fetch(API+'/parrain/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parrain_id:state.parrain.parrain_id,pin:pinValue,user_id:state.filleulDetail.id,category:a.cat,blocked:a.blocked})});
      const data=await res.json();
      if(data.error){hideLoader();toast(data.error,'error');return;}
      await viewFilleul(state.filleulDetail.id);
      hideLoader();
      toast('Mis à jour','success');
    }
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

function parrainToggle(cat,blocked,el){
  el.checked=!blocked;
  const action=blocked?'activer le blocage de':'désactiver le blocage de';
  pendingAction={type:'parrain_toggle',cat,blocked};
  $('confirmTitle').textContent='Confirmation requise';
  $('confirmMsg').textContent='Tu vas '+action+' "'+CAT_LABELS[cat].name+'" pour '+state.filleulDetail.name+'.';
  $('confirmPin').classList.remove('hidden');
  $('confirmPin').value='';
  $('confirmBtn').classList.toggle('btn-danger',!blocked);
  $('confirmModal').classList.add('show');
  setTimeout(()=>$('confirmPin').focus(),100);
}

function closeModal(){$('confirmModal').classList.remove('show')}

async function suggestSite(){
  const urlInput=$('suggestUrl');
  const catSelect=$('suggestCat');
  const otherInput=$('suggestOther');
  if(!urlInput||!catSelect)return;
  const url=urlInput.value.trim();
  const cat=catSelect.value;
  const other=otherInput?.value?.trim()||'';
  if(!url)return toast('Entre une URL','error');
  if(!cat)return toast('Choisis une catégorie','error');
  if(cat==='autre'&&!other)return toast('Précise le type','error');
  showLoader();
  try{
    const res=await fetch(API+'/suggest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:state.user.id,url,category:cat,category_other:other})});
    const data=await res.json();hideLoader();
    if(data.error){toast(data.error,'error');return;}
    toast(data.domain+' ajouté !','success');
    urlInput.value='';catSelect.value='';
    if(otherInput){otherInput.value='';otherInput.style.display='none';}
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

document.addEventListener('change',function(e){
  if(e.target.id==='suggestCat'){
    const otherInput=$('suggestOther');
    if(otherInput)otherInput.style.display=e.target.value==='autre'?'block':'none';
  }
});

async function parrainLogin(){
  const name=$('pName')?.value?.trim();
  const pin=$('pPin')?.value;
  if(!name||!pin)return toast('Remplis tout','error');
  showLoader();
  try{
    const res=await fetch(API+'/parrain/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,pin})});
    const data=await res.json();hideLoader();
    if(data.error){toast(data.error,'error');return;}
    state.parrain=data;
    go('parrain_dashboard');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function parrainRegister(){
  const code=$('invCode')?.value?.trim();
  const name=$('invName')?.value?.trim();
  const pin1=$('invPin1')?.value;
  const pin2=$('invPin2')?.value;
  if(!code||!name||!pin1)return toast('Remplis tout','error');
  if(pin1!==pin2)return toast('Les codes ne correspondent pas','error');
  if(pin1.length<4)return toast('Code trop court','error');
  showLoader();
  try{
    const res=await fetch(API+'/parrain/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({invite_code:code,name,pin:pin1,current_user_id:localStorage.getItem('fdns_id')||''})});
    const data=await res.json();
    if(data.error){hideLoader();toast(data.error,'error');return;}
    toast('Parrain de '+data.filleul+' !','success');
    const lRes=await fetch(API+'/parrain/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,pin:pin1})});
    state.parrain=await lRes.json();hideLoader();
    go('parrain_dashboard');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function viewFilleul(userId){
  showLoader();
  try{
    const res=await fetch(API+'/parrain/filleul?parrain_id='+state.parrain.parrain_id+'&user_id='+userId);
    state.filleulDetail=await res.json();hideLoader();
    go('parrain_detail');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function changePin(){
  const old=prompt('Ancien code secret :');
  if(!old)return;
  const nw=prompt('Nouveau code secret (4+ chiffres) :');
  if(!nw||nw.length<4)return toast('Code trop court','error');
  const nw2=prompt('Confirme :');
  if(nw!==nw2)return toast('Les codes ne correspondent pas','error');
  showLoader();
  try{
    const res=await fetch(API+'/parrain/change-pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parrain_id:state.parrain.parrain_id,old_pin:old,new_pin:nw})});
    const data=await res.json();hideLoader();
    if(data.error)toast(data.error,'error');else toast('Code changé !','success');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function openExceptions(category){
  excCategory=category;showLoader();
  try{
    const res=await fetch(API+'/category-domains?user_id='+state.user.id+'&category='+category);
    const data=await res.json();excDomains=data.domains||[];hideLoader();
    $('excTitle').textContent='Exceptions \u2014 '+CAT_LABELS[category].name;
    renderExcDomains();$('excModal').classList.add('show');
    $('excSearch').value='';
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

function renderExcDomains(){
  const search=($('excSearch')?.value||'').toLowerCase();
  const filtered=excDomains.filter(d=>d.domain.includes(search));
  const list=$('excList');
  if(filtered.length===0){list.innerHTML='<div class="hint" style="padding:1rem">Aucun domaine</div>';return;}
  list.innerHTML=filtered.map(d=>{
    var cls=d.excepted?'excepted':(d.pending?'pending':'');
    var status=d.pending?' (en attente)':'';
    var dis=d.pending?' disabled':'';
    return '<div class="exc-item"><span class="exc-dom '+cls+'">'+d.domain+status+'</span><label class="tg"><input type="checkbox" '+(d.excepted?'checked':'')+(d.pending?' checked disabled':'')+dis+' onchange="toggleException(\\''+d.domain+'\\',this.checked)"><span class="tg-s"></span></label></div>';
  }).join('');
}

function filterExcDomains(){renderExcDomains()}

async function toggleException(domain,excepted){
  showLoader();
  try{
    const res=await fetch(API+'/exception',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:state.user.id,category:excCategory,domain,excepted})});
    const data=await res.json();
    if(data.error){hideLoader();toast(data.error,'error');return;}
    if(data.pending){
      const d=excDomains.find(x=>x.domain===domain);if(d){d.pending=true;d.excepted=false;}
      const deps=data.dependencies||[];
      for(const dep of deps){const dd=excDomains.find(x=>x.domain===dep);if(dd){dd.pending=true;dd.excepted=false;}}
      renderExcDomains();hideLoader();
      toast('Demande envoyée au parrain','success');return;
    }
    const d=excDomains.find(x=>x.domain===domain);if(d){d.excepted=false;d.pending=false;}
    renderExcDomains();
    const prRes=await fetch(API+'/profile?id='+state.user.id);state.user=await prRes.json();hideLoader();
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

function closeExcModal(){$('excModal').classList.remove('show');go('profile')}

async function loadPending(){
  if(!state.parrain)return;
  try{
    const res=await fetch(API+'/parrain/pending?parrain_id='+state.parrain.parrain_id);
    const data=await res.json();
    const el=$('pendingSection');
    if(!el)return;
    if(!data.pending||data.pending.length===0){el.innerHTML='';return;}
    el.innerHTML='<div class="card"><div class="card-title">\u23F3 Demandes en attente</div><div class="hint" style="text-align:left;margin-bottom:10px">Les domaines liés (ex: apis.naver.com pour Webtoon) sont inclus auto.</div>'+data.pending.map(p=>'<div class="row" style="flex-wrap:wrap"><div class="row-icon">\u{1F4E5}</div><div class="row-body"><div class="row-title">'+p.user_name+' : '+p.domain+'</div><div class="row-sub">'+(p.category||'?')+'</div></div><div style="display:flex;gap:6px;width:100%;margin-top:8px"><button class="btn" style="width:auto;padding:8px 14px;font-size:.78rem;flex:1" onclick="approvePending(\\''+p.user_id+'\\',\\''+p.category+'\\',\\''+p.domain+'\\',true)">Approuver</button><button class="btn btn-danger" style="width:auto;padding:8px 14px;font-size:.78rem;flex:1" onclick="approvePending(\\''+p.user_id+'\\',\\''+p.category+'\\',\\''+p.domain+'\\',false)">Refuser</button></div></div>').join('')+'</div>';
  }catch(e){}
}

async function approvePending(userId,category,domain,approved){
  var pin=prompt(approved?'Code secret pour approuver :':'Code secret pour refuser :');
  if(!pin)return;
  showLoader();
  try{
    const res=await fetch(API+'/parrain/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parrain_id:state.parrain.parrain_id,pin:pin,user_id:userId,category:category,domain:domain,approved:approved})});
    const data=await res.json();hideLoader();
    if(data.error){toast(data.error,'error');return;}
    toast(approved?'Approuvée !':'Refusée','success');
    loadPending();
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

async function revokeFilleul(userId,userName){
  if(!confirm('Tu ne seras plus parrain de '+userName+'. Continuer ?'))return;
  var pin=prompt('Code secret :');
  if(!pin)return;
  showLoader();
  try{
    const res=await fetch(API+'/parrain/revoke-filleul',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({parrain_id:state.parrain.parrain_id,pin:pin,user_id:userId})});
    const data=await res.json();hideLoader();
    if(data.error){toast(data.error,'error');return;}
    toast('Parrain retiré pour '+userName,'success');
    const lRes=await fetch(API+'/parrain/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:state.parrain.name,pin:pin})});
    state.parrain=await lRes.json();go('parrain_dashboard');
  }catch(e){hideLoader();toast('Erreur : '+e.message,'error');}
}

const savedId=localStorage.getItem('fdns_id');
const savedPin=localStorage.getItem('fdns_pin');
if(savedId){
  fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:savedId,pin:savedPin||''})}).then(r=>r.json()).then(auth=>{
    if(auth.error){localStorage.removeItem('fdns_id');localStorage.removeItem('fdns_pin');render();return;}
    return fetch(API+'/profile?id='+savedId).then(r=>r.json()).then(d=>{
      if(!d.error){state.user=d;go('profile')}else{localStorage.removeItem('fdns_id');localStorage.removeItem('fdns_pin');render()}
    });
  }).catch(()=>render());
}else render();

document.addEventListener('keydown',function(e){
  if(e.key!=='Enter')return;
  const id=e.target.id;
  if(id==='regName'||id==='regPin1'||id==='regPin2')registerUser();
  if(id==='loginId'||id==='loginPin')loginUser();
  if(id==='pName'||id==='pPin')parrainLogin();
  if(id==='invCode'||id==='invName'||id==='invPin1'||id==='invPin2')parrainRegister();
  if(id==='confirmPin')confirmAction();
  if(id==='suggestUrl')suggestSite();
});
</script>
</body>
</html>`;
}
