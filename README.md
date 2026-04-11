# FiltresDNS — Interface self-service

Interface web parrain/filleul pour la gestion des catégories DNS.

## Stack

- **Frontend** : HTML/CSS/JS vanilla (embarqué dans le Worker)
- **Backend** : Cloudflare Worker
- **Base de données** : Cloudflare D1 (SQLite, Europe de l'Ouest)
- **DNS** : AdGuard Home sur Oracle Cloud (89.168.40.235)

## Fonctionnement

### Filleul
1. Ouvre `filtredns.rpisimon.uk`
2. Crée son profil (prénom)
3. Reçoit son hostname DNS (`prenom.dns.rpisimon.uk`)
4. Choisit ses catégories optionnelles (sens unique : peut bloquer, ne peut pas débloquer)
5. Envoie son code d'invitation à son parrain

### Parrain
1. Reçoit le code d'invitation du filleul
2. S'inscrit avec le code + son prénom + un code secret
3. Accède au dashboard parrain : voit ses filleuls, leurs stats, leurs catégories
4. Peut activer ET désactiver les catégories optionnelles (avec confirmation + code secret)
5. Peut changer son code secret à tout moment

### DNS de base (sans profil)
Utiliser `dns.rpisimon.uk` directement → toutes les catégories bloquées, pas de personnalisation.

## Déploiement

### 1. Créer la base D1

```bash
npx wrangler d1 create filtredns-db --location=weur
```

Copier le `database_id` affiché dans `wrangler.toml`.

### 2. Initialiser le schéma

```bash
npx wrangler d1 execute filtredns-db --file=schema.sql
```

### 3. Configurer les secrets

```bash
npx wrangler secret put ADGUARD_URL
# → http://89.168.40.235:3000

npx wrangler secret put ADGUARD_USER
# → ton login admin AdGuard

npx wrangler secret put ADGUARD_PASS
# → ton mot de passe admin AdGuard
```

### 4. Déployer

```bash
npx wrangler deploy
```

### 5. DNS Cloudflare

Ajouter dans rpisimon.uk → DNS → Records :

| Type  | Nom        | Contenu                              | Proxy |
|-------|------------|--------------------------------------|-------|
| CNAME | `filtredns` | `filtredns.TONCOMPTE.workers.dev`   | ✅ ON  |

(Le nom exact du workers.dev s'affiche après `wrangler deploy`)

## Sécurité

- Les codes secrets des parrains sont hashés (SHA-256 + salt) en base
- Seuls les parrains associés peuvent voir/modifier les catégories de leurs filleuls
- Les filleuls ne peuvent que bloquer (sens unique), jamais débloquer
- Le parrain doit entrer son code secret pour chaque modification de catégorie
- Aucun accès à l'interface admin AdGuard Home pour les utilisateurs

## Catégories

### Obligatoires (non modifiables)
- Contenus pour adultes (157 domaines)
- Webcams adultes (37 domaines)
- Hentai / Comics adultes (55 domaines)
- IA suggestive / NSFW (26 domaines)
- Tor / Anonymisation (9 domaines)

### Optionnelles (modifiables)
- Manga / Webtoon / Scantrad (184 domaines)
- Jeux d'argent / Paris sportifs (46 domaines)
- Moteurs de recherche alternatifs (49 domaines)
- IA mixtes (20 domaines)
- SafeSearch YouTube (via API client AdGuard)
