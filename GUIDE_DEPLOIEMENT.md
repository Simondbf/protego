# FiltresDNS — Guide de déploiement complet
# Git + Cloudflare, étape par étape

---

## Pré-requis

- Node.js installé (https://nodejs.org → version LTS)
- Git installé (https://git-scm.com → si pas déjà fait)
- Le fichier filtredns.zip dézippé sur ton D:\ (ex: D:\Dev\filtredns)
- Ton compte Cloudflare (celui de rpisimon.uk)

---

## PARTIE 1 — Mettre sur GitHub

Ouvre CMD dans le dossier du projet :
Explorateur → D:\Dev\filtredns → barre d'adresse → tape `cmd` → Entrée

```cmd
git init
git config user.email "simon.deboeuf.1@gmail.com"
git config user.name "Simondbf"
git add .
git commit -m "FiltresDNS v1"
git remote add origin https://github.com/Simondbf/filtre_dns.git
git branch -M main
git push -u origin main
```

Si ça demande un mot de passe, utilise un Personal Access Token GitHub :
→ github.com → Settings → Developer settings → Personal access tokens → Generate new token

---

## PARTIE 2 — Installer Wrangler

Toujours dans le même CMD :

```cmd
npm install -g wrangler
```

Attends que ça finisse (1-2 min).

---

## PARTIE 3 — Se connecter à Cloudflare

```cmd
npx wrangler login
```

Ça ouvre ton navigateur → connecte-toi avec ton compte Cloudflare → autorise → reviens au terminal.

---

## PARTIE 4 — Créer la base de données D1

```cmd
npx wrangler d1 create filtredns-db --location=weur
```

Le terminal affiche :

```
Created D1 database filtredns-db
database_id = "abc123-def456-ghi789..."
```

COPIE la valeur de database_id (la longue chaîne).

---

## PARTIE 5 — Mettre le database_id dans la config

Ouvre `wrangler.toml` dans le Bloc-notes.

Trouve la ligne :
```
database_id = "TO_FILL_AFTER_CREATION"
```

Remplace TO_FILL_AFTER_CREATION par l'ID copié. Garde les guillemets.
Sauvegarde (Ctrl+S).

---

## PARTIE 6 — Créer les tables en base

```cmd
npx wrangler d1 execute filtredns-db --file=schema.sql
```

Le terminal affiche "Executed X commands" → les tables sont créées.

---

## PARTIE 7 — Configurer les secrets AdGuard Home

Ces commandes te demandent de taper une valeur. Rien ne s'affiche quand tu tapes — c'est normal.

```cmd
npx wrangler secret put ADGUARD_URL
```
→ tape : http://89.168.40.235:3000 → Entrée

```cmd
npx wrangler secret put ADGUARD_USER
```
→ tape ton login admin AdGuard → Entrée

```cmd
npx wrangler secret put ADGUARD_PASS
```
→ tape ton mot de passe admin AdGuard → Entrée

---

## PARTIE 8 — Déployer sur Cloudflare

```cmd
npx wrangler deploy
```

Le terminal affiche :

```
Uploaded filtredns
Published filtredns
  https://filtredns.xxxxxxx.workers.dev
```

NOTE le lien workers.dev affiché.

---

## PARTIE 9 — Relier au domaine rpisimon.uk

1. Va sur https://dash.cloudflare.com
2. Clique sur rpisimon.uk → DNS → Records
3. "Ajouter un enregistrement" :
   - Type : CNAME
   - Nom : filtredns
   - Cible : le lien workers.dev de l'étape 8 (sans https://)
   - Proxy : activé (icône orange)
4. Sauvegarder

---

## PARTIE 10 — Pousser les changements sur GitHub

```cmd
git add .
git commit -m "Config wrangler avec database_id"
git push
```

---

## PARTIE 11 — Tester

Ouvre dans ton navigateur : https://filtredns.rpisimon.uk

Vérifie :
1. L'écran d'accueil s'affiche
2. Tu peux créer un profil
3. Tu vois le hostname DNS
4. Tu peux proposer un site à bloquer
5. Le DNS de base (dns.rpisimon.uk) est affiché comme alternative

---

## Pour les mises à jour futures

Quand le code change :

```cmd
cd D:\Dev\filtredns
git add .
git commit -m "description du changement"
git push
npx wrangler deploy
```

---

## Commandes utiles

| Action | Commande |
|--------|----------|
| Déployer | npx wrangler deploy |
| Voir les logs | npx wrangler tail |
| Lister les utilisateurs | npx wrangler d1 execute filtredns-db --command="SELECT * FROM users" |
| Lister les parrains | npx wrangler d1 execute filtredns-db --command="SELECT * FROM parrains" |
| Voir les suggestions | npx wrangler d1 execute filtredns-db --command="SELECT * FROM suggestions" |
| Reset PIN d'un parrain | npx wrangler d1 execute filtredns-db --command="DELETE FROM parrains WHERE display_name='marc'" |

Pour le reset PIN : tu supprimes le parrain, le filleul recevra un nouveau code d'invitation et pourra réassocier son parrain.

---

## Résumé de l'architecture

```
Utilisateur → filtredns.rpisimon.uk (Cloudflare Worker)
                    ↓
              Cloudflare D1 (base de données, Europe Ouest)
                    ↓
              AdGuard Home API (89.168.40.235:3000)
                    ↓
              DNS filtré → dns.rpisimon.uk / prenom.dns.rpisimon.uk
```
