# render.yaml — Configuration déploiement Render
# Déposer ce fichier à la racine du dépôt GitHub

services:
  - type: web
    name: district-bfc-arbitrage
    env: node
    region: frankfurt
    plan: free
    buildCommand: npm install
    startCommand: node server.js
    healthCheckPath: /api/health
    envVars:
      - key: NODE_ENV
        value: production
      - key: JWT_SECRET
        generateValue: true
      - key: JWT_REFRESH_SECRET
        generateValue: true
      - key: ANTHROPIC_API_KEY
        sync: false          # À saisir manuellement dans le dashboard Render
      - key: DB_PATH
        value: /data/bfc.db  # Chemin sur le disque persistant

# Disque persistant pour la base SQLite (1 Go = ~7$/mois)
# SUPPRIMER ce bloc si vous utilisez Supabase à la place
    disk:
      name: bfc-data
      mountPath: /data
      sizeGB: 1

# ═══════════════════════════════════════
# ALTERNATIVE GRATUITE : Supabase PostgreSQL
# ═══════════════════════════════════════
# 1. Créer un projet gratuit sur https://supabase.com
# 2. Récupérer la DATABASE_URL dans Settings > Database
# 3. Ajouter DATABASE_URL dans les env vars Render
# 4. Remplacer better-sqlite3 par pg dans server.js
# ═══════════════════════════════════════
