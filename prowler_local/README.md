# Prowler Local — 608 checks, zéro installation

Exécute les 608 checks AWS de Prowler (github.com/prowler-cloud/prowler)
en local via un shim boto3 minimal. Aucun package prowler requis.

## Installation

```bash
pip install -r requirements.txt
```

## Scan

```bash
# Profil unique
python prowler_local.py scan --profile prod-SecurityAudit

# Tous les comptes (accounts.json)
python prowler_local.py scan

# Services spécifiques
python prowler_local.py scan --profile prod-SecurityAudit --services iam,s3,cloudtrail

# Seulement les failures
python prowler_local.py scan --profile prod-SecurityAudit --fail-only

# Multi-régions
python prowler_local.py scan --profile prod-SecurityAudit --regions eu-west-1,eu-west-3
```

## Dashboard

```bash
python prowler_local.py dashboard
# → http://localhost:8050
```

## Explorer les checks

```bash
python prowler_local.py list-checks
python prowler_local.py list-checks --service iam
python prowler_local.py list-checks --severity critical
python prowler_local.py summary
```

## Structure

```
prowler_local/
├── prowler_local.py      ← CLI
├── prowler_shim.py       ← AwsProvider minimal (boto3)
├── run_checks.py         ← Découverte et exécution des checks
├── dashboard_app.py      ← Dashboard Dash local
├── catalog.json          ← Métadonnées des 608 checks
├── accounts.json         ← Configuration des comptes
├── requirements.txt
└── prowler_src/          ← Code source Prowler (checks + services)
    └── prowler/
        ├── providers/aws/services/   ← 608 checks
        └── lib/                      ← Modèles, logger, utilitaires
```
