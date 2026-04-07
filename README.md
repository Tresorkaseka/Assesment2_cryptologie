# RSA Handshake Sécurisé

Projet d'évaluation qui met en place un canal de communication sécurisé entre un client de démonstration et un serveur d'API grâce à un handshake RSA suivi d'un chiffrement AES-GCM.

## Objectif

L'API de messagerie était initialement pensée comme un canal en texte clair. Le projet ajoute une couche de sécurité hybride :

- RSA 2048 bits pour échanger la clé de session
- AES-256-GCM pour protéger les messages applicatifs
- stockage en mémoire des sessions pendant 1 heure
- conteneurisation Docker avec réseau interne isolé

## Structure du projet

- `server/` : application FastAPI sécurisée
- `client/` : client de démonstration et mode interactif
- `shared/` : primitives cryptographiques et schémas de données
- `keys/` : stockage persistant des clés RSA générées au démarrage
- `rapport/` : rapport PDF final

## Fonctionnement

### 1. Démarrage du serveur

Le serveur génère ou recharge automatiquement sa paire de clés RSA au lancement. La clé publique est exposée via `GET /public-key`.

### 2. Handshake

Le client récupère la clé publique, génère localement une clé AES-256, la chiffre avec RSA-OAEP, puis l'envoie au serveur via `POST /handshake`.

### 3. Échange applicatif

Une fois la session créée, le client chiffre ses messages avec AES-256-GCM et les envoie sur `POST /message` avec l'en-tête `X-Session-ID`.

### 4. Sécurité

Le middleware serveur refuse toute requête sans session valide et journalise les tentatives non authentifiées. Le chiffrement AES-GCM permet aussi de détecter toute altération du message.

## Lancer le projet

### Avec Docker

```bash
docker compose up --build
```

### Client interactif local

Dans un autre terminal, depuis la racine du projet :

```bash
python -m client.app.main --server-url http://127.0.0.1:8000 --interactive
```

### Simulation d'attaque

```bash
python -m client.app.main --server-url http://127.0.0.1:8000 --attack tamper
```

## Démonstration attendue

- récupération de la clé publique
- handshake RSA réussi
- envoi d'un message chiffré
- visualisation du trafic avec Wireshark
- rejet d'un message altéré

## Vérification

```bash
pytest -q
```

## Rapport

Le rapport final est disponible dans `rapport/handshake_report.pdf`.
