# Projet AEGIS — Sécurisation du SI TechSud

> **IPSSI — Promotion BTC1 — 2026**  
> Module : Sécurité des Systèmes d'Information (SSI)  
> Référence : TS-2026-SSI-001

---

## Contexte

Le 18 avril 2026, la PME TechSud a subi une compromission critique de son serveur principal (`SRV-PROD-01`) :

- Connexion SSH non autorisée depuis un **nœud Tor** (`185.220.101.47`)
- Processus malveillant `kworker/u4:2` consommant **80 % du CPU**
- **Webshell PHP** `shell.php` déposé via le formulaire d'upload
- Entrée **cron malveillante** exécutant un binaire ELF toutes les 5 minutes
- Logs `auth.log` **partiellement effacés** (période : 17/04 08h00 → 18/04 21h00)

Notre équipe a été mandatée pour auditer, sécuriser et documenter l'infrastructure.

---

## Objectifs du projet

| Objectif | Statut |
|---|---|
| Déployer une VM Linux isolée | ✅ |
| Durcir le service SSH | ✅ |
| Configurer le pare-feu UFW | ✅ |
| Mettre en place Fail2ban | ✅ |
| Analyser les logs et IOC | ✅ |
| Développer un script d'audit Python | ✅ |
| Rédiger le rapport d'audit complet | ✅ |
| Analyser la conformité RGPD | ✅ |

---

## Stack technique

| Composant | Technologie |
|---|---|
| OS de lab | Kali Linux Rolling (VMware Workstation) |
| Admin distante | OpenSSH — port 2222 |
| Pare-feu hôte | UFW (Uncomplicated Firewall) |
| IPS | Fail2ban 1.1.x |
| Audit automatisé | Python 3 |
| Scan réseau | Nmap 7.x |
| Versioning | Git / GitHub |

---

## Mesures de sécurisation déployées

### 1. Durcissement SSH

Fichier modifié : `/etc/ssh/sshd_config`

```
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 60
```

- Migration du port 22 → **2222** (réduction de l'exposition aux scans automatisés)
- Désactivation de l'accès root direct
- **Authentification par clé Ed25519 exclusive** (mots de passe désactivés)
- Limitation à 3 tentatives d'authentification

### 2. Pare-feu UFW

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp
sudo ufw enable
```

- Politique **default deny** sur toutes les connexions entrantes
- Seul le port **2222/tcp** autorisé en entrée
- Vérification : `sudo ufw status verbose`

### 3. Fail2ban — Protection anti-bruteforce

Configuration `/etc/fail2ban/jail.local` :

```ini
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 10m
findtime = 5m
```

- Bannissement automatique après **3 échecs** en 5 minutes
- Durée de ban : 10 minutes (configurable)
- Testé avec succès : 1 IP bannie lors des tests

### 4. Nettoyage du système

- Désactivation du shell interactif du compte `postgres` (`/usr/sbin/nologin`)
- Permissions `/home/techsud` et `/home/adminsec` restreintes à `chmod 700`
- Désactivation des services inutiles : `avahi-daemon`, `bluetooth`, `cups`
- Mise à jour complète du système (`apt full-upgrade`)

---

## Script d'audit Python

### Fichier : `audit_ssh.py`

Le script vérifie automatiquement l'état de sécurité du serveur et génère deux rapports :

| Fonction | Vérification |
|---|---|
| `audit_systeme()` | Hostname, OS, kernel, uptime |
| `audit_ssh()` | Port, PermitRootLogin, PasswordAuthentication, PubkeyAuthentication, MaxAuthTries |
| `audit_ufw()` | Statut UFW, politique default, règles actives |
| `audit_fail2ban()` | Service actif, jail SSH, tentatives/bans |
| `audit_ports()` | Ports ouverts, alertes sur ports critiques (22, 80, 3306…) |
| `audit_utilisateurs()` | Shells interactifs, comptes sans mot de passe, permissions /home |
| `audit_services()` | Services actifs, détection de services dangereux |
| `audit_mises_a_jour()` | Paquets disponibles |
| `audit_ioc()` | Recherche des IOC TechSud (backdoor, webshell, crons malveillants) |
| `exporter_resultats()` | Export `rapport_audit.json` + `rapport_audit.txt` |

### Exécution

```bash
sudo python3 audit_ssh.py
```

### Fichiers générés

- `rapport_audit.json` — rapport structuré (intégrable dans un outil SIEM)
- `rapport_audit.txt` — rapport lisible humain

---

## Analyse des vecteurs d'attaque (TechSud)

| IOC identifié | Vecteur d'attaque | Mesure appliquée |
|---|---|---|
| `/tmp/.x11-unix/sshd_bak` (ELF 64 bits) | Exécution de code post-compromission | Suppression + audit IOC automatisé |
| `/etc/cron.d/sysupdate` (cron malveillant) | Persistance — exécution toutes les 5 min | Suppression + audit cron automatisé |
| `shell.php` dans `/var/www/html/upload/` | Upload non filtré → webshell | Audit répertoires upload |
| Connexion SSH via `compte deploy` | Mot de passe faible / compte non désactivé | Désactivation comptes inutiles |
| Logs `auth.log` effacés | Suppression de traces forensiques | Centralisation des logs recommandée |
| Connexion C2 vers `45.142.212.100:4444` | Beacon sortant (reverse shell) | Pare-feu + surveillance sortante |

---

## Conformité RGPD

| Article RGPD | Mesure technique |
|---|---|
| Art. 32 — Confidentialité | SSH par clé, PermitRootLogin no, UFW |
| Art. 32 — Intégrité | Fail2ban, désactivation services inutiles |
| Art. 33 — Notification violation | Logs SSH centralisés, Fail2ban tracé |
| Privacy by Design | Principe du moindre privilège sur les comptes |

---

## Structure du dépôt

```
aegis-groupe/
├── audit_ssh.py                          # Script d'audit principal
├── README.md                             # Ce fichier
├── rapport/
│   ├── ProjetAEGIS-final.pdf             # Rapport d'audit complet
│   ├── L_audit_Conformite_RGPD.docx      # Analyse RGPD détaillée
│   └── commandes.docx                    # Référentiel des commandes utilisées
└── schemas/
    ├── schema-infrastructure-initiale.png
    ├── schema-infrastructure-apres-securisation.png
    ├── schema-deroulement-projet.png
    └── schema-flux-reseaux-durci.png
```

---

## Équipe

| Membre | Rôle |
|---|---|
| **Yaya** | Administrateur Système & Sécurité — déploiement VM, hardening SSH, script Python |
| **Yvana** | Auditeur Sécurité — rapport écrit, analyse de risques, IOC |
| **Gyessi** | Responsable Conformité — section RGPD, soutenance |

---

## Références

- [man.debian.org](https://man.debian.org)
- [wiki.archlinux.org](https://wiki.archlinux.org)
- [fail2ban.readthedocs.io](https://fail2ban.readthedocs.io)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [RGPD — Article 32](https://www.cnil.fr/fr/reglement-europeen-protection-donnees/chapitre4)

---

*Document pédagogique — IPSSI BTC1 2026 — Ne pas diffuser en dehors du cadre du cours.*