# Projet AEGIS
Projet AEGIS - Sécurisation de l'Infrastructure TechSud

Ce projet a été réalisé dans le cadre de l'unité d'enseignement Sécurité des Systèmes d'Information (SSI) au sein de l'école IPSSI (Promotion BTC1 - 2026).

L'objectif principal est de répondre à un incident de sécurité ayant touché la PME TechSud en déployant une infrastructure Linux durcie, en automatisant l'audit de conformité et en assurant le respect des normes RGPD.

Présentation du Projet

À la suite d'une compromission majeure du système d'information de TechSud, notre équipe a été mandatée pour :

Auditer l'existant : Identifier les vecteurs d'attaque utilisés.

Sécuriser l'hôte : Appliquer des mesures de durcissement (Hardening) sur une VM Linux.

Surveiller les flux : Mettre en place des mécanismes de détection et de blocage d'intrusions.

Automatiser la conformité : Développer un script de vérification pour garantir le maintien du niveau de sécurité.

Stack Technique

OS : Ubuntu 24.04 LTS (VMware Workstation)

Administration : OpenSSH (Server & Client)

Sécurité Réseau : UFW (Uncomplicated Firewall)

IPS/IDS : Fail2ban

Audit : Python 3 (Scripts personnalisés) & Nmap (Scans externes)

Gestion de version : Git & GitHub

Mesures de Sécurisation Déployées

1. Durcissement du service SSH (SSH Hardening)

Le service SSH étant la porte d'entrée principale, nous avons appliqué les mesures suivantes :

Port non-standard : Migration du port 22 vers le port 2222 pour limiter les scans automatiques et les attaques par force brute.

Désactivation du compte Root : Configuration de PermitRootLogin no pour forcer l'usage d'un compte utilisateur standard avec sudo.

Authentification par Clés : Abandon des mots de passe au profit de clés asymétriques Ed25519 (plus sécurisées et performantes).

2. Configuration du Pare-feu (UFW)

Mise en place d'une politique de sécurité de type "Whitelisting" :

Fermeture de tous les ports par défaut (Default Deny).

Ouverture exclusive du port 2222/tcp pour l'administration distante.

Vérification systématique via la commande sudo ufw status verbose.

3. Système de Prévention d'Intrusion (Fail2ban)

Installation et configuration de Fail2ban pour surveiller les logs d'authentification :

Analyse en temps réel de /var/log/auth.log.

Bannissement automatique des adresses IP après 3 tentatives de connexion infructueuses.

Configuration d'une "jail" spécifique pour le port SSH personnalisé.

 Script d'Audit Python (audit_ssh.py)

Nous avons développé un script Python permettant de vérifier l'état de sécurité du serveur sans intervention manuelle.

Fonctionnalités du script :

Analyse du fichier /etc/ssh/sshd_config pour valider le port utilisé.

Vérification du statut d'activation d'UFW via des appels système sécurisés.

Export JSON : Génération d'un fichier rapport_audit.json structuré pour faciliter l'intégration dans des outils de monitoring tiers.

Exécution :

sudo python3 audit_ssh.py


 Conformité RGPD & Analyse de Risques

Le projet intègre nativement les principes de Privacy by Design :

Article 32 du RGPD : Mise en œuvre de mesures techniques appropriées pour garantir la confidentialité et l'intégrité (Chiffrement SSH, Firewalling).

Traçabilité : Conservation et protection des logs d'accès pour répondre à l'obligation de notification en cas de violation de données (Article 33).

Analyse des Menaces : Réduction de la probabilité des risques de force brute (de "Haute" à "Faible") grâce au couplage Port Custom + Fail2ban.

 Équipe de Projet

Yaya : Administrateur Système & Sécurité (Déploiement VM, Hardening SSH, Script Python).

Yvana : Auditeur Sécurité (Rapport écrit, Analyse de risques).

Gyessi : Responsable Conformité (Section RGPD, Support soutenance).

Projet intensif "Mode Piscine" réalisé du 13 au 17 Avril 2026.