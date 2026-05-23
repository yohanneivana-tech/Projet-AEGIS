import subprocess
import json
import datetime
import os
import sys

RAPPORT_FILE = "rapport_audit.json"
RAPPORT_TXT  = "rapport_audit.txt"

resultats = {}

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def run(cmd):
    """Exécute une commande shell et retourne la sortie (str)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception as e:
        return f"[ERREUR] {e}"


def titre(texte):
    print(f"\n{'='*55}")
    print(f"  {texte}")
    print(f"{'='*55}")


def ok(msg):
    print(f"  [OK]       {msg}")


def warn(msg):
    print(f"  [ATTENTION] {msg}")


def erreur(msg):
    print(f"  [ERREUR]   {msg}")


# ─────────────────────────────────────────────────────────────
# 1. Informations système
# ─────────────────────────────────────────────────────────────

def audit_systeme():
    titre("1 · INFORMATIONS SYSTÈME")
    hostname  = run(["hostname"])
    os_info   = run(["lsb_release", "-d"])
    kernel    = run(["uname", "-r"])
    arch      = run(["uname", "-m"])
    uptime    = run(["uptime", "-p"])

    infos = {
        "hostname": hostname,
        "os": os_info.replace("Description:\t", ""),
        "kernel": kernel,
        "architecture": arch,
        "uptime": uptime,
    }

    for k, v in infos.items():
        print(f"  {k:<15}: {v}")

    resultats["systeme"] = infos


# ─────────────────────────────────────────────────────────────
# 2. Configuration SSH
# ─────────────────────────────────────────────────────────────

def audit_ssh():
    titre("2 · CONFIGURATION SSH")
    sshd_config = "/etc/ssh/sshd_config"
    rapport_ssh = {}

    if not os.path.exists(sshd_config):
        erreur("Fichier sshd_config introuvable.")
        resultats["ssh"] = {"erreur": "fichier absent"}
        return

    with open(sshd_config, "r") as f:
        contenu = f.read()

    # Port
    port = "22"
    for ligne in contenu.splitlines():
        l = ligne.strip()
        if l.startswith("Port ") and not l.startswith("#"):
            port = l.split()[1]
    if port != "22":
        ok(f"Port SSH : {port} (port non-standard)")
        rapport_ssh["port"] = {"valeur": port, "statut": "OK"}
    else:
        warn("Port SSH : 22 (port par défaut — risque de scan automatisé)")
        rapport_ssh["port"] = {"valeur": port, "statut": "ATTENTION"}

    # PermitRootLogin
    root_login = "non défini (défaut : prohibit-password)"
    for ligne in contenu.splitlines():
        l = ligne.strip()
        if l.lower().startswith("permitrootlogin") and not l.startswith("#"):
            root_login = l.split(None, 1)[1]
    if root_login.lower() in ("no", "false"):
        ok(f"PermitRootLogin : {root_login}")
        rapport_ssh["permit_root_login"] = {"valeur": root_login, "statut": "OK"}
    else:
        warn(f"PermitRootLogin : {root_login} — désactiver avec 'no'")
        rapport_ssh["permit_root_login"] = {"valeur": root_login, "statut": "ATTENTION"}

    # PasswordAuthentication
    pwd_auth = "yes"  # défaut OpenSSH
    for ligne in contenu.splitlines():
        l = ligne.strip()
        if l.lower().startswith("passwordauthentication") and not l.startswith("#"):
            pwd_auth = l.split(None, 1)[1]
    if pwd_auth.lower() in ("no", "false"):
        ok("PasswordAuthentication : no (auth par clé exclusive — BIEN)")
        rapport_ssh["password_auth"] = {"valeur": pwd_auth, "statut": "OK"}
    else:
        warn("PasswordAuthentication : yes — DÉSACTIVER après avoir déployé votre clé publique")
        rapport_ssh["password_auth"] = {"valeur": pwd_auth, "statut": "ATTENTION"}

    # PubkeyAuthentication
    pubkey = "yes"
    for ligne in contenu.splitlines():
        l = ligne.strip()
        if l.lower().startswith("pubkeyauthentication") and not l.startswith("#"):
            pubkey = l.split(None, 1)[1]
    if pubkey.lower() in ("yes", "true"):
        ok(f"PubkeyAuthentication : {pubkey}")
        rapport_ssh["pubkey_auth"] = {"valeur": pubkey, "statut": "OK"}
    else:
        warn(f"PubkeyAuthentication : {pubkey} — activer l'authentification par clé")
        rapport_ssh["pubkey_auth"] = {"valeur": pubkey, "statut": "ATTENTION"}

    # MaxAuthTries
    max_tries = "6"
    for ligne in contenu.splitlines():
        l = ligne.strip()
        if l.lower().startswith("maxauthtries") and not l.startswith("#"):
            max_tries = l.split(None, 1)[1]
    if int(max_tries) <= 3:
        ok(f"MaxAuthTries : {max_tries}")
        rapport_ssh["max_auth_tries"] = {"valeur": max_tries, "statut": "OK"}
    else:
        warn(f"MaxAuthTries : {max_tries} — recommandé : 3 ou moins")
        rapport_ssh["max_auth_tries"] = {"valeur": max_tries, "statut": "ATTENTION"}

    # LoginGraceTime
    grace = "2m"
    for ligne in contenu.splitlines():
        l = ligne.strip()
        if l.lower().startswith("logingracetime") and not l.startswith("#"):
            grace = l.split(None, 1)[1]
    ok(f"LoginGraceTime : {grace}")
    rapport_ssh["login_grace_time"] = {"valeur": grace, "statut": "INFO"}

    resultats["ssh"] = rapport_ssh


# ─────────────────────────────────────────────────────────────
# 3. Pare-feu UFW
# ─────────────────────────────────────────────────────────────

def audit_ufw():
    titre("3 · PARE-FEU UFW")
    rapport_ufw = {}

    status = run(["sudo", "ufw", "status", "verbose"])

    if "Status: active" in status:
        ok("UFW est ACTIF")
        rapport_ufw["statut"] = "actif"
    else:
        warn("UFW est INACTIF — le serveur est exposé sans filtrage réseau")
        rapport_ufw["statut"] = "inactif"

    if "Default: deny" in status or "deny (incoming)" in status:
        ok("Politique par défaut : DENY (tout bloquer par défaut)")
        rapport_ufw["default_policy"] = "deny"
    else:
        warn("Politique par défaut non restrictive — vérifier 'ufw default deny incoming'")
        rapport_ufw["default_policy"] = "non restrictif"

    # Lister les règles actives
    regles = []
    for ligne in status.splitlines():
        if "ALLOW" in ligne or "DENY" in ligne:
            regles.append(ligne.strip())
    if regles:
        ok(f"Règles actives ({len(regles)}) :")
        for r in regles:
            print(f"           → {r}")
    rapport_ufw["regles"] = regles

    resultats["ufw"] = rapport_ufw


# ─────────────────────────────────────────────────────────────
# 4. Fail2ban
# ─────────────────────────────────────────────────────────────

def audit_fail2ban():
    titre("4 · FAIL2BAN (IPS)")
    rapport_f2b = {}

    status = run(["sudo", "systemctl", "is-active", "fail2ban"])
    if status == "active":
        ok("Service Fail2ban : actif")
        rapport_f2b["service"] = "actif"
    else:
        warn(f"Service Fail2ban : {status}")
        rapport_f2b["service"] = status

    jail_status = run(["sudo", "fail2ban-client", "status", "sshd"])
    if "Status for the jail" in jail_status:
        ok("Jail SSH détectée :")
        for ligne in jail_status.splitlines():
            if any(k in ligne for k in ["Currently", "Total", "Banned", "Filter", "Actions"]):
                print(f"           {ligne.strip()}")
        rapport_f2b["jail_sshd"] = jail_status
    else:
        warn("Jail 'sshd' non trouvée — vérifier /etc/fail2ban/jail.local")
        rapport_f2b["jail_sshd"] = "absente"

    resultats["fail2ban"] = rapport_f2b


# ─────────────────────────────────────────────────────────────
# 5. Ports ouverts
# ─────────────────────────────────────────────────────────────

def audit_ports():
    titre("5 · PORTS OUVERTS (ss -tulnp)")
    rapport_ports = []

    sortie = run(["ss", "-tulnp"])
    lignes = sortie.splitlines()

    ports_critiques = {"22": "SSH par défaut", "80": "HTTP", "3306": "MariaDB", "5432": "PostgreSQL",
                       "23": "Telnet", "21": "FTP", "445": "SMB"}
    alertes = []

    for ligne in lignes[1:]:  # skip header
        if "LISTEN" in ligne:
            rapport_ports.append(ligne.strip())
            for port, label in ports_critiques.items():
                if f":{port}" in ligne and f":2{port}" not in ligne:
                    alertes.append(f"Port {port} ({label}) détecté ouvert")

    if rapport_ports:
        ok(f"{len(rapport_ports)} socket(s) en écoute :")
        for p in rapport_ports:
            print(f"           {p}")
    else:
        ok("Aucun port en écoute détecté.")

    if alertes:
        for a in alertes:
            warn(a)
    else:
        ok("Aucun port critique non autorisé détecté.")

    resultats["ports"] = {"sockets": rapport_ports, "alertes": alertes}


# ─────────────────────────────────────────────────────────────
# 6. Comptes utilisateurs
# ─────────────────────────────────────────────────────────────

def audit_utilisateurs():
    titre("6 · COMPTES UTILISATEURS")
    rapport_users = {}

    # Comptes avec shell interactif
    shells_interactifs = []
    try:
        with open("/etc/passwd", "r") as f:
            for ligne in f:
                parts = ligne.strip().split(":")
                if len(parts) >= 7 and parts[6] in ("/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ksh"):
                    shells_interactifs.append({"user": parts[0], "uid": parts[2], "shell": parts[6]})
    except Exception as e:
        erreur(f"Lecture /etc/passwd : {e}")

    ok(f"Comptes avec shell interactif ({len(shells_interactifs)}) :")
    for u in shells_interactifs:
        flag = " ← compte de service !" if u["uid"] not in ("0",) and u["user"] not in ("root", "techsud", "adminsec", "ivana") else ""
        print(f"           {u['user']} (uid={u['uid']}) {u['shell']}{flag}")
    rapport_users["shells_interactifs"] = shells_interactifs

    # Comptes sans mot de passe
    shadow_output = run(["sudo", "awk", "-F:", "($2 == \"\" || $2 == \"!\") {print $1}", "/etc/shadow"])
    comptes_sans_mdp = [l for l in shadow_output.splitlines() if l.strip() and "[ERREUR]" not in l]
    if comptes_sans_mdp:
        warn(f"Comptes sans mot de passe ou verrouillés : {', '.join(comptes_sans_mdp)}")
    else:
        ok("Aucun compte sans mot de passe détecté.")
    rapport_users["sans_mot_de_passe"] = comptes_sans_mdp

    # Permissions /home
    ok("Permissions des répertoires /home :")
    home_check = run(["ls", "-la", "/home"])
    for ligne in home_check.splitlines()[1:]:
        perms = ligne.split()[0] if ligne.split() else ""
        nom   = ligne.split()[-1] if ligne.split() else ""
        if perms and not perms.startswith("total"):
            if "drwx------" in perms:
                print(f"           {nom} : {perms} ✓")
            elif nom not in (".", ".."):
                warn(f"{nom} : {perms} — recommandé chmod 700")
    rapport_users["home"] = home_check

    resultats["utilisateurs"] = rapport_users


# ─────────────────────────────────────────────────────────────
# 7. Services actifs
# ─────────────────────────────────────────────────────────────

def audit_services():
    titre("7 · SERVICES ACTIFS")
    services_dangereux = ["avahi-daemon", "bluetooth", "cups", "atftpd", "telnet", "rsh", "rlogin"]
    rapport_services = {"actifs": [], "alertes": []}

    sortie = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
    for ligne in sortie.splitlines():
        if ".service" in ligne:
            nom = ligne.strip().split()[0]
            rapport_services["actifs"].append(nom)
            for danger in services_dangereux:
                if danger in nom:
                    warn(f"Service non recommandé actif : {nom}")
                    rapport_services["alertes"].append(nom)

    ok(f"{len(rapport_services['actifs'])} service(s) en cours d'exécution.")
    if not rapport_services["alertes"]:
        ok("Aucun service dangereux connu détecté.")

    resultats["services"] = rapport_services


# ─────────────────────────────────────────────────────────────
# 8. Mises à jour disponibles
# ─────────────────────────────────────────────────────────────

def audit_mises_a_jour():
    titre("8 · MISES À JOUR DISPONIBLES")
    rapport_maj = {}

    run(["sudo", "apt", "update", "-qq"])
    sortie = run(["apt", "list", "--upgradable"])
    paquets = [l for l in sortie.splitlines() if "/" in l]

    if not paquets:
        ok("Système à jour — aucun paquet à mettre à jour.")
        rapport_maj["paquets_disponibles"] = 0
    else:
        warn(f"{len(paquets)} paquet(s) à mettre à jour.")
        for p in paquets[:10]:
            print(f"           {p}")
        if len(paquets) > 10:
            print(f"           ... et {len(paquets)-10} autre(s).")
        rapport_maj["paquets_disponibles"] = len(paquets)

    resultats["mises_a_jour"] = rapport_maj


# ─────────────────────────────────────────────────────────────
# 9. Analyse forensique des IOC (AEGIS TechSud)
# ─────────────────────────────────────────────────────────────

def audit_ioc():
    titre("9 · ANALYSE DES IOC — INDICATEURS DE COMPROMISSION")
    rapport_ioc = {"suspects": [], "propres": []}

    ioc_a_verifier = [
        ("/tmp/.x11-unix/sshd_bak",         "Binaire ELF suspect (backdoor)"),
        ("/etc/cron.d/sysupdate",            "Entrée cron malveillante"),
        ("/var/www/html/upload/shell.php",   "Webshell PHP"),
        ("/var/www/html/upload/",            "Répertoire upload sans protection"),
    ]

    for chemin, description in ioc_a_verifier:
        if os.path.exists(chemin):
            warn(f"TROUVÉ : {chemin} — {description}")
            rapport_ioc["suspects"].append({"chemin": chemin, "description": description})
        else:
            ok(f"Absent (nettoyé) : {chemin}")
            rapport_ioc["propres"].append(chemin)

    # Vérification cron général
    crons_suspects = []
    cron_dirs = ["/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
                 "/var/spool/cron/crontabs/"]
    for d in cron_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                try:
                    with open(fp, "r") as fh:
                        contenu = fh.read()
                    if "/tmp/" in contenu or "wget" in contenu or "curl" in contenu:
                        crons_suspects.append(fp)
                        warn(f"Cron suspect : {fp}")
                except Exception:
                    pass

    rapport_ioc["crons_suspects"] = crons_suspects
    if not crons_suspects:
        ok("Aucun cron suspect détecté.")

    resultats["ioc"] = rapport_ioc


# ─────────────────────────────────────────────────────────────
# 10. Export JSON + TXT
# ─────────────────────────────────────────────────────────────

def exporter_resultats():
    titre("10 · EXPORT DES RÉSULTATS")

    meta = {
        "projet": "AEGIS — TechSud Sécurisation SI",
        "ecole": "IPSSI BTC1",
        "date_audit": datetime.datetime.now().isoformat(),
        "auditeurs": ["Yaya — Admin Sys", "Yvana — Audit", "Gyessi — Conformité"],
    }
    rapport_complet = {"meta": meta, "resultats": resultats}

    # JSON
    with open(RAPPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(rapport_complet, f, ensure_ascii=False, indent=2)
    ok(f"Rapport JSON exporté : {RAPPORT_FILE}")

    # TXT lisible
    with open(RAPPORT_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("RAPPORT D'AUDIT AEGIS — IPSSI BTC1\n")
        f.write(f"Date : {meta['date_audit']}\n")
        f.write("=" * 60 + "\n\n")

        def section(titre_s, data):
            f.write(f"\n[ {titre_s} ]\n")
            if isinstance(data, dict):
                for k, v in data.items():
                    f.write(f"  {k}: {v}\n")
            elif isinstance(data, list):
                for item in data:
                    f.write(f"  - {item}\n")
            else:
                f.write(f"  {data}\n")

        for cle, val in resultats.items():
            section(cle.upper(), val)

    ok(f"Rapport TXT exporté  : {RAPPORT_TXT}")


# ─────────────────────────────────────────────────────────────
# MENU PRINCIPAL
# ─────────────────────────────────────────────────────────────

def afficher_resume():
    titre("RÉSUMÉ DE CONFORMITÉ")
    scores = {
        "ssh":          resultats.get("ssh", {}),
        "ufw":          resultats.get("ufw", {}),
        "fail2ban":     resultats.get("fail2ban", {}),
        "ioc":          resultats.get("ioc", {}),
    }

    ok_count   = 0
    warn_count = 0

    def compte(d):
        nonlocal ok_count, warn_count
        if isinstance(d, dict):
            for v in d.values():
                if isinstance(v, dict) and "statut" in v:
                    if v["statut"] == "OK":
                        ok_count += 1
                    elif v["statut"] == "ATTENTION":
                        warn_count += 1
                elif isinstance(v, dict):
                    compte(v)

    for _, v in scores.items():
        compte(v)

    if resultats.get("ufw", {}).get("statut") == "actif":
        ok_count += 1
    else:
        warn_count += 1

    if resultats.get("fail2ban", {}).get("service") == "actif":
        ok_count += 1
    else:
        warn_count += 1

    ioc_suspects = len(resultats.get("ioc", {}).get("suspects", []))
    if ioc_suspects > 0:
        warn(f"{ioc_suspects} IOC suspect(s) toujours présent(s) sur le système !")
        warn_count += ioc_suspects
    else:
        ok("Aucun IOC connu détecté.")

    print(f"\n  Points conformes   : {ok_count}")
    print(f"  Points à corriger  : {warn_count}")
    print()
    if warn_count == 0:
        print("  → Serveur conforme aux bonnes pratiques AEGIS.")
    else:
        print("  → Des améliorations sont nécessaires. Consulter le rapport.")


def main():
    if os.geteuid() != 0:
        print("[AVERTISSEMENT] Certaines vérifications nécessitent sudo.")
        print("                Relancer avec : sudo python3 audit_ssh.py\n")

    print("\n" + "=" * 55)
    print("  AUDIT AEGIS — Sécurisation SI TechSud")
    print("  IPSSI BTC1 — 2026")
    print("=" * 55)

    audit_systeme()
    audit_ssh()
    audit_ufw()
    audit_fail2ban()
    audit_ports()
    audit_utilisateurs()
    audit_services()
    audit_mises_a_jour()
    audit_ioc()
    exporter_resultats()
    afficher_resume()

    print("\nAudit terminé. Fichiers générés :")
    print(f"  → {RAPPORT_FILE}")
    print(f"  → {RAPPORT_TXT}\n")


if __name__ == "__main__":
    main()