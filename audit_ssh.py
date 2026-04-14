import subprocess

def audit():
    print("--- RAPPORT D'AUDIT AEGIS ---")
    
    # Vérification SSH Port
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            if "Port 2222" in f.read():
                print("[OK] SSH utilise le port 2222")
            else:
                print("[ATTENTION] SSH est toujours sur le port par défaut")
    except:
        print("[ERREUR] Impossible de lire la config SSH")

    # Vérification Pare-feu
    status = subprocess.getoutput("sudo ufw status")
    if "active" in status:
        print("[OK] Pare-feu UFW est ACTIF")
    else:
        print("[ATTENTION] Pare-feu UFW est INACTIF")

if __name__ == "__main__":
    audit()
