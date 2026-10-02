#!/usr/bin/env python3
"""Audit local Linux en lecture seule, sans dépendances externes."""
import argparse
import datetime
import json
import ipaddress
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def command(args):
    if not shutil.which(args[0]):
        return None
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def audit():
    findings = []

    def add(check, state, detail, advice=""):
        findings.append(dict(controle=check, etat=state, detail=detail, conseil=advice))

    sockets = command(["ss", "-H", "-lntu"])
    if sockets is None:
        add("Ports en écoute", "INCONNU", "Commande ss indisponible ou refusée.", "Installer iproute2 puis relancer.")
    else:
        exposed = []
        for line in sockets.splitlines():
            fields = line.split()
            if len(fields) >= 5:
                address = fields[4]
                if not address.startswith(("127.", "[::1]:", "::1:")):
                    exposed.append(line)
        add("Ports en écoute", "À EXAMINER" if exposed else "OK", "\n".join(exposed) or "Aucun port non local observé.", "Vérifier que chaque service est nécessaire. Une écoute ne prouve pas une exposition sur Internet.")

    firewall = command(["ufw", "status"])
    if firewall and "Status: active" in firewall:
        add("Pare-feu", "OK", firewall)
    else:
        firewalld = command(["firewall-cmd", "--state"])
        nft = command(["nft", "list", "ruleset"])
        if firewalld == "running":
            add("Pare-feu", "OK", "firewalld fonctionne ; règles à examiner.")
        elif nft:
            add("Pare-feu", "À EXAMINER", nft, "La présence de règles ne garantit pas un filtrage efficace.")
        else:
            add("Pare-feu", "INCONNU", "Impossible de confirmer le filtrage avec les droits actuels.", "Examiner les règles avec un administrateur avant tout changement, surtout en connexion SSH.")

    checks = [
        ("kernel.randomize_va_space", "2", "Randomisation mémoire", "Activer une randomisation mémoire complète."),
        ("net.ipv4.tcp_syncookies", "1", "Protection SYN", "Examiner l'activation des SYN cookies."),
        ("kernel.kptr_restrict", None, "Adresses du noyau", "Examiner la restriction des pointeurs du noyau."),
    ]
    for key, expected, title, advice in checks:
        value = read("/proc/sys/" + key.replace(".", "/"))
        ok = value == expected if expected is not None else value in ("1", "2")
        add(title, "INCONNU" if value is None else "OK" if ok else "À EXAMINER", f"{key} = {value if value is not None else 'inaccessible'}", advice if not ok else "")

    shadow = Path("/etc/shadow")
    try:
        mode = shadow.stat().st_mode & 0o777
        add("Permissions /etc/shadow", "À EXAMINER" if mode & 0o007 else "OK", f"Mode {mode:03o} ; contenu jamais lu.", "Retirer les droits accordés aux autres utilisateurs." if mode & 0o007 else "")
    except OSError:
        add("Permissions /etc/shadow", "INCONNU", "Métadonnées inaccessibles.")

    sshd = shutil.which("sshd")
    if sshd is None and Path("/usr/sbin/sshd").exists():
        sshd = "/usr/sbin/sshd"
    config = command([sshd, "-T"]) if sshd else None
    if config:
        settings = dict(line.split(None, 1) for line in config.splitlines() if " " in line)
        for key, desired in [("permitrootlogin", "no"), ("passwordauthentication", "no")]:
            value = settings.get(key)
            add("SSH : " + key, "OK" if value == desired else "À EXAMINER", str(value), "Privilégier un compte ordinaire et des clés SSH. Tester une seconde connexion avant de désactiver un accès. Les règles Match peuvent modifier ces valeurs.")
    else:
        add("Configuration SSH", "INCONNU", "Serveur absent ou configuration effective inaccessible.")

    add("Mises à jour et vulnérabilités connues", "NON VÉRIFIÉ", "Cette version ne consulte pas les dépôts ni les bases CVE.", "Vérifier les mises à jour avec le gestionnaire de paquets de la distribution.")
    return dict(date=datetime.datetime.now(datetime.timezone.utc).isoformat(), systeme=platform.platform(), machine=platform.node(), controles=findings)


def direct_audit(export_path=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", metavar="FICHIER", help="Enregistrer le rapport JSON (contient le nom de machine et les ports).")
    args = parser.parse_args(["--json", export_path] if export_path else [])
    if platform.system() != "Linux":
        parser.error("Cet outil nécessite Linux.")
    report = audit()
    print("Linux Garde — audit local en lecture seule\n")
    for item in report["controles"]:
        print(f"[{item['etat']}] {item['controle']}\n  {item['detail']}")
        if item["conseil"]:
            print("  Conseil : " + item["conseil"])
    if args.json:
        # Création exclusive : ne remplace aucun fichier existant.
        fd = os.open(args.json, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
        print("\nRapport enregistré : " + args.json)
    print("\nUn contrôle OK ne garantit pas l'absence de failles. Aucun réglage n'a été modifié.")


def network_scan():
    if not shutil.which("nmap"):
        print("Nmap est absent. Installe le paquet nmap avec le gestionnaire de ta distribution.")
        return
    target = input("Réseau IPv4 autorisé en CIDR (exemple : 192.168.1.0/24) : ").strip()
    try:
        network = ipaddress.ip_network(target, strict=True)
        if network.version != 4 or network.num_addresses > 256:
            print("Choisis un réseau IPv4 de 256 adresses maximum (/24 ou plus petit).")
            return
    except ValueError:
        print("Adresse réseau invalide. Utilise un réseau CIDR, par exemple 192.168.1.0/24.")
        return
    if input("Tu as l'autorisation d'auditer tous ces appareils ? Tape OUI : ").strip() != "OUI":
        print("Scan annulé.")
        return
    print("Recherche des appareils et scan des 1 000 ports TCP les plus fréquents. Cela peut prendre plusieurs minutes.")
    print("Les appareils qui ne répondent pas à la découverte peuvent être manqués.")
    try:
        result = subprocess.run([
            "nmap", "-sT", "--top-ports", "1000", "--open",
            "--max-rate", "100", "--max-retries", "1",
            "--host-timeout", "60s", "-n", str(network),
        ], timeout=600)
        if result.returncode:
            print("Nmap a signalé une erreur ; le scan peut être incomplet.")
    except subprocess.TimeoutExpired:
        print("Durée maximale atteinte ; résultats incomplets.")
    except OSError as error:
        print(f"Impossible de lancer le scan : {error}")
    print("Un port ouvert ne prouve pas une vulnérabilité. UDP, tous les ports TCP et les CVE ne sont pas vérifiés.")



def device_audit(vulnerability_tests=False):
    if not shutil.which("nmap"):
        print("Nmap est absent. Installe le paquet nmap de ta distribution.")
        return
    try:
        address = ipaddress.ip_address(input("Adresse IPv4 de ton appareil local : ").strip())
        ranges = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        if address.version != 4 or not any(address in network for network in ranges):
            print("Utilise une adresse privée locale : 10.x.x.x, 172.16–31.x.x ou 192.168.x.x.")
            return
    except ValueError:
        print("Adresse IP invalide.")
        return
    print("1. Analyse des 1 000 ports TCP fréquents\n2. Analyse des 65 535 ports TCP (plus longue)")
    choice = input("Profil : ").strip()
    if choice not in ("1", "2"):
        print("Profil invalide ; analyse annulée.")
        return
    ports = ["--top-ports", "1000"] if choice == "1" else ["-p", "1-65535"]
    scripts = "ssh2-enum-algos,ssl-cert,http-security-headers,smb2-security-mode"
    if vulnerability_tests:
        scripts += ",smb-vuln-ms17-010,ssl-enum-ciphers"
        print("Tests actifs : détection SMB MS17-010 et négociations TLS répétées. Ils peuvent charger les services.")
    args = ["nmap", "-sT", "-sV", "--version-light", "-Pn", "-n", *ports,
            "--script", scripts,
            "--script-timeout", "30s", "--max-rate", "100", "--max-retries", "1",
            "--host-timeout", "20m", str(address)]
    print("Analyse en cours ; jusqu'à 20 minutes. Ctrl+C pour interrompre.")
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=1250)
    except subprocess.TimeoutExpired:
        print("Durée maximale atteinte ; analyse incomplète.")
        return
    except OSError as error:
        print(f"Analyse impossible : {error}")
        return
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    print("Contrôles : algorithmes SSH, certificat TLS, en-têtes HTTP et signature SMB.")
    if vulnerability_tests:
        print("Si MS17-010 est signalée : appliquer les correctifs Windows et désactiver SMBv1.")
        print("Si des protocoles/chiffrements TLS faibles sont signalés : mettre à jour le service et sa configuration TLS.")
        print("Un contrôle absent, en erreur ou interrompu ne signifie pas que le service est sécurisé.")
    print("Les résultats demandent une interprétation. Une version détectée ne confirme pas une CVE.")
    print("UDP et sécurité radio Wi-Fi ne sont pas analysés. Les délais peuvent rendre le scan incomplet.")
    report = dict(date=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  cible=str(address), profil=choice, tests_vulnerabilites=vulnerability_tests, commande=args, code_retour=result.returncode,
                  sortie=result.stdout, erreurs=result.stderr,
                  conseils=["Mettre à jour les services et le firmware avec les versions du fabricant.",
                            "Désactiver les services inutiles et limiter les accès avec le pare-feu.",
                            "Examiner les paramètres SSH, TLS, HTTP et SMB selon les résultats."])
    path = input("Nouveau fichier JSON pour ce rapport (Entrée pour ignorer) : ").strip()
    if path:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
            print("Rapport enregistré : " + path)
        except OSError as error:
            print(f"Enregistrement impossible : {error}")


def menu():
    try:
        while True:
            print("\n+----------------------------------------+\n|              LINUX GARDE               |\n+----------------------------------------+\n1. Audit de cet ordinateur\n2. Audit local avec rapport JSON\n3. Scanner un réseau autorisé\n4. Aide\n5. Analyse détaillée de mon appareil réseau\n6. Tests ciblés de vulnérabilités (SMB / TLS)\n0. Quitter")
            choice = input("Ton choix : ").strip()
            if choice == "0":
                return
            if choice == "1":
                direct_audit()
            elif choice == "2":
                path = input("Chemin du nouveau rapport JSON (Entrée pour annuler) : ").strip()
                if path:
                    try:
                        direct_audit(path)
                    except OSError as error:
                        print(f"Enregistrement impossible : {error}")
            elif choice == "3":
                network_scan()
            elif choice == "5":
                device_audit()
            elif choice == "6":
                device_audit(vulnerability_tests=True)
            elif choice == "4":
                print("L'audit local lit les réglages de cet ordinateur.\nLe scan réseau utilise Nmap sur un réseau IPv4 autorisé de 256 adresses maximum.\nAucune correction automatique ni exploitation de faille.\nLes rapports peuvent contenir des informations privées sur les machines.")
            else:
                print("Choisis 0, 1, 2, 3, 4, 5 ou 6.")
    except (EOFError, KeyboardInterrupt):
        print("\nOpération interrompue. Menu fermé.")



def banner():
    colored = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    cyan = "\033[1;36m" if colored else ""
    reset = "\033[0m" if colored else ""
    print(cyan + r"""
        /=================\
       /    LINUX GARDE    \
       |       .---.       |
       |       |   |       |
       |      [=====]      |
       |      [  o  ]      |
       |      [_____]      |
        \                 /
         \   PROTECTION   /
          \   & AUDIT    /
           \___________/
    """ + reset)
    print("    Ton reseau. Tes appareils. Leur securite.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true", help="Audit local sans menu.")
    parser.add_argument("--json", metavar="FICHIER", help="Audit local avec rapport JSON.")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Cet outil nécessite Linux.")
    if args.audit or args.json:
        try:
            direct_audit(args.json)
        except OSError as error:
            parser.exit(1, f"Enregistrement impossible : {error}\n")
    else:
        banner()
        menu()


if __name__ == "__main__":
    main()
