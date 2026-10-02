"""Exercices jetables en mémoire : aucune cible réseau ni donnée réelle."""
import datetime
import sqlite3


def sql_login(db, username, password, hardened):
    if hardened:
        return db.execute("SELECT name FROM users WHERE name=? AND password=?", (username, password)).fetchone() is not None
    # Vulnérabilité volontaire, confinée à cette base fictive en mémoire.
    return db.execute(f"SELECT name FROM users WHERE name='{username}' AND password='{password}'").fetchone() is not None


def password_attempts(limited):
    failures = 0
    evidence = []
    for candidate in ("wrong-1", "wrong-2", "wrong-3", "wrong-4", "demo-secret"):
        if limited and failures >= 3:
            evidence.append("BLOQUÉ")
        elif candidate == "demo-secret":
            evidence.append("ACCEPTÉ")
        else:
            failures += 1
            evidence.append("REFUSÉ")
    return evidence


def run_lab():
    db = sqlite3.connect(":memory:")
    try:
        db.execute("CREATE TABLE users(name TEXT, password TEXT)")
        db.execute("INSERT INTO users VALUES (?, ?)", ("demo", "demo-secret"))
        payload = "demo' -- "
        before = sql_login(db, payload, "incorrect", False)
        after = sql_login(db, payload, "incorrect", True)
        valid_after = sql_login(db, "demo", "demo-secret", True)
        wrong_after = sql_login(db, "demo", "incorrect", True)
    finally:
        db.close()
    unbounded = password_attempts(False)
    limited = password_attempts(True)
    return {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": "laboratoire_fictif_en_memoire",
        "cible": "laboratoire intégré — aucun appareil réseau",
        "limite": "Ces résultats concernent uniquement les exercices intégrés, pas vos appareils.",
        "controles": [
            {"controle": "Injection SQL dans une connexion fictive",
             "etat": "FAILLE CONFIRMÉE DANS LE LABO" if before else "NON REPRODUITE",
             "preuve": {"connexion_sans_mot_de_passe_valide": before},
             "correction": "Utiliser des requêtes paramétrées ; ne jamais concaténer les entrées SQL.",
             "retest": "CORRIGÉ POUR CE TEST" if not after and valid_after and not wrong_after else "ÉCHEC DU RETEST",
             "preuve_apres": {"injection_acceptee": after, "connexion_valide": valid_after, "mauvais_mot_de_passe_accepte": wrong_after}},
            {"controle": "Essais de mots de passe sur un compte fictif",
             "etat": "FAIBLESSE CONFIRMÉE DANS LE LABO" if "ACCEPTÉ" in unbounded else "NON REPRODUITE",
             "preuve": {"tentatives": unbounded, "nombre_maximal": 5},
             "correction": "Limiter les tentatives et ajouter une temporisation ; envisager une authentification multifacteur. Le seuil de 3 est un exemple pédagogique.",
             "retest": "CORRIGÉ POUR CE TEST" if limited == ["REFUSÉ"] * 3 + ["BLOQUÉ"] * 2 else "ÉCHEC DU RETEST",
             "preuve_apres": {"tentatives": limited}},
        ],
    }
