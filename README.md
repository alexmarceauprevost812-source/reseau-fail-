# Linux Garde

Outil Linux en français pour auditer ses appareils, examiner des services réseau et comprendre des failles dans un laboratoire intégré.

## Lancement

Python 3 suffit pour l'audit local et le laboratoire. Les scans réseau nécessitent Nmap installé avec le gestionnaire de paquets de votre distribution. Conserver `audit.py` et `laboratoire.py` dans le même dossier.

```sh
git clone --branch linux-garde-menu https://github.com/alexmarceauprevost812-source/reseau-fail-.git
cd reseau-fail-
python3 audit.py
```

Pour actualiser une copie existante :

```sh
git switch linux-garde-menu
git pull --ff-only
python3 audit.py
```

Commencer sans sudo. La bannière est cyan sur un terminal compatible ; `NO_COLOR=1` désactive la couleur.

## Menu

| Option | Fonction |
| --- | --- |
| 1 | Audit de l'ordinateur Linux |
| 2 | Audit local avec rapport JSON |
| 3 | Découverte et scan réseau, 256 adresses IPv4 maximum |
| 4 | Aide |
| 5 | Mode courant : services, versions et configurations d'un appareil |
| 6 | Tests ciblés supplémentaires SMB MS17-010 et TLS |
| 7 | Mode laboratoire : exercices, preuves, corrections et retests |
| 0 | Quitter |

L'audit local vérifie les ports en écoute, quelques paramètres du noyau, les permissions de `/etc/shadow` sans lire son contenu, la présence d'un pare-feu et la configuration SSH accessible. La présence d'un pare-feu ne valide pas ses règles. Les règles SSH `Match` peuvent différer des valeurs affichées.

## Mode courant et tests ciblés

L'option 5 accepte une adresse IPv4 privée et propose les 1 000 ports TCP fréquents ou les 65 535 ports TCP. Nmap identifie les services avec des sondes légères et exécute les contrôles applicables :

- algorithmes SSH et certificat TLS ;
- en-têtes de sécurité HTTP ;
- signature SMB et présence de SMBv1 ;
- connexion FTP anonyme, sans lister les fichiers (`ftp-anon.maxlist=0`).

L'option 6 ajoute `smb-vuln-ms17-010`, qui recherche les indices de cette faille sans exécuter EternalBlue, et `ssl-enum-ciphers`, qui effectue plusieurs négociations TLS. Ces tests actifs peuvent charger les services et apparaître dans leurs journaux. La limitation du débit du scan de ports ne limite pas toutes les connexions des scripts NSE.

Les résultats distinguent service accessible, accès anonyme confirmé, faiblesse possible, vulnérabilité signalée par Nmap, résultat à examiner et contrôle non vérifié. Un accès anonyme peut être intentionnel ; son observation ne démontre pas automatiquement une faille. Une sortie absente ou interrompue ne signifie jamais « sécurisé ». Le rapport JSON facultatif conserve aussi le XML brut, la commande, les erreurs et les conseils. Refaire le même profil après correction pour examiner l'évolution des résultats.

Les délais sont limités : 30 secondes par script et 20 minutes par appareil. Même le profil de 65 535 ports peut rester incomplet. Les scripts ne couvrent pas toutes les CVE ; UDP, la sécurité radio Wi-Fi, le firmware du routeur, les permissions internes et les mises à jour ne sont pas audités automatiquement. Une adresse privée seule ne prouve pas qu'un appareil est local ou autorisé.

## Laboratoire intégré

L'option 7 exécute deux exercices jetables avec des comptes fictifs en mémoire, sans ouvrir de serveur ni contacter un appareil :

1. Une véritable requête SQLite volontairement vulnérable permet un contournement de connexion. Le même test est rejoué avec une requête paramétrée ; une connexion valide et un mauvais mot de passe sont également contrôlés.
2. Cinq essais prédéfinis sur un compte fictif illustrent la découverte d'un mot de passe sans limitation. La même série est rejouée avec un blocage après trois échecs.

Le résultat présente la preuve avant correction, la correction et le retest. Les conclusions concernent exclusivement ce laboratoire. Il ne s'agit pas d'un test d'exploitation de vos appareils ni d'un module de force brute distante. Le stockage de mots de passe en clair dans la base fictive et le verrouillage permanent de démonstration ne sont pas des modèles d'authentification à déployer.

Les rapports sont créés avec des permissions privées et aucun fichier existant n'est écrasé. Examiner leur contenu avant partage. Aucun réglage réel n'est corrigé automatiquement.

## Vérification du code

```sh
python3 -m unittest -v test_audit.py
```

Les exercices du laboratoire sont réellement exécutés. L'interprétation des résultats réseau est testée avec des fixtures XML ; cela ne remplace pas une validation Nmap sur vos appareils.

## Documentation Nmap

- https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html
- https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html
- https://nmap.org/nsedoc/scripts/ftp-anon.html
- https://nmap.org/nsedoc/scripts/smb-protocols.html
