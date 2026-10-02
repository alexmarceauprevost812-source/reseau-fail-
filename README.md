# Linux Garde

Premier prototype d'audit local Linux, en français, avec Python 3 et sans bibliothèque externe. Il analyse la machine sur laquelle il est lancé : ports en écoute, indices de pare-feu, quelques paramètres du noyau, permissions de `/etc/shadow` et configuration SSH effective lorsqu'elle est accessible.

## Utilisation

```sh
python3 audit.py
python3 audit.py --audit
python3 audit.py --json rapport.json
```

Commencer sans sudo. Certains contrôles resteront inconnus faute de droits ou d'outils système. Le rapport JSON est créé avec des permissions privées et ne remplace pas un fichier existant.

## Limites

Le menu propose un scan réseau avec Nmap : découverte des appareils et 1 000 ports TCP les plus fréquents, sur un réseau IPv4 de 256 adresses maximum. Nmap doit être installé séparément. Les appareils invisibles à la découverte, les ports UDP et les autres ports TCP peuvent être manqués. Ce scan ne constitue pas un audit complet de vulnérabilités. Le programme ne teste aucune exploitation et ne modifie aucune configuration. Il propose des conseils à examiner avant application. Il ne détecte pas les CVE, ne vérifie pas les mises à jour et ne garantit pas une sécurité complète. Une configuration SSH conditionnelle (`Match`) peut différer des valeurs globales affichées. La présence d'un pare-feu ne valide pas ses règles.

Les rapports contiennent des informations sur la machine et les services : examiner leur contenu avant de les partager.

## Menu

Lancer `python3 audit.py`, puis choisir : 1 pour un audit local, 2 pour un rapport JSON, 3 pour un scan réseau autorisé, 4 pour l’aide, ou 0 pour quitter. Le scan réseau demande une plage CIDR et une confirmation d’autorisation.

## Analyse détaillée : option 5

Saisir une adresse IPv4 privée appartenant à un appareil autorisé. Choisir les 1 000 ports TCP fréquents ou les 65 535 ports TCP. Le programme identifie les services avec des sondes de version légères et lance une liste explicite de contrôles Nmap : `ssh2-enum-algos`, `ssl-cert`, `http-security-headers`, `smb2-security-mode`. Ces sondes établissent des connexions et peuvent apparaître dans les journaux des appareils. Le débit est limité et les délais peuvent laisser des ports non vérifiés.

Un rapport JSON facultatif conserve la commande, les résultats, les erreurs et des conseils généraux. Il ne constitue pas une détection exhaustive de CVE, une preuve d'exploitation ou un audit radio Wi-Fi. Nmap doit être installé. Aucune base de vulnérabilités distante n'est interrogée. Les adresses saisies doivent correspondre à tes appareils locaux ; une adresse privée seule ne prouve pas leur propriété ni leur localisation.

Documentation des contrôles : https://nmap.org/nsedoc/scripts/

Une bannière avec un bouclier apparaît au lancement du menu. Elle utilise le cyan dans les terminaux compatibles ; définir `NO_COLOR=1` désactive la couleur.
