# Carte SQLite de Standard

La carte répond à « qui fait quoi, avec quelle capacité, quelle limite, quel effet et quel travail reste ouvert ? ». Elle est une **description du dépôt**. Une relation dans la carte n'accorde aucun droit ; `documented` indique seulement qu'une source la décrit. Les tests cités ne sont pas des résultats mesurés. K, BT et les instruments ne consultent pas cette base pour juger.

La base versionnée est `interface/context/standard.sqlite`. Elle contient 120 objets et 142 liens initiaux, ancrés sur le commit indiqué par `basis_sha`. Ses domaines couvrent agent, build, produit, client, contrôle, vérification et récupération. L'inventaire des garanties dans `fabric/guarantees.toml` est représenté avec ses limites explicites. Les sources des objets et liens pointent vers les fichiers du dépôt. Les questions ouvertes incluent l'UID partagé avec le superviseur, la rétention indépendante des preuves, l'absence de produit réel qualifié et la restauration des données et clés.

## Lire la carte

Depuis la racine du dépôt, sans serveur, dépendance ou accès à une base produit :

```sh
python -m interface.context.cartography overview
python -m interface.context.cartography gaps
python -m interface.context.cartography search superviseur
python -m interface.context.cartography node capability/candidate-run
python -m interface.context.cartography node authority/kernel --depth 2
python -m interface.context.cartography path agent/mission component/candidate --depth 6
python -m interface.context.cartography validate
python -m interface.context.cartography compare /tmp/ancienne.sqlite
python -m interface.context.cartography gaps --json
```

`node` présente les voisins et les sources ; `path` cherche un chemin **dirigé documenté**, sans prétendre prouver une possibilité d'accès. `gaps` affiche les limites recensées ainsi que les relations attendues et absentes. Une relation absente signifie « non décrite », jamais « protection inexistante ». `search` échappe les jokers SQL et annonce `next_offset` pour continuer avec `--offset`. Les parcours sont bornés à trois niveaux pour les voisins et huit pour les chemins. Le mode `--json` sert aux agents. La lecture ouvre SQLite en lecture seule. `validate` renvoie un code non nul si la carte est invalide.

## Mettre à jour

Le schéma est dans `interface/context/cartography.py`. `nodes` porte les objets typés, `links` leurs relations orientées, `expectations` les relations attendues, `metadata` le commit de base. Les identifiants lisibles sont stables. Chaque ligne possède une source existante dans le dépôt. La carte est un fichier par état Git. `compare ANCIENNE_BASE` liste les objets, liens et attentes ajoutés, retirés ou changés par identifiant stable ; extraire une ancienne base avec `git show REV:interface/context/standard.sqlite > /tmp/ancienne.sqlite`.

Pour tester une nouvelle carte : `python -m interface.context.cartography init --db /tmp/map.sqlite`, puis `python -m interface.context.cartography import-json fichier.json --db /tmp/map.sqlite`. Le JSON comporte des listes `metadata`, `nodes`, `links`, `expectations` avec les mêmes colonnes que le schéma. Les ajouts sont transactionnels ; les clefs étrangères sont appliquées à chaque connexion. Éditer la carte suivie par Git dans une branche et valider le résultat avec `validate` et les tests avant de proposer le commit. L'éditeur ajoute des lignes ; supprimer ou corriger une ligne existante nécessite pour l'instant un outil SQLite. Aucune opération d'édition ne crée une permission dans Standard.

Le commit de base sert à situer les sources. La validation vérifie leur présence dans le checkout, pas leur équivalence sémantique au code qui tourne. Après une modification des composants ou de leurs relations, revoir les entrées concernées et avancer `basis_sha`. Ne pas considérer la simple absence de lacune comme une attestation de sécurité.
