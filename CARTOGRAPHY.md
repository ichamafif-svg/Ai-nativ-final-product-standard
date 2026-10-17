# Carte SQLite de Standard

La carte répond à « qui fait quoi, avec quelle capacité, quelle limite, quel effet et quel travail reste ouvert ? ». Elle est une **description du dépôt**. Une relation dans la carte n'accorde aucun droit ; `documented` indique seulement qu'une source la décrit. Les tests cités ne sont pas des résultats mesurés. K, BT et les instruments ne consultent pas cette base pour juger.

La base versionnée est `interface/context/standard.sqlite`. Elle contient 152 objets et 238 liens, ancrés sur le commit indiqué par `basis_sha`. Ses domaines couvrent agent, build, produit, client, contrôle, vérification et récupération. L'inventaire des garanties dans `fabric/guarantees.toml` est représenté avec ses limites explicites. Les 38 lacunes ou questions incluent aussi les chaînes de capacité encore manquantes pour certains effets. La couverture du dépôt est mesurée séparément : une zone sans référence source n'est pas automatiquement une protection absente.

Pour travailler, l'agent utilise `search`, puis `context ID`. Ce paquet contient chaque objet une seule fois, ses relations directes, les sources d'implémentation, les questions liées et les relations attendues absentes. Les identifiants permettent de poursuivre avec un autre `context`. Le paquet est limité à 28 000 caractères ; un dépassement est un refus explicite, jamais une suppression silencieuse de contraintes. Il est toujours rendu en JSON compact. [Le parcours agent, candidat et réseau](ARCHITECTURE_PATH.md) offre une lecture narrative facultative du même sujet.

Les liens `implements` distinguent un objet de code source d'un composant d'architecture. Un fichier peut implémenter plusieurs responsabilités ; cela ne crée pas plusieurs services. `context` indique `representation=source` et le déploiement de cet objet source est `not_applicable`.

`state` conserve son sens documentaire. Trois appréciations indépendantes sont enregistrées dans `assessments` : `implementation`, `deployment`, `verification`. `present` pour l'implémentation signifie qu'un chemin de code est identifié, avec ses limites ; il ne prouve pas un comportement. Le déploiement exige une observation d'installation, la vérification un résultat retenu et circonscrit. Les deux restent `unknown` dans cette carte. Chaque appréciation enregistrée possède une note et une source ; une appréciation absente est affichée comme inconnue. Les anciennes valeurs `partial` ne sont pas converties automatiquement en résultat positif.

## Lire la carte

Depuis la racine du dépôt, sans serveur, dépendance ou accès à une base produit :

```sh
python -m interface.context.cartography overview
python -m interface.context.cartography gaps
python -m interface.context.cartography search superviseur
python -m interface.context.cartography context capability/candidate-run
python -m interface.context.cartography context capability/dispatch
python -m interface.context.cartography coverage --json
python -m interface.context.cartography node capability/candidate-run
python -m interface.context.cartography node gap/agent-egress-lifecycle
python -m interface.context.cartography node capability/agent-egress
python -m interface.context.cartography node capability/product-egress
python -m interface.context.cartography node authority/kernel --depth 2
python -m interface.context.cartography path agent/mission component/candidate --depth 6
python -m interface.context.cartography validate
python -m interface.context.cartography compare /tmp/ancienne.sqlite
python -m interface.context.cartography gaps --json
```

`node` présente les voisins et les sources ; `path` cherche un chemin **dirigé documenté**, sans prétendre prouver une possibilité d'accès. `gaps` affiche les limites recensées ainsi que les relations attendues et absentes. Une relation absente signifie « non décrite », jamais « protection inexistante ». `search` échappe les jokers SQL et annonce `next_offset` pour continuer avec `--offset`. Les parcours sont bornés à trois niveaux pour les voisins et huit pour les chemins. Le mode `--json` sert aux agents. La lecture ouvre SQLite en lecture seule. `validate` renvoie un code non nul si la carte est invalide.

`coverage` compare les références directes des sources aux fichiers de code/configuration suivis par Git, par sous-système. Il inclut les tests, exemples, dépendances et workflows ; les documents narratifs et fichiers non suivis ne comptent pas. Il rend les fichiers non cités par pages avec `next_offset`, ainsi que le commit du checkout et la base de la carte. Ce compteur ne mesure ni les lignes comprises, ni les chemins d'exécution, ni une garantie de sécurité. Un fichier cité une fois n'est pas intégralement cartographié. Les attentes des capacités vérifient séparément demandeur, autorité, médiation, ressource, effet et contrainte ; celles des effets rendent visibles les capacités ou ressources manquantes.

## Mettre à jour

Le schéma est dans `interface/context/cartography.py`. `nodes` porte les objets typés, `links` leurs relations orientées, `expectations` les relations attendues, `assessments` les appréciations séparées et `metadata` le commit de base. Les identifiants lisibles sont stables. Chaque ligne sourcée pointe vers un fichier existant dans le dépôt. La carte est un fichier par état Git. `compare ANCIENNE_BASE` liste aussi les appréciations ajoutées, retirées ou changées ; les anciennes bases sans cette table restent lisibles. Extraire un ancien état avec `git show REV:interface/context/standard.sqlite > /tmp/ancienne.sqlite`.

Pour tester une nouvelle carte : `python -m interface.context.cartography init --db /tmp/map.sqlite`, puis `python -m interface.context.cartography import-json fichier.json --db /tmp/map.sqlite`. Le JSON comporte des listes `metadata`, `nodes`, `links`, `expectations`, `assessments` avec les mêmes colonnes que le schéma. Les ajouts sont transactionnels ; les clefs étrangères sont appliquées à chaque connexion. Éditer la carte suivie par Git dans une branche et valider le résultat avec `validate` et les tests avant de proposer le commit. L'éditeur ajoute des lignes ; supprimer ou corriger une ligne existante nécessite pour l'instant un outil SQLite. Aucune opération d'édition ne crée une permission dans Standard.

Le commit de base sert à situer les sources. La validation vérifie leur présence dans le checkout, pas leur équivalence sémantique au code qui tourne. Après une modification des composants ou de leurs relations, revoir les entrées concernées et avancer `basis_sha`. Ne pas considérer la simple absence de lacune comme une attestation de sécurité.
