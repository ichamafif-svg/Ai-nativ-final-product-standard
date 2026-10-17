# Carte SQLite de Standard

La carte répond à « qui fait quoi, avec quelle capacité, quelle limite, quel effet et quel travail reste ouvert ? ». Elle est une **description du dépôt**. Une relation dans la carte n'accorde aucun droit ; `documented` indique seulement qu'une source la décrit. Les tests cités ne sont pas des résultats mesurés. K, BT et les instruments ne consultent pas cette base pour juger.

La base versionnée est `interface/context/standard.sqlite`. Elle contient 550 objets et 1 065 liens, ancrés sur le commit indiqué par `basis_sha`. Ses domaines couvrent agent, build, produit, client, contrôle, vérification et récupération. Les 63 lacunes ou questions et les fichiers sans référence restent visibles. La couverture du dépôt est mesurée séparément : une zone sans référence source n'est pas automatiquement une protection absente.

La boucle est reliée : obligations → file de travail → construction/relecture → propositions → programmes de mesure → observations signées → admission K/BT → guard → dépôt ou registres → exécution et observations suivantes. Le catalogue, les contrats de blocs, la surface COUP, la distribution, les preuves et la reconstruction ont leurs propres objets et sources. Ces flèches combinent des relations typées de travail, de données ou de contrôle ; ce ne sont pas toutes des appels directs.

Pour travailler, l'agent commence par `overview --json` ou `context domain/standard`, puis `context ID` ou `search`. Les entrées de recherche de l'overview pointent vers chaque domaine. Un contexte de domaine donne ses relations et questions directes ; un contexte de composant inclut ses sources et les questions des voisins ; une capacité inclut aussi les sources de ses contrôles. Le champ `scope` dit ce qui est développé. Chaque objet apparaît une seule fois ; les autres responsabilités se lisent par leur identifiant. Le paquet est limité à 28 000 caractères ; un dépassement est un refus explicite, jamais une suppression silencieuse de contraintes. Il est toujours rendu en JSON compact. [Le parcours agent, candidat et réseau](ARCHITECTURE_PATH.md) offre une lecture narrative facultative.

La profondeur repose aussi sur 14 parcours ordonnés et 78 fiches de conditions attachées à des liens existants. `flow ID` expose les étapes, leur source, leurs conditions ou leur absence explicite. Les parcours distinguent admission, proposition, mesure, merge, déploiement, réconciliation, finalité, entrée produit, candidats, sorties agent/produit, injection de secret, lecture SQL et préparation de récupération. Les branches, échecs et variantes sont décrits dans les conditions et limites ; ces parcours ne sont ni des traces exécutées ni une liste exhaustive des chemins possibles.

Chaque fiche précise `timing`, `checks`, `on_failure`, `scope` et `limitation`, avec une source. Par exemple, le programme de mesure est épinglé à la construction de Host ; le guard rejugera chaque départ sous verrou ; PostgreSQL vérifie le token à `act_as`, puis les politiques consultent le sujet lié à la transaction. Ces durées ne sont pas interchangeables. `gaps` et `context.missing_conditions` signalent les relations de contrôle de capacités sans fiche ; une fiche renseignée peut elle-même décrire une limite.

`shared ID` retrouve les dépendances directes et les autres objets qui les partagent : processus, compte, administrateur, clé ou jeton, budget, noyau, code ou stockage. Il conserve la nature du lien : PostgreSQL dépend de la clé publique d’identité, sans posséder la clé privée. Les conditions d’assemblage restent dans les liens et les objets ; un sous-processus peut hériter du compte de Stack sans être dans son processus. Cette recherche n’est pas transitive : poursuivre avec `context` ou `shared` sur l’identifiant de dépendance, par exemple processus → compte → administrateur. L’absence de dépendance documentée ne démontre jamais l’indépendance.

Dans l’assemblage Installation, K/checker, guard, scanner et oracle partagent le processus opérateur. Dans le laboratoire, agent et superviseur partagent UID et budget parent ; les comptes séparés dépendent du même root. K et checker partagent aussi canon, floor0 et runtime cryptographique. La carte conserve ces dépendances malgré la différence des responsabilités. Les comptes effectifs de Stack, du runner de releases et du service de clés restent à préciser pour un déploiement donné.

209 des 267 fichiers de code/configuration suivis ont une référence directe ; 58 restent sans référence, principalement tests, exemples et modules d’initialisation. Cette passe approfondit les implémentations ; elle n’ajoute aucun registre de scénarios ou de résultats de preuve.

La lecture `topology ID` sélectionne les relations de placement, montages, canaux, pouvoirs et couverture. Elle commence par `resource/assembly-lab`, `resource/assembly-stack` ou `resource/assembly-measurement`. Les objets de ces assemblages désignent des instances paramétrées dans le code, pas des machines observées. Un lien `contains` ne crée pas une frontière de sécurité. `outside_of` signifie ici hors d’une enveloppe nommée, sans promettre une autre machine, identité ou autorité. Le substrat physique/VM/conteneur du laboratoire reste non renseigné ; aucune micro-VM n’est inventée dans la carte.

Le laboratoire relie hôte → enveloppe agent → processus agent, ainsi que les processus opérateur/superviseur et les bacs candidats créés sur l’hôte. Le candidat du superviseur est hors de l’enveloppe agent. Les sockets admission/candidat et le relais optionnel, les montages RO/RW, les snapshots et copies de retour sont des objets distincts. Un socket monté dans un répertoire RO peut rester connectable. Les droits `can_read`, `can_write`, `holds`, les comptes, budgets et noyau partagés complètent ces relations. Le chemin Host `network=True` est séparé de `run_confined` : la carte ne lui attribue pas les mêmes murs OCI.

Les rôles sont explicites par `has_role` : protection, instrument ou sonde. La protection `protects_access` un objet d’accès précis ; celui-ci `expects_property` une propriété ; l’instrument `measures_property` et peut `uses_probe` des sondes ; la sonde `exercises_access`, `checks_property` et `uses_environment` un environnement. `targets_environment` distingue le client de sa cible. Une inspection du dictionnaire OCI est un instrument statique, pas une tentative réseau. Les références de méthodes décrivent du code de mesure existant ; aucune exécution ni résultat de preuve n’est enregistré.

Les sondes ont leurs propres accès et fixtures, distincts des accès du laboratoire et de Stack paramétrée. `walls.measure` crée son propre Bac ; `platform_walls` crée une pile temporaire avec des valeurs adaptées ; les tests de contrat du superviseur injectent un faux Bac ; la fixture native lance réellement bubblewrap et le superviseur OCI. Réutiliser une définition ne démontre pas égalité de runtime, profil, UID, montages ou artefact avec le service actif. Les limites correspondantes restent ouvertes, notamment la sortie Internet du candidat exact du superviseur et la couverture tenant des sondes owner_id.

`topology` conserve les conditions des liens sélectionnés, limite les parcours à trois niveaux et les paquets à 28 000 caractères ; un grand voisinage est refusé sans troncature. Commencer à profondeur 1, suivre les identifiants, puis lire `context ID` pour les appréciations et questions. Cette vue ne calcule ni fermeture complète des privilèges ni preuve d’absence de contournement.

Les frontières importantes sont explicites : préchecks agent et mesures admises sont séparés ; les programmes lisent les captures privées du contrôle, tandis que l'interface utilise une projection publique ; le runner exporte un arbre depuis Git sans hériter automatiquement de la pile `Stack` ; TUF et la reconstruction d'archives suivent encore un autre chemin. Les rapports de tests potentiellement falsifiables et les contrôles non mesurés restent des limites de garantie.

Les liens `implements` distinguent un objet de code source d'un composant d'architecture. Un fichier peut implémenter plusieurs responsabilités ; cela ne crée pas plusieurs services. `context` indique `representation=source` et le déploiement de cet objet source est `not_applicable`.

`state` conserve son sens documentaire. Trois appréciations indépendantes sont enregistrées dans `assessments` : `implementation`, `deployment`, `verification`. `present` pour l'implémentation signifie qu'un chemin de code est identifié, avec ses limites ; il ne prouve pas un comportement. Le déploiement exige une observation d'installation, la vérification un résultat retenu et circonscrit. Les deux restent `unknown` dans cette carte. Chaque appréciation enregistrée possède une note et une source ; une appréciation absente est affichée comme inconnue. Les anciennes valeurs `partial` ne sont pas converties automatiquement en résultat positif.

## Lire la carte

Depuis la racine du dépôt, sans serveur, dépendance ou accès à une base produit :

```sh
python -m interface.context.cartography overview
python -m interface.context.cartography context domain/standard
python -m interface.context.cartography topology resource/assembly-lab
python -m interface.context.cartography topology resource/lab-agent-env
python -m interface.context.cartography topology resource/lab-supervisor-process
python -m interface.context.cartography topology resource/access-lab-candidate-direct-net
python -m interface.context.cartography topology instrument/topology-bac-network
python -m interface.context.cartography topology instrument/topology-supervisor-contract
python -m interface.context.cartography flow flow/deploy
python -m interface.context.cartography flow flow/merge
python -m interface.context.cartography shared component/effect-guard
python -m interface.context.cartography shared resource/uid-guard
python -m interface.context.cartography context resource/process-operator
python -m interface.context.cartography context component/mission-assembly
python -m interface.context.cartography context component/instrument-host
python -m interface.context.cartography context capability/merge
python -m interface.context.cartography context capability/deploy
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

`node` présente les voisins et les sources ; `path` cherche un chemin **dirigé documenté**, sans prétendre prouver une possibilité d'accès. `gaps` affiche les limites recensées ainsi que les relations attendues et absentes. Une relation absente signifie « non décrite », jamais « protection inexistante ». `search` échappe les jokers SQL et annonce `next_offset` pour continuer avec `--offset`. Les parcours sont bornés à trois niveaux pour les voisins et huit pour les chemins. Le mode `--json` sert aux agents ; `context`, `flow`, `shared` et `topology` rendent toujours du JSON compact. `shared` se pagine avec `--limit` et `--offset` ; `context`, `flow`, `topology` et chaque page `shared` refusent tout paquet dépassant 28 000 caractères. La lecture ouvre SQLite en lecture seule. `validate` renvoie un code non nul si la carte est invalide.

`coverage` compare les références directes des sources aux fichiers de code/configuration suivis par Git, par sous-système. Il inclut les tests, exemples, dépendances et workflows ; les documents narratifs et fichiers non suivis ne comptent pas. Il rend les fichiers non cités par pages avec `next_offset`, ainsi que le commit du checkout et la base de la carte. Ce compteur ne mesure ni les lignes comprises, ni les chemins d'exécution, ni une garantie de sécurité. Un fichier cité une fois n'est pas intégralement cartographié. Les attentes des capacités vérifient séparément demandeur, autorité, médiation, ressource, effet et contrainte ; celles des effets rendent visibles les capacités ou ressources manquantes.

## Mettre à jour

Le schéma est dans `interface/context/cartography.py`. `nodes` porte les objets typés, `links` leurs relations orientées, `expectations` les relations attendues, `assessments` les appréciations séparées et `metadata` le commit de base. Le schéma 3 ajoute `link_conditions` (une fiche par lien), `flows` (description d’un parcours) et `flow_steps` (positions référençant les liens du graphe par clef étrangère composite). Un parcours ne duplique pas les objets ou relations. `validate` contrôle ses positions contiguës et la continuité des extrémités, en plus des sources et de l’intégrité SQLite. Le schéma ne force pas la présence d’une condition : son absence reste une lacune explicite. Les identifiants lisibles sont stables. Chaque ligne sourcée pointe vers un fichier existant dans le dépôt. La carte est un fichier par état Git. `compare ANCIENNE_BASE` liste aussi les appréciations ajoutées, retirées ou changées ; les anciennes bases sans les tables récentes restent lisibles et comparables. `init` crée le schéma courant ; les commandes de lecture ne migrent jamais une base ancienne. Extraire un ancien état avec `git show REV:interface/context/standard.sqlite > /tmp/ancienne.sqlite`.

Pour tester une nouvelle carte : `python -m interface.context.cartography init --db /tmp/map.sqlite`, puis `python -m interface.context.cartography import-json fichier.json --db /tmp/map.sqlite`. Le JSON comporte des listes `metadata`, `nodes`, `links`, `expectations`, `assessments`, `link_conditions`, `flows`, `flow_steps` avec les mêmes colonnes que le schéma. Les ajouts sont transactionnels ; les clefs étrangères sont appliquées à chaque connexion. Éditer la carte suivie par Git dans une branche et valider le résultat avec `validate` et les tests avant de proposer le commit. L'éditeur ajoute des lignes ; supprimer ou corriger une ligne existante nécessite pour l'instant un outil SQLite. Aucune opération d'édition ne crée une permission dans Standard.

Le commit de base sert à situer les sources. La validation vérifie leur présence dans le checkout, pas leur équivalence sémantique au code qui tourne. Après une modification des composants ou de leurs relations, revoir les entrées concernées et avancer `basis_sha`. Ne pas considérer la simple absence de lacune comme une attestation de sécurité.
