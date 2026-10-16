# Standard — parcours agent, candidat et sorties réseau

État décrit : branche de la cartographie, code examiné le 16 octobre 2026. Ce fichier sert à orienter une mission IA dans l'architecture actuelle. Il sépare les **comportements codés**, les **essais disponibles** et les **conditions de déploiement encore à qualifier**. La carte SQLite `interface/context/standard.sqlite` reprend les objets et relations de ces parcours ; ni ce document ni la carte n'accordent une capacité ou n'attestent une installation.

## À retenir en une minute

Il n'existe pas de chaîne « candidat → proxy → Internet ». Le **candidat de développement n'a pas de route réseau ni de socket de sortie monté**. L'agent reçoit son résultat par le superviseur ; l'agent peut ensuite utiliser son propre proxy pour appeler un modèle. Un **produit exécuté** possède une autre pile et, si activé, son propre proxy de sortie. Ces trois contextes partagent des mécanismes OCI et réseau, mais leurs capacités sont différentes.

| Contexte | Peut demander | Frontière effective dans le code | Sortie réseau prévue |
|---|---|---|---|
| Agent installé | Exécution de candidat via `candidate.sock` ; admission via son socket ; appel de modèle via `egress.sock` si configuré | `bubblewrap`, montages choisis, réseau privé, cgroup UID | Seulement par le relais du proxy agent configuré |
| Candidat de développement | Commande et fichiers copiés sous scratch/cache, dans les plafonds demandés | Superviseur extérieur à l'agent, bac OCI, réseau vide, montages copiés | Aucune ; sa sortie texte/fichier retourne au superviseur |
| Produit exécuté par `Stack` | Port interne, porte Unix, éventuellement base et proxy produit | Bac OCI et pile Envoy/gate/door ; destinataires du proxy produit | Si `egress=True`, relais Unix vers mitmproxy, sous la politique du produit |

### 1. Agent → superviseur → candidat

| Étape | Autorité, donnée ou effet | Point d'application et source | Vérification existante ; limite |
|---|---|---|---|
| Installation du service agent | Le lanceur crée le bac agent ; le montage en lecture seule expose le code, la configuration, le contexte public et les répertoires de sockets dédiés. L'état agent et le scratch sont en écriture. | [`fabric/runtime/agent.py`](fabric/runtime/agent.py) `layout`, `command` ; [`tools/install_server.sh`](tools/install_server.sh) | [`tests/test_agent_enclosure.py`](tests/test_agent_enclosure.py) vérifie montages et tentatives depuis l'enclosure sur un hôte compatible. La CLI directe de l'agent n'est pas ce service. |
| Demande de candidat | `Sandbox` choisit `RemoteBac` quand `STANDARD_CANDIDATE_SOCKET` est présent. La perte du socket refuse l'exécution. | [`engine/agents/sandbox.py`](engine/agents/sandbox.py), [`fabric/runtime/supervisor.py`](fabric/runtime/supervisor.py) `RemoteBac` | [`tests/test_candidate_supervisor.py`](tests/test_candidate_supervisor.py) vérifie le refus sans superviseur. Hors du service installé, `Sandbox` peut choisir un bac OCI local : ne pas lui attribuer l'isolation agent installée. |
| Contrôle du demandeur | Le superviseur compare l'UID et, dans le service installé, le cgroup du pair Unix ; l'API accepte une commande, des chemins scratch/cache et des limites inférieures au plafond. | [`fabric/runtime/supervisor.py`](fabric/runtime/supervisor.py) `Handler`, `Executor` ; [`tools/install_server.sh`](tools/install_server.sh) | Les essais couvrent le pair refusé et les paramètres interdits. Le superviseur et l'agent partagent encore **le même UID laboratoire** ; la résistance dépend de l'enclosure, du cgroup et du noyau hôte. |
| Préparation des fichiers | Le superviseur épingle les chemins sans suivre les liens, copie les entrées dans un répertoire privé et passe ces copies à OCI. | [`fabric/runtime/supervisor.py`](fabric/runtime/supervisor.py) `pin`, `copy_in`, `Executor.execute` | Les tests couvrent des substitutions de chemin et des budgets. La copie totale est bornée ; un hôte compromis échappe à ce modèle. |
| Exécution | Le bac impose réseau vide, namespaces, seccomp, montages déclarés, cgroups et limites de processus. Le profil `base` essaie `runsc`, puis `runc` ou `crun` ; le superviseur du laboratoire utilise ce profil par défaut. | [`fabric/runtime/oci.py`](fabric/runtime/oci.py), [`fabric/runtime/bac.py`](fabric/runtime/bac.py), [`fabric/runtime/profiles.py`](fabric/runtime/profiles.py) | Les tests natifs/CI exercent l'enclosure et OCI. **gVisor n'est pas garanti pour chaque candidat** en profil `base` ; les profils renforcés le requièrent mais ne sont pas sélectionnés par le superviseur actuel. |
| Résultat et restitution | Le texte du candidat est non fiable. Les montages déclarés inscriptibles sont réconciliés dans le scratch après exécution. | [`fabric/runtime/supervisor.py`](fabric/runtime/supervisor.py) `copy_out`, `RemoteBac.run` | Les essais couvrent renommages, suppressions et refus de budget avant suppression. Une panne pendant la restitution peut laisser un état **partiel** ; le scratch n'est pas une transaction atomique. |

Le socket du superviseur n'entre pas dans le candidat. Le cgroup du demandeur est vérifié par le superviseur ; le candidat n'a pas le montage cgroup de l'agent. Cela borne une attaque dans les hypothèses indiquées, sans créer une séparation de comptes ou d'administration indépendante.

**Lecture des deux Murs.** Les refus `CANDIDATE.*` du superviseur et les diagnostics du proxy relèvent du contrôle ordinaire explicable. Les namespaces, montages et plafonds imposés par le noyau/OCI continuent à borner les processus si leur code ignore ces diagnostics. Leur indépendance face au même administrateur hôte n'est pas démontrée : deux contrôles visibles ne deviennent pas deux autorités séparées par leur seul nombre. Le candidat, sans socket de sortie, ne traverse pas le proxy réseau pour être « filtré une seconde fois ».

### 2. Sortie de l'agent vers les modèles

L'agent enfermé reçoit le répertoire public `egress.sock` et `ca.pem`, pas la configuration privée du proxy ni le jeton OpenBao. [`engine/agents/enclosed.py`](engine/agents/enclosed.py) crée un relais loopback `127.0.0.1:3128` vers ce socket. [`tools/agent_egress.py`](tools/agent_egress.py) lance, **si configuré séparément**, un proxy pour les fournisseurs de modèles et les sources de recherche. [`fabric/network/egress_addon.py`](fabric/network/egress_addon.py) applique destinations, résolution, injection des secrets autorisés et refus de réflexions exactes. Les destinations permises peuvent toujours recevoir les données que l'agent leur envoie ; un secret transformé n'est pas couvert par le contrôle de réflexion.

**Point de déploiement à vérifier :** [`tools/install_server.sh`](tools/install_server.sh) démarre les unités `standard-candidates` et `standard-agent`, mais ne démarre pas lui-même une unité `agent_egress`. Le lancement, la durée de vie et la séparation administrative du proxy agent doivent être reliés à l'installation cible. Une configuration `[llm]` absente signifie qu'aucun relais modèle n'est créé ; un appel exigé doit alors échouer, sans supposer qu'un accès réseau alternatif existe.

### 3. Sortie du produit

[`fabric/network/stack.py`](fabric/network/stack.py) assemble **un produit** dans un bac OCI. Envoy et le gate contrôlent son entrée ; `door.py` relie son socket à son port interne. Avec `egress=True`, `door.py` relie aussi le loopback proxy au socket du mitmproxy produit. [`fabric/network/egress.py`](fabric/network/egress.py) démarre ce proxy et [`fabric/network/egress_addon.py`](fabric/network/egress_addon.py) applique ses destinations, ses capacités de clés et ses limites de fichiers. Le code produit qui ignore le proxy n'obtient pas une route réseau générale dans le bac. Le proxy produit n'est ni le socket du superviseur ni le proxy agent.

Cette pile existe dans le code et dans les essais ; aucun produit client qualifié n'est présupposé dans ce dépôt. L'entrée prototype suppose une terminaison TLS en amont. La séparation effective des administrateurs du proxy, du provisionnement et de l'hôte doit être établie sur une installation réelle.

## Lacunes à traiter, dans l'ordre

1. **Parcours de déploiement du proxy agent.** Préciser qui démarre `tools.agent_egress`, où résident son jeton et sa configuration, qui le redémarre et comment l'agent installé reçoit son socket. Vérifier sur une installation représentative ; ne pas déclarer cette capacité disponible à partir de la seule classe Python.
2. **Autorité commune agent/superviseur.** L'UID et les plafonds agrégés sont partagés. Documenter l'attaque que le contrôle de cgroup arrête, puis qualifier séparément l'effet d'une compromission du noyau, du lanceur ou de l'administrateur hôte. Décider ensuite si un UID séparé ou une micro-VM apporte une indépendance démontrable.
3. **Restitution non atomique.** Un refus avant la mutation tient dans les essais ; une panne après la première suppression ou écriture peut laisser un scratch partiel. Définir la propriété attendue et le traitement de cet état avant de modifier `copy_out`.
4. **Preuves du réseau candidat/produit.** Conserver des sondes distinctes : tentative de réseau direct depuis le candidat, tentative de socket non monté, sortie autorisée et refusée depuis un produit, puis appels modèles de l'agent. Un succès sur un de ces chemins ne prouve pas les autres.
5. **Qualification du produit et des administrations.** Vérifier le déploiement réel des profils, identités, proxy, TLS, secrets et conservation des observations. Les tests CI ne démontrent pas cette indépendance physique.

Une lacune de la carte est une question de connaissance ou de garantie limitée ; elle n'autorise pas à conclure qu'une attaque a réussi. Les corrections techniques doivent suivre une propriété testable et son point d'application réel.
