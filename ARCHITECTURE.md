# Standard — Architecture, tissu de sécurité et autonomie AI-native

Référence de conception · Octobre 2026. Cette référence décrit la cible et distingue les mécanismes
présents de leur qualification sur une installation réelle. Une déclaration, un dossier ou une suite verte
ne constitue jamais une attestation générale de sécurité.

## 1. Vision et méthode d'ingénierie

Standard permet de confier à des agents IA la création, l'évolution, l'exploitation et la maintenance de
produits logiciels, sans leur donner seuls l'autorité de décider ce qui est acceptable. Il fonctionne avant
qu'un produit existe : objectifs, outils, ressources, contraintes effectives, vérifications et correction.

La boucle est : intention humaine et exigences applicables → missions et Patrol → actions bornées par le
tissu → observations indépendantes → écarts et obligations → correction, acceptation et maintenance.
COUP relie les choix humains à cette boucle. Les modèles cherchent, construisent et proposent ; leur parole
ne clôt pas seule une obligation et ne crée aucun droit.

Les six objectifs sont l'autonomie élevée, l'autorité limitée, la sécurité effective, la qualité vérifiable,
la maintenance permanente et le remplacement des technologies sans perte silencieuse de garanties.

**Suringénierie contrôlée des garanties, sobriété radicale du code de sécurité développé par nous-mêmes.**
Le budget de protection peut être élevé ; le budget de confiance doit rester petit ; le budget de maintenance
favorise les mécanismes natifs maintenus et les interfaces ouvertes. Une nouvelle protection doit bloquer un
chemin ou résister à un autre mode de compromission. Deux contrôles sous le même administrateur ne deviennent
pas indépendants parce qu'ils portent des noms différents.

## 2. Domaines, primitives et double Mur

L'unité de conception est le domaine de compromission : les éléments qui peuvent tomber ensemble à cause
d'une identité, d'un secret, d'une dépendance ou d'une autorité commune.

| Domaine | Ressources et responsabilité |
|---|---|
| Travail des agents | Contexte, outils, état de mission et code candidat |
| Construction | Dépendances, tests, compilations et artefacts temporaires |
| Exécution produit | Services, identités et données propres au produit |
| Ressources client | Données et capacités de chaque tenant |
| Contrôle | Administration, délégation, révocation et publication |
| Vérification | Instruments, captures, traces et conservation des preuves |
| Récupération | Artefacts connus, sauvegardes, racines et chemins de restauration |

Ce sont des responsabilités, pas sept machines obligatoires. Le rayon d'une compromission dépend des pouvoirs
réels. Un root commun peut compromettre tous les domaines du même hôte.

Cinq primitives structurent les protections : **isolation**, **autorité**, **médiation**, **intégrité** et
**limitation**. Elles sont appliquées par les propriétaires des ressources, pas par cinq moteurs maison.
La survivabilité ajoute observation externe, révocation, conservation des preuves et récupération testée.
Elle s'applique à tout le tissu ; elle n'est pas un troisième Mur.

Le **Mur intérieur** applique réellement les restrictions ordinaires et fournit des refus exploitables :
opération, capacité manquante, emplacement concerné et alternative autorisée. Le **Mur extérieur** conserve
un confinement indépendant lorsque les premiers contrôles échouent. Ses alarmes détaillées restent protégées.
« Muet » signifie divulgation minimale, pas absence d'effets observables.

Identité, capacités, provenance, flux, budgets et observation traversent ces frontières. Ils visent la
non-propagation, la non-amplification et les plafonds cumulés. Les limites mesurables sont appliquées au point
d'effet avec cohérence transactionnelle. Aucun moteur universel d'effets ni proxy universel n'est introduit.

## 3. Organisation du code et responsabilités

| Répertoire | Responsabilité réelle |
|---|---|
| `fabric/runtime/` | Définition OCI, profils, ressources et lecture technique des refus |
| `fabric/network/` | Envoy, entrée, sortie, relais, sessions et assemblage produit |
| `fabric/identity/` | Identité signée et intégration native OpenBao |
| `fabric/data/` | Intégration PostgreSQL et frontières RLS |
| `fabric/control/kernel/` | K : jugement déterministe, loi, identité logique et obligations |
| `fabric/control/bt/` | Admission, second juge, journal, observation et départ des effets |
| `fabric/control/runtime/` | Assemblage privilégié, empreinte d'installation et exécution des releases |
| `fabric/supply_chain/` | Composants épinglés et fermeture des dépendances du proxy |
| `fabric/evidence/` | Captures, alarmes, télémétrie et inventaire des garanties |
| `fabric/recovery/` | Reconstruction d'un artefact vérifié dans un répertoire neuf |
| `engine/agents/` | Missions, recherche, construction, revue, Patrol et maintenance |
| `engine/verification/` | Instruments et sondes épinglés, sans pouvoir de signature propre |
| `engine/catalog/` | Exigences communes, paramètres et compilation des floors |
| `interface/context/` | Lecture partagée, capacités, diagnostics et contexte des missions |
| `interface/surface/` | CLI et interface humaine, transmission des décisions signées |
| `blocks/` | Contrats d'implémentation Python, FastAPI, Next.js et navigateur |
| `tools/` | Installation, qualification, distribution, replay et récupération |
| `tests/` | Contrats, intégration, attaques, pannes et non-régression |
| `examples/` | Fixtures et démonstrations, aucun produit client présupposé |

Aucun dossier vide ne représente une protection livrée. En particulier, les produits restent extérieurs
au socle tant qu'il n'en existe pas. Ce rangement ne constitue aucune séparation de privilèges à lui seul.
`make layers` vérifie les imports Python ordinaires, la pureté de K et l'indépendance logique du second juge ;
il ne démontre pas l'isolation physique ni l'absence d'import dynamique hostile.

## 4. Sécurité infrastructure-first et Building Blocks

L'OS, le runtime OCI, Envoy, le fournisseur OIDC, OpenBao et PostgreSQL appliquent leurs contrôles natifs.
Standard fournit configurations, adaptateurs bornés, contrats, sondes et contexte. Il ne réécrit ni IAM,
cryptographie générale, hyperviseur, gestionnaire de secrets ni système de sauvegarde distribué.

L'application conserve les contraintes dont elle seule connaît le sens : validation métier, accès à l'objet,
encodage contextuel, finalités et calculs spécialisés. Un contrôle applicatif nécessaire ne disparaît pas
parce qu'un proxy existe. XSS, injection SQL, CSRF, SSRF, vol de session, fuite de secrets, accès inter-tenant,
mauvaise configuration et dépendances vulnérables restent des exigences communes.

Un Building Block est un contrat de comportement réutilisable. Les implémentations Python et Next.js peuvent
différer ; les sondes doivent vérifier les mêmes résultats. Le catalogue décrit exigences, paramètres,
conditions d'applicabilité et hypothèses. `held_by` désigne un propriétaire prévu, jamais une mesure.
Les bibliothèques existantes restent conservées pendant la migration : aucune disparition de bloc sans preuve
d'équivalence de toutes ses garanties, y compris les propriétés que la plateforme ne peut comprendre.
Les suffixes Python génériques ne supposent pas FastAPI ; ses intégrations nécessitent la détection du framework.

Les futurs contrats de Publisher OS devront couvrir consentement, finalités, exports d'identifiants, inférences,
validité des audiences, révocation et expiration des collaborations. Ces garanties spécialisées ne peuvent
pas affaiblir le tissu générique et ne sont pas revendiquées par ce dépôt.

## 5. Autorité, COUP et jugement

Le modèle actuel est un humain logique et un agent gouverné, avec plusieurs workers possibles. Il ne
réintroduit ni anciens quorums ni délais constitutionnels. Le client signe ses choix dans les règles du jeu,
composées avec les floors de release. Les agents peuvent préparer ces choix, jamais les signer à sa place.

Les trois gestes humains restent oui (approbation d'une ressource exacte), non (gel) et règles (nouveaux choix
signés). Une route autonome s'ouvre sur les faits exigés par la loi, pas sur l'opinion d'un reviewer. Une
approbation porte sur l'opération, la ressource et les octets concernés ; elle n'est pas un droit réutilisable
pour tout changement ultérieur. La signature ne prouve pas que son détenteur n'a pas été trompé.

K reste pur : pas de réseau, système de fichiers, horloge ou effet physique. Il juge des entrées canoniques,
identités, lois, preuves qualifiées, intentions et transitions. Le second juge reformule indépendamment
l'admission ; il ne réutilise pas le premier jugement. BT possède le départ et les ressources privilégiées.
L'empreinte de release continue à lier ces mécanismes et l'assemblage qui les utilise.

| Garantie historique | Décision de migration |
|---|---|
| G01 Autorité humaine sur l'élargissement ; G03 floors inaffaiblissables | Conserver K et le second juge |
| G02 Restriction immédiate ; G05 sens des signatures ; G06 temps non permissif | Conserver les contrats et leurs tests |
| G04 transition canonique ; G08 dette persistante | Conserver jugement, journal, continuité et échéances |
| G07 preuve qualifiée ; G13 santé distincte d'une preuve | Conserver qualification et expliciter les limites physiques |
| G09 effet lié à l'intention ; G10 incertitude conservée | Conserver garde, réservation et réconciliation |
| G11 historique non régressable | Conserver pins et checkpoints ; indépendance administrative à déployer |
| G12 second juge indépendant | Conserver indépendance logique ; indépendance de processus non livrée |
| G14 aucune récupération toute-puissante ; G15 aucun egress privilégié alternatif | Conserver les restrictions ; qualifier les chemins externes |
| G16 autonomie sans souveraineté | Conserver obligations, missions, escalade et admission |

Aucune garantie n'a été supprimée pour obtenir un dossier plus propre. Leurs hypothèses d'exploitation
restent nécessaires. La même signature peut attester un fait vrai ou faux ; K ne fabrique pas la vérité physique.

## 6. Instruments, obligations et autonomie

BT capture les sources déclarées et exécute les programmes épinglés. Les instruments calculent des résultats
sur des entrées identifiées ; un registre de replay permet de les reproduire dans leur périmètre. Les faits
gardent sujet, source, méthode, fraîcheur et couverture. Donnée absente ou sonde incomplète reste non mesurée.

Un écart peut créer ou alimenter une obligation avec continuité et échéance. L'agent recherche, propose et corrige ;
la fermeture exige la preuve prévue par la loi. Cette boucle couvre sécurité, fonctionnel, qualité, configuration,
production et continuité, selon les instruments réellement disponibles.

BUILD et RUN sont des contextes de présentation, pas des files ni des moteurs d'autorisation concurrents.
Un même chemin prépare le candidat et ses vérifications. Une réparation conserve son obligation ; une demande
conserve son contrat d'acceptation. Les tests contractuels et la configuration protégée restent hors des écritures
ordinaires de l'agent dans un dépôt client.

Un constructeur écrit. Deux reviewers sans outils d'écriture inspectent le même candidat immuable : correction/
sécurité et simplicité. Toute modification invalide ces revues. Leurs constats restent des propositions,
jamais des attestations. Patrol d'ingénierie, Patrol de sécurité et investigation peuvent proposer du travail
sans devenir des racines de confiance. Aucune équipe externe n'acquiert un droit d'intrusion chez des tiers.

Les contrôles déterministes doivent continuer quand les modèles sont indisponibles. Les modèles défensifs
s'activent sur événements ou missions périodiques. Les confinements préautorisés restent bornés ; les actions
à conséquences importantes conservent le contrôle humain requis.

## 7. Pédagogie fondée sur le réel

Avant l'action : exposer les capacités pertinentes, les exigences et les chemins utilisables. Pendant : fournir
le refus exact et une alternative autorisée. Après : conserver les observations et corrections vérifiées.
Le tissu détient la vérité technique ; l'interface la présente dans le contexte de la mission.

La pédagogie n'a pas de moteur d'autorisation et sa panne ne désactive aucun contrôle. Une carte dérivée d'une
configuration est explicitement une prévisualisation ; elle ne démontre pas que cette configuration s'exécute.
La matrice distingue les moyens de vérification disponibles du statut d'un déploiement, non mesuré par défaut.
Le plancher de couverture ne devient jamais une attestation de réussite.

L'inventaire `fabric/guarantees.toml` relie propriété, composant, domaine, hypothèses, contournements, tests et
travail restant. Les missions peuvent lire ses entrées `guarantee/<id>` avec leurs outils habituels.
Ce registre est documentaire ; il ne crée ni policy concurrente ni autorité de qualification.
Les alarmes, clés, signatures internes et détails du confinement indépendant ne sont pas livrés par défaut
aux agents. Les diagnostics libres ne doivent pas devenir un canal d'exfiltration.

## 8. Protections présentes et limites exactes

Le bac OCI définit namespaces, environnement minimal, fichiers déclarés, filtre seccomp et budgets cgroups.
Tous les profils exigent désormais les limites du groupe ; un plafond par processus ne remplace pas un plafond
cumulé. `base` accepte runsc, runc ou crun ; `reinforced` et `critical` exigent runsc sans repli implicite.
Le mode rootless de runsc peut ignorer les erreurs de configuration cgroups : il est donc refusé.
Sous un compte non privilégié, `base` utilise runc/crun ; les profils qui exigent runsc restent indisponibles.
Un service runsc privilégié distinct et ses frontières devront être qualifiés avant d'ouvrir ce parcours.
Cela sélectionne un runtime, sans qualifier les domaines de contrôle ou de récupération du profil.
Les cgroups sont rangés par UID puis exécution. L'installateur laboratoire prépare des sous-arbres distincts
pour agent et runner, garde leurs plafonds agrégés sous propriété root et vérifie le lancement sous ces comptes
avant de démarrer les services. Cette préparation nécessite un hôte cgroup v2 compatible ; elle n'est pas
une preuve de séparation face à son administrateur root.
Une unité de préparation recrée la délégation à chaque démarrage. Le lanceur fixe, installé sous propriété root,
place son propre processus dans la délégation avant de changer d'identité ; il ne peut cibler que les comptes
agent et runner. Le contrôle conserve l'accès en lecture aux compteurs ; une lecture impossible reste inconnue.
L'arrêt du service agent nettoie seulement son groupe `enclosure` avec `cgroup.kill`.
L'arrêt du superviseur nettoie le sous-arbre UID complet, candidats compris ; l'unité agent dépend de lui.

L'entrée utilise Envoy et oauth2-proxy, puis la politique Standard : identité signée pour un produit, JSON strict,
refus des collisions, délai, en-têtes et cookies. Le prototype local suppose une terminaison TLS amont.
Le produit écoute dans son réseau isolé ; le relais Unix ne lui ajoute pas de route réseau générale.

Le proxy de sortie contrôle destinations et résolution, puis injecte les références de secrets hors du bac.
Les réponses sont mises en mémoire avant inspection des corps décodés et des en-têtes : une réflexion exacte
est refusée. Cela ne protège pas contre toutes les transformations d'un secret par un destinataire autorisé.
Les valeurs ne doivent donc jamais être décrites comme absolument impossibles à recevoir ou à divulguer.

Les clés sont autorisées par liste exacte de couples clé/opération, avec refus par défaut. Le proxy reçoit un
jeton enfant OpenBao dont la policy native ne permet que les lectures de secrets et opérations déclarées,
plus sa propre révocation. Le credential de provisionnement reste dans le contrôle. Le jeton expire au plus
tard après une heure ; aucune prolongation automatique n'est implémentée. Son expiration bloque les appels.
La séparation entre administrateur de provisionnement et administrateur du proxy doit encore être déployée.

Le stockage de fichiers borne taille, type déclaré et quota du magasin produit. Un verrou fichier natif
sérialise contrôle et écriture entre processus ; les mêmes octets sont comptés une fois. Ce compteur local ne
fournit ni quota distribué ni identité par utilisateur. Le type déclaré n'est pas un scan antivirus.

PostgreSQL applique RLS sur les tables protégées avec propriétaire distinct et identité signée par transaction.
Une table sans colonne propriétaire/tenant reste hors de cette protection ; la validation métier reste nécessaire.
Un scénario owner-only ne démontre pas toute la règle TENANT.

La capture des logs, les empreintes et les checkpoints apportent des contrôles locaux. Ils ne démontrent pas
une rétention indépendante face au root de cet hôte. K, BT et le second juge partagent encore un processus.
Le service agent du laboratoire passe par `engine.agents.enclosed` : bubblewrap crée une racine de fichiers
limitée, des namespaces PID/réseau/IPC/UTS et retire les capacités. Seuls l'état agent en écriture, le dépôt
local en lecture, la configuration, le contexte public et les répertoires des sockets choisis sont exposés.
Le scratch partagé est distinct de l'état agent. Aucun cgroupfs n'entre dans sa racine : un appel direct
au runtime OCI ne peut pas y obtenir les budgets requis. Les plafonds UID restent finis et sous propriété root.

Le service extérieur `fabric.runtime.supervisor` lance les candidats depuis l'environnement hôte, hors des
namespaces de l'agent. Son API Unix accepte une commande, des chemins sous le scratch ou le cache de dépendances
et des limites au plus égales à son allocation fixe. Elle ne reçoit ni configuration OCI arbitraire, ni secret,
ni nouveau réseau, ni identité d'exécution choisie par l'appelant. Une seule exécution est admise à la fois.
Les chemins sont ouverts composant par composant sans suivre les liens ; les descripteurs restent ouverts
jusqu'au démontage, pour empêcher une substitution de chemin entre contrôle et montage. Les sorties restent
bornées par le bac. La perte du superviseur refuse le travail sans repli vers une exécution locale.

Le laboratoire conserve le même UID pour l'agent et le superviseur afin de partager les fichiers temporaires
sans service privilégié de transfert. Le superviseur dispose de la délégation cgroups ; l'agent n'en voit pas
le montage. Cette séparation dépend donc de l'enclosure et du noyau, sans indépendance d'identité face à leur
compromission. Les budgets UID agrégés sont encore partagés. Une identité distincte ou une micro-VM par charge
reste une qualification ultérieure, et non une protection revendiquée ici. Les sorties du candidat sont
non fiables ; les instruments de vérification restent sous un autre compte et ne consomment pas ses assertions.
Le précheck HTTP complet derrière Envoy n'est pas déplacé vers cette API de commandes : il reste indisponible
dans l'agent enfermé, avec un diagnostic explicite, sans devenir une preuve de conformité.
Les appels de modèles utilisent un relais loopback vers le socket public du proxy, sans clé fournisseur.
La CLI directe `engine.agents run` reste une exécution non enfermée ; elle n'est pas le service installé.
Le parcours Git distant n'est pas ouvert dans cette enclosure. Les autorités sur l'hôte restent partagées. Le déploiement laboratoire
conserve un humain auto-évalué sur le même hôte et ne constitue pas une installation de production qualifiée.

### Pouvoirs effectifs dans le laboratoire

| Identité ou domaine | Pouvoirs exposés | Frontière et limite |
|---|---|---|
| Agent enfermé | Sa clé, ses propositions, scratch, contexte public, admission signée et demandes de tests bornées | Pas de montage cgroups ; K juge la portée et la révocation |
| Superviseur de candidats | Création et arrêt des bacs OCI, limites fixes, scratch et cache explicitement sélectionnés | Hors des namespaces agent ; même UID dans le laboratoire, sans autorité d'admission |
| Candidat séparé | Fichiers explicitement montés et budgets de son bac | Ni socket superviseur, ni état agent, ni réseau direct ; reste dépendant du noyau Linux |
| Contrôle / guard | Journal, clés de services, vérification et promotion des artefacts | Compte distinct de l'agent ; les deux juges partagent encore un processus |
| Runner de vérification | Exécution des candidats pour les instruments | Compte distinct et lanceur fixe ; aucune clé de contrôle |
| Proxy de modèles | Destinations autorisées et jeton OpenBao délégué | L'agent voit le socket public et la CA ; la séparation administrative du proxy reste à déployer |
| Preuves et reconstruction | Conservation et octets connus hors de la racine agent | Protégés de l'agent dans les tests ; aucune indépendance face au root commun n'est revendiquée |

Révoquer une capacité K bloque ses futures admissions. Cela ne retire pas rétroactivement des données déjà lues,
ne restaure pas un espace compromis et n'interrompt pas à lui seul les appels réseau en cours. Le confinement
opérationnel doit aussi arrêter le service et révoquer les accès externes concernés. Le chemin de reconstruction
ne réactive aucune capacité révoquée et ne restitue pas les données ou les clés client.

Le prérequis `unshare -Urn` est vérifié avant le remplacement du laboratoire. Son succès ne suffit pas : la CI
exécute aussi le candidat OCI depuis l'enclosure réelle. Un workspace cloud peut refuser les user namespaces ;
aucun privilège supplémentaire ni assouplissement LSM n'est automatiquement appliqué pour contourner ce refus.
Un déploiement qui ne permet pas cette imbrication nécessite un exécuteur orchestré séparément, non fourni ici.

## 9. Intégrité, distribution et récupération

L'empreinte d'installation couvre le tissu, le contrôle, le catalogue, les blocs et les configurations de sécurité
présentes. Un déplacement ne doit pas retirer un code privilégié de cette empreinte. Le digest sur disque ne
prouve cependant pas ce que le processus a chargé avant son calcul.

Les outils existants exportent provenance SLSA/in-toto, checkpoints et cibles TUF. Ils réutilisent les formats
publics ; une provenance déclarative n'est pas une preuve que le builder était indépendant.
Le client TUF vérifie les cibles à partir d'une racine de confiance préexistante.

`python -m tools.recover ARCHIVE sha256:DIGEST NOUVEAU_REPERTOIRE` prépare un artefact sans changer le déploiement.
Le digest doit venir d'un enregistrement de release digne de confiance, par exemple d'une cible TUF vérifiée.
L'outil vérifie les mêmes octets qu'il extrait, refuse traversées, liens, doublons, fichiers spéciaux et expansion
hors budget, puis publie dans un répertoire neuf. Il ne restaure pas les clés, les données client ou les droits.
Une vraie restauration exige en plus sauvegardes natives protégées, racines disponibles, point de reprise,
vérification fonctionnelle et autorité distincte. Cette indépendance n'est pas simulée par un dossier local.

## 10. Validation et exploitation

Chaque garantie doit nommer sa propriété, son point d'application, les chemins de contournement, ses dépendances
et domaines, et les sondes qui la vérifient. Quatre familles de vérification sont nécessaires : structure,
comportement, adversarial et résilience. Les tests conservent leurs préconditions et leur périmètre.

```sh
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.hashes
make check PYTHON=.venv/bin/python
make coverage PYTHON=.venv/bin/python
python -m tools.fabric inventory
python -m tools.fabric measure --strict
python -m tools.qualify /chemin/standard.toml
```

La dernière mesure du tissu lance des sondes locales contre leurs fixtures ; même entièrement verte, elle ne
qualifie pas une autre installation. `--strict` refuse toute sonde absente, cassée ou non mesurée. Une panne
ne devient pas un zéro sain. Pour les tests du proxy, créer son environnement séparé à partir de
`fabric/supply_chain/egress-requirements.txt` avec `--require-hashes` puis lancer `test_fabric_adversarial.py`.
La fermeture est épinglée séparément : ne pas mélanger ses dépendances avec celles de Standard.

Les scénarios adversariaux comprennent les secrets réfléchis, les autres clés et opérations, les réponses DNS
mixtes, les quotas concurrents entre processus, les archives altérées et la restauration sans modification du live.
Les scénarios nécessitant OCI, Envoy, OpenBao, PostgreSQL ou les sockets Unix doivent tourner sur un hôte compatible.
Leur indisponibilité ici ne vaut jamais réussite. La CI Linux conserve les essais d'isolation et d'intégration.

Le parcours représentatif complet reste : mission humaine → environnement borné → candidat → build isolé →
vérifications indépendantes → publication de l'artefact exact → identité produit → compromission simulée →
confinement et preuves → reconstruction. Le checkout ne permet pas de revendiquer ce parcours qualifié en production.

## 11. Décisions et travail restant

La stabilité 2026–2031 porte sur les contrats, pas les technologies. Remplacer runtime, identité, gateway,
attestation, backend de télémétrie ou sauvegarde exige une nouvelle validation. Une API compatible ne prouve
pas une équivalence de sécurité. Les candidats spécialisés restent évaluables selon menace, privilèges,
maintenance, intégration et comportement en panne ; ils ne sont pas tous des dépendances obligatoires.

Priorités d'exploitation : isoler le processus agent sans casser ses outils, séparer physiquement les autorités
de contrôle/vérification/récupération, vérifier l'installation avant import, imposer les délais sortants, déployer
OpenBao persistant avec renouvellement borné, qualifier les scopes natifs et les frontières client, automatiser
la projection des capacités du déploiement exact, puis exercer la restauration des données et racines.
Aucun profil ne rend ces propriétés vraies par son seul nom.

Les accès légitimes abusés, effets cumulés, propagation, compromission des protections, preuves trompeuses et
perte du chemin de récupération restent les six scénarios prioritaires. Les coûts build/run doivent être mesurés
sur l'hôte cible, sans inventer de chiffres depuis les tests unitaires.

Les anti-objectifs sont un moteur omniscient, un proxy universel, un sandbox ou IAM maison, une pédagogie qui
accorde ses propres permissions, des agents avec clés maîtresses, l'auto-certification du candidat et le retrait
silencieux d'une garantie. Chaque migration doit conserver une décision explicite et une preuve adaptée.

**Surinvestir dans les garanties. Réutiliser les mécanismes éprouvés. Réduire le code privilégié. Vérifier les
effets réels. Faire de chaque protection une condition de l'autonomie.**
