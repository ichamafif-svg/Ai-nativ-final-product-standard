# Standard — Architecture

Document unique de référence. Il réunit tout ce qui a été trouvé et décidé dans les versions V0 → V7, M2, le laboratoire TCB (campagnes I à V) et le prototype hybride, réécrit au propre. Il remplace tous les documents antérieurs.

**Statut :** architecture cible et décisions arrêtées. **Depuis D51, la cible est une personne et un agent** : l'humain garde le dernier mot là où il compte (§4.8) ; depuis D61, les options d'équipe (seuil, délais, veto, quorum de témoins, livraison T09) sont retirées. Les sections antérieures qui parlent de quorum k ≥ 2, de sentinelle, de revue, de `configure` ou de conformité organisationnelle décrivent l'histoire ; §4.2, §4.8–4.9, §11, §12 et les décisions D51–D53 et D62 décrivent l’état courant. Une exigence de ce document n'est **pas** une garantie démontrée. §18 conserve l'historique des décisions, y compris les anciens noms de modules ; §20 décrit le code actuel et §21.4 distingue réalisation et qualification. En cas d'écart entre une ancienne décision et l'inventaire courant, l'inventaire courant prévaut.

---

## Sommaire

0. Comment lire ce document
1. Mission et promesse
2. Principes directeurs
3. Objets et vocabulaire
4. La loi
5. Architecture en couches
6. Le noyau (K)
7. Les cinq contrats transversaux
8. La ligne d'effet
9. Obligations et cycle de maintenance
10. La frontière de confiance (T)
11. L'autonomie (U)
12. Floors de la release
13. Protocole et parcours produit
14. Garanties G01–G16
15. Limites établies
16. Modèle de menace
17. Registre des constats (non-régression)
18. Décisions
19. Hébergement et produit
20. Organisation du code
21. Réception
22. Discipline de changement

---

## 0. Comment lire ce document

### 0.1 Statuts à ne jamais mélanger

| Statut | Sens | État actuel |
|---|---|---|
| `BOUNDARY_FROZEN` | Le découpage K/T/U d'une garantie est arrêté, avec contrat, hypothèses et falsificateur | **16/16**, conditionnel |
| `IMPLEMENTATION_VERIFIED` | Le mécanisme est implémenté et éprouvé contre ses falsificateurs | À démontrer, mécanisme par mécanisme |
| `PHYSICAL_TRUST_VERIFIED` | Le contrat T tient sur une installation réelle | Non atteint |
| `PRODUCTION_READY` | Toutes les portes de §21 passées sur le déploiement | **Non** |

Un test vert, une CI verte ou une signature ne promeuvent jamais un statut.

### 0.2 Qualité d'un résultat

- **Observé** : sous un commit, un environnement, un oracle et des limites nommés. Rien de plus.
- **Limite établie** : deux entrées indistinguables pour K mènent à deux vérités physiques différentes, ou une trace prouve qu'une dépendance est indispensable (§15).
- **Ouvert** : tout le reste. Une question ouverte produit une route inactive ou un écart visible, jamais une hypothèse silencieuse qui permet un départ.

---

## 1. Mission et promesse

Standard est une plateforme **AI-native** qui crée puis, surtout, **maintient en continu** des dépôts et systèmes logiciels par des agents autonomes, **sans accorder d'autorité souveraine** à un agent, à un humain seul ou à un composant seul.

- **BUILD** crée ou transforme : conception, code, vérifications, intégration, déploiement gouverné. Un dépôt peut partir presque de zéro.
- **RUN** observe le dépôt et la production, détecte les écarts, corrige, vérifie et maintient sécurité, fiabilité et exigences techniques du code. Les référentiels motivent certaines règles ; Standard ne certifie pas une organisation.
- BUILD et RUN sont deux contextes d'un **même système**, sous la même loi. Ni BUILD, ni l'initialisation, ni la récupération n'ont de mode « god ».

**Cycle central :** écart → obligation durable → travail autonome → preuve qualifiée → clôture ou escalade.

### 1.1 La promesse a deux faces

Une TCB qui refuse tout satisfait trivialement la sûreté et échoue au produit. Un agent qui peut tout faire paraît autonome et échoue à la constitution. Chaque garantie se teste donc dans les deux sens :

- **Sûreté** : aucune transition ou effet interdit, aucune preuve fictive, aucune dette effacée.
- **Progrès conditionnel** : si une capacité valide, une preuve accessible, un fournisseur disponible et une route permise existent, le système progresse **sans approbation humaine inutile**. Sinon, il produit une issue identifiable : attente, dette stable ou escalade.

Le progrès n'est garanti que sous des hypothèses écrites de disponibilité et d'équité (§15, L-05).

---

## 2. Principes directeurs

Chaque principe vient d'un constat ; la référence entre crochets renvoie au registre §17.

1. **Simplicité d'abord.** Un mécanisme n'existe que s'il porte une garantie nommée. Les limites résiduelles sont acceptées et documentées plutôt que compensées par de la complexité. Mais **aucune baisse de garantie au nom de la simplicité**.
2. **Un seul souverain déterministe.** Un jugement, une sémantique. Aucun second moteur, aucun `allowed` fourni de l'extérieur, aucun fallback `allowed=true`.
3. **La TCB est l'enjeu du produit.** Ce qui est dans la TCB ne souffre d'aucune faiblesse et ne demande aucune IA pour s'appliquer.
4. **Silos.** L'AI-first gouverne la forme de la loi (lisible par une IA, sans ambiguïté) et les opérations. Il ne s'applique **pas** au noyau, où l'IA est absente.
5. **La TCB ne se fait pas confiance.** Séparation interne de premier rang : un défaut d'un composant ne suffit pas à admettre un effet interdit. L'isolation est imposée par le noyau Linux (processus, comptes, permissions, seccomp), pas par la discipline du code. [V6-§3.5, V6-§3.6]
6. **La TCB seule amène le dépôt vers l'état voulu.** Les floors déclarent ce qui est exigé ; tout écart devient une obligation ; une obligation devient du travail. Les couches externes accélèrent et enrichissent, elles ne sont pas nécessaires à la correction.
7. **La TCB ne grossit pas avec le métier.** Les règles métier croissent par déclarations ; les mécanismes de confiance restent constants. Aucun déplacement ni compactage de code ne compte comme réduction.
8. **Sécurité adversariale native.** Elle naît de FLOOR-0. Un événement adversarial déclenche lui-même du travail ou un traitement spécial.
9. **Aucun acteur de confiance seul**, humains compris.
10. **Le noyau décide, il n'observe pas.** La vérité du monde réel (problème des oracles) est assumée hors du noyau [L-01].
11. **Hors du noyau ≠ hors de la TCB.** Tout composant dont la défaillance peut permettre une action interdite, effacer l'historique ou faire passer une clôture qui ouvre des droits est dans la TCB effective, quel que soit son dossier ou son nom. Une petite TCB locale ne prouve pas une petite TCB effective.
12. **Identité ≠ définition.** Quand la loi évolue, autorisations, preuves et obligations restent liées à la définition sous laquelle elles sont nées. Jamais de réinterprétation implicite. [V6-§2]
13. **Fermer par cause racine, pas par cas.** Un constat se corrige par une structure qui ferme sa classe entière. [V6-causes]

---

## 3. Objets et vocabulaire

| Objet | Définition |
|---|---|
| **Principal** | Identité logique (clé) d'un genre fixé : `human`, `agent`, `service`, `oracle`, `guard`, `witness`, `sentinel` |
| **Ressource** | Objet gouverné, identifié de façon stable, typé, à états finis |
| **Capacité** | Droit borné (sujet, ressource, opération, conditions, budget, durée) issu d'une chaîne de délégation atténuante |
| **Exigence** | Propriété attendue d'un sujet (ex. `vulns = none` sur `repo:deps:vulns`), avec fraîcheur et échéance |
| **Preuve** | Affirmation bornée, attribuée, sur un sujet exact, sous une méthode et une couverture déclarées |
| **Obligation** | Dette stable née d'un écart entre exigence et preuve ; n'accorde jamais de droit |
| **Transition** | Changement d'état canonique causé par exactement une entrée signée |
| **Intention d'effet** | Description exacte d'une action physique : destination, octets, préconditions, fenêtre, reprise |
| **Préfixe** | Historique admis, signé, ancré ; toute décision se prend sur un préfixe nommé |
| **WorkItem** | Tentative de travail. N'est **jamais** une obligation |

Le noyau ne connaît **aucun** objet métier : ni PR, Git, CI, scanner, SBOM, modèle IA, WorkItem ou politique ISO. Les contrats déclaratifs les raccordent aux objets ci-dessus.

---

## 4. La loi

### 4.1 Trois niveaux

| Niveau | Contenu | Auteur | Changement |
|---|---|---|---|
| **FLOOR-0** | Protège la confiance elle-même : autorité, causalité, polarité, temps, preuve, effets, historique, redevabilité | Équipe Standard | Nouvelle release + nouvelle genèse. Jamais par le système |
| **Floors** | Ce que Standard impose à tous : autonomie, sécurité, conformité. C'est le **niveau intermédiaire** qui porte l'autonomie | Équipe Standard, dans la release | Nouvelle release adoptée explicitement. Ni retirables ni affaiblissables par le client |
| **Loi client** | Identités, liaisons des rôles, opérations, exigences supplémentaires, resserrements | Humains du client | Dans le journal : une entrée `law` signée par l'humain, en vigueur aussitôt. Sans nouvelle genèse |

- Il n'y a pas de « lois d'exploitation Standard » séparées : tout ce que Standard impose est dans les floors.
- Seule FLOOR-0 (avec le code et les floors de la release) est figée à la genèse. La loi client évolue dans le journal.
- Floors + loi client activée = **une seule loi effective**, épinglée par digest et par préfixe. Toute projection refuse un digest discordant.
- La TCB elle-même est **hors** de la maintenance autonome.

### 4.2 FLOOR-0

Texte normatif. Le digest de FLOOR-0 couvre ce texte, la table de polarité, les droits de restriction, les constantes et l'automate de la ligne d'effet.

| Règle | Contenu |
|---|---|
| **F0-1** | Une personne et un agent. L'agent ne détient aucune autorité propre. Tout élargissement est énoncé et signé par l'unique humain de la racine ; le temps est énoncé par un témoin de la racine. |
| **F0-2** | Pour chaque propriété critique : ses contrôles, ses dépendances communes et les fautes couvertes sont nommés. Un désaccord de sûreté bloque l'effet ; une incohérence d'intégrité bloque la frontière touchée. Un arrêt local n'est pas une mutation non signée du journal. |
| **F0-3** | Code et floors sont liés à la genèse. La loi client ne change que par élargissement, sans jamais affaiblir les floors de la release ; les chaînes de capacités ne font que se restreindre. Une loi ne contraint que les genres qui agissent, attestent ou atténuent : **jamais** une restriction, un témoin ou le protocole d'élargissement. |
| **F0-4** | Toute transition d'état canonique est causée par exactement une entrée signée. L'admission ne dépend que du préfixe admis, de la loi et du code épinglés. |
| **F0-5** | Chaque genre d'entrée a une seule polarité. La genèse établit la racine initiale, épinglée de l'extérieur. Un élargissement prend effet avec sa propre entrée. Les autres polarités ne font que restreindre, atténuer, agir sous capacité, attester ou témoigner. |
| **F0-6** | Le temps ne fait qu'expirer ou faire tomber une autorité ; il n'en accorde jamais. Seul un témoin fait avancer l'ancre attestée. Les horodatages ordinaires sont monotones et bornés au-dessus de l'ancre. Une restriction peut partager le dernier instant : aucun horodatage ne peut l'affamer. |
| **F0-7** | Lever une restriction est un élargissement : seul l'humain lève un gel. |
| **F0-8** | Un fait ne permet une action que s'il est fraîchement attesté par une chaîne ne partageant **aucun détenteur** avec l'acteur. Tout fait permissif porte son étiquette de provenance : observations, clôtures, instances ouvertes et portes. L'absence d'un fait ne permet jamais rien. |
| **F0-9** | Tout effet est typé ; sa ressource dérive de ses arguments ; sa réservation est durable et à usage unique. Re-jugement et départ fournisseur sont ordonnés contre l'admission. Seule la requête canonique jugée passe à l'adaptateur de confiance, avec une clé de réservation liée à la genèse. La ligne d'effet suit une table unique ; une réservation part dans `DISPATCH_MS` ou jamais, et seulement ensuite peut être réconciliée. |
| **F0-10** | L'historique est append-only et lié à la genèse. Une épingle monotone indépendante est retenue pour chaque écriture **avant** acquittement. Un historique en dessous ou divergent est bloqué ; la réparation restaure sa queue exacte. |
| **F0-11** | Hors admission, chaque cible déclarée sans preuve indépendante fraîche a une obligation et une échéance stables ; un écart en retard enregistre une escalade vers l'humain. La redevabilité n'autorise jamais rien. Enregistrer une escalade ne prouve ni que l'humain l'a vue, ni la réparation. |
| **F0-12** | Chaque opération déclare ses routes : les routes autonomes ne lisent que des faits mesurés, la route humaine exige la décision d'un humain sur la ressource exacte (`decision = approve`, auteur de genre `human`). Un effet ne passe que tant qu'une route en vigueur tient, de l'intention au départ. Une loi peut couper des routes autonomes, jamais la route humaine. |

**Constantes de FLOOR-0** (valeurs par défaut de la release ; une loi client peut seulement les durcir) :

| Constante | Valeur | Rôle |
|---|---|---|
| `MIN_HUMANS` | 1 | Un humain, conformément à la forme de racine de cette release |
| `HUMANS` | 1 | Exactement un humain dans la racine (jusqu'à huit clés : ses appareils) ; au moins un témoin (l'horloge de l'opérateur, `clock`) |
| `MAX_AHEAD_MS` | 5 min | Avance maximale d'un horodatage sur l'ancre |
| `DISPATCH_MS` | 5 min | Fenêtre de départ d'une réservation |
| `DECISION` | `observed(decision, approve, real, human)` | Le seul atome qu'une route humaine doit porter (F0-12) |
| TTL `pending`, `unredeemed`, `reconcile`, `proof`, `observation` | 1 jour | Durées de vie avant expiration |

**Polarité de chaque genre d'entrée :**

| Polarité | Genres |
|---|---|
| `widen` | `genesis`, `rotate`, `grant`, `unfreeze`, `law` |
| `attenuate` | `delegate` |
| `restrict` | `revoke`, `freeze`, `invalidate` |
| `witness` | `checkpoint` |
| `act` | `intent`, `token`, `reservation`, `execution`, `resource`, `transition` |
| `attest` | `reconciliation`, `observation`, `measurement`, et tout genre de preuve déclaré par la loi |

**Qui peut restreindre seul :** `revoke` et `freeze` : humain (et tout détenteur sur la chaîne révoquée pour `revoke`) ; `invalidate` : humain ou oracle source. Il n'y a plus de sentinelle ni de `flag`/`heartbeat` (D51) : un refus humain est un gel, une révocation ou l'absence de `decision`.

### 4.3 Les six mécanismes

Toute loi de la TCB s'exprime avec six primitives. Les floors et la loi client utilisent **les mêmes** primitives : une loi client se lit comme une loi de la TCB. Chaque refus du noyau porte un code de la forme `MÉCANISME.RAISON`.

| Mécanisme | Ce qu'il porte | Exemples de refus |
|---|---|---|
| **CAP** — capacités | Autorité : rôles, chaînes de délégation atténuantes, budgets, restrictions, gel, garde | `CAP.CHAIN`, `CAP.WIDENS`, `CAP.ATTENUATE`, `CAP.SCOPE`, `CAP.RESTRICT`, `CAP.HOLDER`, `CAP.GUARD`, `CAP.WITHDRAWN` |
| **OBL** — obligations | Dettes, portes, ligne d'effet, réservations, budgets d'usage, reprises | `OBL.NOT_OPEN`, `OBL.ALREADY_OPEN`, `OBL.LINE`, `OBL.RESERVATION`, `OBL.LAPSED`, `OBL.GATE`, `OBL.CONTRACT`, `OBL.BUDGET`, `OBL.RETRY` |
| **NIV** — niveaux de preuve | Ordre total des niveaux de qualification (`unknown` < `real`) ; `min_level` exigé par une cible ou une condition | `NIV.TOO_LOW`, `NIV.UNKNOWN`, `NIV.CERTIFY` |
| **PROV** — provenance | Indépendance des chaînes de détenteurs, source habilitée, instrument, sujet, couverture, fraîcheur | `PROV.NOT_INDEPENDENT`, `PROV.INSTRUMENT`, `PROV.SUBJECT`, `PROV.COVERAGE`, `PROV.STALE`, `PROV.UNKNOWN` |
| **TYPE** — types | Formes fermées : genres, champs, arguments, ressources, opérations, racine | `TYPE.SHAPE`, `TYPE.FIELDS`, `TYPE.ARGS`, `TYPE.KIND`, `TYPE.OP`, `TYPE.RESOURCE`, `TYPE.ROOT`, `TYPE.DUPLICATE` |
| **HIST** — historique | Genèse, chaîne, épingles, ancre de temps, rollback | `HIST.GENESIS`, `HIST.CHAIN`, `HIST.PIN`, `HIST.ROLLBACK`, `HIST.TIME`, `HIST.AHEAD`, `HIST.CHECKPOINT` |

Correspondance avec les sept responsabilités sémantiques du scope figé :

| Responsabilité | Mécanismes |
|---|---|
| Identity | TYPE (formes, genres), HIST (genèse, racine), PROV (détenteurs) |
| Authority | CAP |
| Law | NIV (niveaux), TYPE (déclarations fermées), HIST (loi applicable à chaque position) |
| State | TYPE, HIST |
| Evidence | PROV, NIV |
| Obligation | OBL |
| Effect | OBL (ligne d'effet), TYPE (effet typé), CAP (re-jugement) |

La suffisance des six primitives pour toute règle métier n'est pas démontrée ; c'est un objectif. Une intégration qui exigerait une septième primitive rouvre la frontière (§22).

### 4.4 Langage de loi

Le langage est **fini, borné, positif** :

- Prédicats : `eq`, `prefix`, `observed`, `compare`, `closed_at_least`, `open`, `related`.
- `compare: [propriété, le|ge, borne, niveau]` (D35) compare un nombre mesuré à une borne de la loi, en arithmétique exacte (`Fraction`) sur des décimales `-?[0-9]{1,12}(\.[0-9]{1,6})?` ; aucun flottant. C'est ainsi que les floors bornent le jugement de l'instrument : le scanner mesure, la loi fixe le seuil.
- `related: [relation, gauche, droite]` n'interroge que les relations constitutionnelles `role`, `holds`, `parent`, `owns`, `type`, `state`, avec les liaisons `$author`, `$resource`, `$under`. Chaque interrogation est directe et bornée, sans code ni recherche non bornée.
- `where` n'accepte que des chaînes et des entiers [V6-3].
- Une condition ne voit que les faits qu'elle nomme, pour la ressource qu'elle juge [V6-causes].
- Aucune négation : l'absence d'un fait ne permet rien.
- Les ressources déclarent types, champs scalaires fermés, états, état initial et table de transitions. Une transition déclare ses états de départ et d'arrivée, ses contraintes et la liste **exacte** des champs écrits. Une déclaration ne peut écrire ni racine, ni droits, ni constitution, ni preuves, ni obligations. Enregistrer exige `register:<type>` ; transitionner exige `transition:<type>:<operation>`.
- Les instruments déclarent méthode, couverture exacte, sources, niveau minimal et fraîcheur.
- Format source humain/agent : TOML (`.standard/law.toml`), lu comme les mêmes déclarations typées que K juge. Ce n'est ni un second langage ni un second interpréteur.

### 4.5 Composition et évolution

- La composition est **additive** : le client ajoute ou durcit. Il ne retire ni n'affaiblit un floor.
- Un client peut ajouter des façons de prouver, **jamais** à un niveau inférieur à celui du floor [V6-7].
- Une obligation bloquante ne peut viser que des genres qui agissent, attestent ou atténuent ; jamais une restriction ou `checkpoint` [V6-2].
- Opérations : `ops.<op>.trusted` est une liste **additive** de contrats T requis ; T07/T08 sont des minima non retirables.
- Une loi présente dans le dépôt est une **proposition**. Seule la genèse ou une entrée `law` signée par l'humain lui donne autorité.
- Changer la loi client passe par le protocole gouverné même quand le changement resserre seulement.
- Une entrée `law` est traitée sous la loi qui l'a admise ; les nouvelles cibles s'appliquent ensuite [V6-§3.8].
- La relecture historique utilise la loi en vigueur à la position de chaque entrée.
- Retirer une cible client est une décision de loi visible ; ce n'est **jamais** une réparation (`REQUIREMENT_RETIRED_WITHOUT_REPAIR_PROOF`). Sa réintroduction retrouve la dette.
- Changer de release (code ou floors) exige une nouvelle genèse sélectionnée de l'extérieur. Aucune migration silencieuse, aucun reset automatique, aucune exception de bootstrap. Un historique importé reste une provenance, jamais une preuve.

### 4.6 Identité et définition

| Objet | Épinglé sur | Si la définition change |
|---|---|---|
| Proposition | Racine **et** loi au moment de l'approbation | Périmée ; nouvelle proposition obligatoire [V6-§3.2] |
| Capacité | Nom **et** contenu canonique de ses conditions | L'ancienne capacité ne reçoit pas la nouvelle interprétation |
| Intention | Contrat exact de l'opération | Nouvelle intention si arguments, ressource ou profil changent |
| Approbation humaine | Racine courante | Ne traverse pas une rotation |
| Preuve | Définition complète de sa cible (ressource, propriété, source, propriétaire, seuils, couverture, route) | Invalidée ; nouvelle observation exigée [V6-§3.1] |
| Instance d'obligation | Déclaration d'origine | Une nouvelle règle de clôture ne solde pas l'ancienne instance [V6-§3.7] |
| Clôture | Contrat d'origine, provenance, fraîcheur | N'accorde aucun droit sous un autre contrat |

### 4.7 Source de l'autonomie

L'autonomie vient de **l'écart entre ce que Standard et le client demandent et ce que le dépôt a**. Toute exigence active produit des besoins observables dès son activation, même sans route installée ni écart encore attesté. Chaque besoin non satisfait produit une obligation ; chaque obligation produit du travail. Une obligation ne crée **jamais** de permission.

---

### 4.8 Les règles du jeu (D51)

Le système part des situations où une personne doit avoir le dernier mot, pas d'une organisation. Trois objets suffisent :

- **Le socle** (`catalog/floors.py`, lié à la genèse) : chaque coup possible (une opération), ses routes, et pour chaque seuil la borne que personne ne peut relâcher.
- **Les règles du jeu** : le document client, signé par l'humain (une entrée `law`), en vigueur aussitôt. Il ne contient que des choix *à l'intérieur* du socle : quelles routes autonomes restent allumées (`routes`), les seuils que ces routes comparent (`settings`, liés dans les atomes `compare` par `@nom`, jamais plus lâches que le socle : le sens se déduit de `ge`/`le`), et ce contre quoi la production est jugée (objectif, latence, fenêtre de mise en production, composants, SLO, sondes, silences). Les options d’équipe sont retirées : un humain, aucun délai d’élargissement et l’horloge de l’opérateur (D61).
- **Les coups** : chaque opération sur une ressource exacte. Un coup est *prêt* quand une route autonome tient sur des faits mesurés par le scanner, *décidé* quand l'humain a dit oui, *à toi* quand seule ta décision l'ouvre.

**Les trois gestes de l'humain :** **oui** (une observation `decision = approve` sur la ressource exacte du coup), **non** (un gel de la ressource), **règles** (signer de nouvelles règles du jeu). Rien d'autre n'est requis pour qu'une personne et un agent travaillent ; tout le reste est mesuré.

**Situations où l'humain garde le dernier mot** (route humaine seule, ou route autonome que les règles recommandées laissent éteinte) : intégrer le code de quelqu'un d'autre (`integrate`) ; réparer hors du périmètre d'écriture de la cible ; implémenter sans contrat accepté ; mettre en production hors fenêtre ou sous le budget gelé ; revenir en arrière au-delà de l'horizon ou à travers des migrations ; redémarrer (éteint par défaut) ; changer les règles elles-mêmes, que l'agent ne signe jamais (`CAP.HUMAN`).

**Ce que l'agent fait et comment.** Une boucle (`agent/loop.py`) : lire la vue, laisser ses producteurs écrire des candidats dans son propre dépôt (réparations, constructions), puis jouer chaque coup *prêt* ou *décidé*, la production d'abord et une seule bascule par passe. Il ne choisit ni route, ni seuil, ni capacité : il en détient une seule. Sa tactique ne peut que le retenir (reculer avant d'avancer, ne pas redémarrer le code qu'une bascule vient d'amener, retirer un canari seulement s'il fait pire au-delà du bruit ou si main a bougé) et chaque retenue est écrite pour la console. La file de l'humain (`moves.queue`) est la même lecture des coups, vue de l'autre côté.

**Deux juges.** Le noyau juge chaque coup sur la route qu'il nomme ; le second juge (`bt/checker.py`) restate les routes, les bornes des seuils et l'entrée en vigueur immédiate des règles.

### 4.9 Le catalogue des exigences et le travail (D54–D63)

Le catalogue est la définition commune des exigences de Standard : cibles de maintenance, règles techniques, paramètres signés, contrats des blocs et vérifications déclarées. Le socle en compile les obligations et les bornes ; les choix clients signés instancient la loi effective. Les modèles, budgets et cadences relèvent de la configuration d’exécution. Quatre responsabilités se raccordent à cette définition :

1. **Imposer des protections par les blocs** (`blocks/python/standard_blocks`, `blocks/js/front.mjs`). Un module épinglé par préoccupation (web, sessions OIDC, accès, crypto, fichiers, parseurs, processus, appels sortants, entrées, rendu, journaux, exécution, données) ; les API brutes qu'il couvre sont interdites ailleurs. Le fait du scanner `blocks = clean | breaks:<n> | uncovered:analysis` juge le changement (comme `regressions`) et conditionne les routes autonomes `scoped` et `accepted`. D68 (§4.10) arrête le transfert de la plupart de ces protections vers la plateforme d'exécution ; ce point décrit le code courant jusqu'à la bascule.
2. **Mesurer : les sondes de Standard** (`instruments/rule_probes.py`). Écrites par Standard, jamais par l'agent, remplies avec les valeurs en vigueur, elles démarrent l'application du produit (`@app`) dans un processus séparé : en-têtes, cookies, CORS, CSRF, méthodes, erreurs, matrice d'accès rôle par rôle, limites d'envoi, flux OpenID Connect contre un faux fournisseur, rotation, déconnexion, expiration.
3. **Construire et relire** (`agent/candidate.py`). Le catalogue sélectionne les exigences applicables aux surfaces concernées, sans hiérarchie de passes. Un constructeur écrit ; deux reviewers en lecture seule examinent le même candidat en parallèle : comportement/sécurité et simplicité. Le constructeur corrige ou motive un désaccord ; toute modification invalide les revues. Les règles sont recalculées sur les nouvelles surfaces et fonctionnalités du brouillon. Un refus conserve le texte de la règle.
4. **Explorer : la patrouille** alterne une recherche de simplicité à l’échelle du dépôt et les catégories de règles qu’une IA lit. Elle passe après les coups ordinaires, selon une cadence persistée. Ses résultats sont des propositions liées au commit et au digest de loi, jamais des faits, une dette de sûreté ou un refus.

**Le catalogue** (`catalog`, CC BY-SA 4.0, attribution OWASP) : les 345 exigences d'OWASP ASVS 5.0 (niveaux 1 à 3) portées par 156 règles ou écartées avec leur raison (33 documentation seule, 9 hors dépôt, 2 déjà dans le socle), le CWE Top 25 2025 attaché, des règles d'exploitation (liste de lancement SRE ; DORA, règlement délégué 2024/1774 art. 17, comme motif et non comme prétention de conformité). Chaque règle : un ordre (`do`), ce qu'il ne faut jamais faire, quand elle s'applique (fonctionnalités) et se déclenche (surfaces, constructions lues par `instruments/surfaces.py`), qui la vérifie (déterministe, IA, humain), le bloc qui l'absorbe, les obligations résiduelles de câblage, les vérifications, des exemples par langage, ses sources. Aucun mot vague : *sensible*, *critique*, *de confiance* sont des valeurs nommées (`@access`, `@critical`, `@sensitive`…) avec un défaut strict ; l'humain les signe dans les règles du jeu, l'agent peut les proposer.

**Primitives et intégrations, un contrat (D59, D67).** Chaque bloc a un contrat unique (`does`, `probes` dans `blocks.toml`). Les neuf implémentations génériques sont déclarées sous `[block.X.python]` : crypto, parse, process, outbound, input (Pydantic), data (SQLAlchemy), render, log, runtime. Web, session, access et files restent des intégrations `[block.X.fastapi]`. Le catalogue résout une seule fois leur table de support : FastAPI hérite des primitives Python sans deuxième définition ; scanner et missions lisent cette même projection. Un fichier `.py` ne désigne plus FastAPI : un import FastAPI doit être observé, sinon la pile reste Python. Les autres frameworks Python ne reçoivent pas les intégrations FastAPI. Le paquet de base ne dépend plus de FastAPI/PyJWT ; `standard-blocks[web]` les installe avec le support multipart. Les helpers `Pages.render` et `runtime.install(app)` demandent explicitement Starlette/FastAPI et ne rendent pas les autres frameworks compatibles. Les intégrations JS sont déclarées sous `[block.X.nextjs]` (`blocks/js/nextjs`, paquet `@standard/blocks` : `web` — middleware `guard`, en-têtes, cookies, redirections ; `session` — OIDC avec PKCE et vérification du jeton d'identité par WebCrypto ; `access` — `route(id, …)` et `action(id, …)` ; `input` — schémas Zod stricts, corps borné). Les blocs Next.js sans implémentation (crypto, journaux, données…) gardent leurs interdictions JS (`[block.X.js]`) mais ne doivent rien : l'adoption n'est due que pour un bloc que la pile du produit possède. Le scanner lit la pile et les points d'entrée Next là où vivent les fichiers (`app/**/route.ts`, `pages/api/**`, actions `"use server"`), avec l'identifiant d'accès de chaque export. Le contexte commun montre l'usage du bloc pour la pile du produit. Une application que Standard ne peut pas importer est sondée en HTTP : `@app` est alors l'URL où elle tourne (service de CI, préversion) ; seules les sondes purement HTTP s'exécutent, les autres sont une lacune de la release sur cette pile, jamais une dette.

**Au-delà des référentiels (D60).** Les référentiels disent quoi vérifier ; un bloc supprime la manière de se tromper, et un durcissement protège tous les produits à la fois. Six principes, détaillés bloc par bloc dans `blocks/HARDENING.md` : rendre la version dangereuse impossible à écrire (types `Secret`, `SafeHtml`, `TrustedUrl` ; filtres de propriétaire et de locataire posés par SQLAlchemy lui-même avec `for_user` ; une route sans identifiant d'accès ne démarre pas en production) ; tout borner par défaut (URL, en-têtes, corps, profondeur JSON, temps avant réponse, réponses sortantes, processus, archives, journaux) ; fermer les contournements (rebinding DNS vérifié à la connexion, différentiels d'analyseurs, X-Forwarded-For lu par la droite, bombes de décompression, contrôles Unicode, clés embarquées dans un JWT, table de limites vidable) ; échouer fermé ; n'étendre que vers plus strict (crochets `refuse=`, prédicats `also=`) ; durer (sorties versionnées, rotation des clés, `needs_rehash`, place prévue pour les signatures post-quantiques du fournisseur). Nouvelles valeurs : `@body_max_bytes`, `@json_max_depth`, `@request_timeout_s`, `@outbound_max_bytes`, `@hosts`, `@trusted_types`. Sessions et limites dans un magasin partagé (mémoire ou Redis).

**Couverture et dette.** Une cible du socle par catégorie (`rules-<catégorie>`, 17) : elle tient quand aucune règle applicable n'est enfreinte ni non mesurée faute de ce que le produit doit déclarer. Le reste (patrouille, lacunes de la release : semgrep, gabarits de tests, sondes du fournisseur d'identité) est visible, jamais une dette. Un bloc pas encore adopté est une dette avec échéance, pas un refus ; un changement qui enfreint une règle mesurée est une régression.

**Limites des mesures (D62).** SAST et catalogue partagent la même invocation isolée de Bandit ; seuls les fichiers Python demandés sont matérialisés, et `-I` empêche un module du candidat de remplacer l’outil installé. Une panne, une sortie vide/invalide ou un rapport omettant des fichiers demandés produit une mesure indisponible. Un import de bloc établit sa présence ; des appels résolus et, pour accès/sessions Python, un `bind`, établissent seulement un câblage syntaxique. Les sondes comportementales restent distinctes. Aucun de ces indices statiques ne prouve que tous les chemins traversent le bloc. Le scanner JavaScript reste lexical : alias directs, imports renommés, déstructuration et propriétés littérales sont suivis ; appels calculés, exécution/imports dynamiques et interpolation de templates sont explicitement non mesurés. Erreurs de syntaxe Python et fichiers trop grands le sont aussi. Le fait `blocks` ne vaut alors pas `clean` ; il ne peut ouvrir une route autonome `scoped`/`accepted`. Les autres limites lexicales restent à couvrir par un parseur épinglé et des sondes.

### 4.10 Invariants imposés par la plateforme d'exécution (D68)

Statut : décision arrêtée, étape 1 livrée. §4.9 et §20.7 décrivent le code courant jusqu'à la bascule.

**État de la mise en œuvre.** Étape 1, le bac : `enclosure/oci.py` génère le fichier OCI des murs (namespaces dont un réseau vide, aucune capacité, système en lecture seule, montages déclarés, profil seccomp de Docker épinglé dans `enclosure/seccomp.json`, rlimits, groupe de contrôle bornant processus, mémoire et CPU) ; `enclosure/bac.py` l'exécute avec runc ou crun, retire le conteneur après chaque exécution et lit les compteurs du noyau. Le précontrôle et les expériences de l'agent l'utilisent. Il échoue fermé : rien ne tourne sans un runtime qui accepte cette définition, et en root jamais sans groupe de contrôle (Linux n'applique pas `RLIMIT_NPROC` à root). `instruments/walls.py` mesure 14 murs depuis l'intérieur en tentant ce que chacun doit refuser ; un bac privé de son filtre ou de son namespace réseau est mesuré cassé. Mesuré localement (octobre 2026, runc, hôte mixte cgroup v1/v2 que crun refuse, en root) : les 14 tiennent. Deux murs mémoire emboîtés : le groupe de contrôle pour l'exécution entière et un plafond d'espace d'adresses par processus (large sous un groupe, pour les runtimes qui réservent d'avance). La CI (`.github/workflows/bac.yml`) mesure les murs sur un hôte cgroup v2 pur, en utilisateur ordinaire et en root.

Étape 2, l'entrée (livrée) : `enclosure/gateway.py` dérive la configuration d'Envoy des valeurs (limites d'en-têtes et de corps, délais, méthodes refusées, hôtes, CORS, débit, suppression de tout en-tête d'identité venu d'un client avant tout filtre, autorisation externe vers oauth2-proxy hors routes @public) ; Envoy la valide. `enclosure/gate.py` applique la politique propre à Standard : JSON strict, refus des clés en collision après normalisation Unicode, réécriture canonique (le produit ne reçoit jamais les octets du client), isolation Fetch Metadata, échéance unique, en-têtes de sécurité et attributs de cookies imposés, bannières retirées ; chaque correction et chaque refus est consigné une fois par route. `enclosure/signin.py` configure oauth2-proxy (OpenID Connect avec PKCE S256, cookie `__Host-` chiffré, durées issues des valeurs). `enclosure/identity.py` signe l'identité transmise au produit (JWS EdDSA d'une minute, pour ce seul produit) ; le bloc access la vérifie (`platform_identity`). `enclosure/door.py` est la porte du produit dans le bac : il écoute sur `127.0.0.1:$PORT` de son réseau vide, la plateforme l'atteint par un socket Unix. `enclosure/stack.py` assemble le tout ; `runtime/runner.py` lance chaque release dans le bac, derrière sa porte, et refuse sans bac sauf `--unconfined` explicite. Les composants sont épinglés par version et empreinte (`enclosure/components.toml`, `python -m tools.components fetch`). Dans le précontrôle, si `@start` est signé, base et candidat tournent derrière cette même entrée ; ce que la porte a dû corriger ou refuser sur le candidat et pas sur la base devient sa leçon (`agent/entry.py`) ; ce que la plateforme impose simplement (un en-tête absent) n'en est pas une. Vérifié de bout en bout : corps lent coupé à l'échéance, clés en collision refusées, identité forgée effacée, JSON canonique reçu, TRACE refusé, corps trop grand refusé, connexion OpenID Connect complète contre un fournisseur factice avec identité vérifiable. Limites : la limite de débit est un seau par écouteur (une limite par adresse exige le service de limitation d'Envoy) ; TLS n'est pas encore terminé par Envoy dans le prototype local ; après la connexion, l'utilisateur revient à `/`.

Étapes 3 et 4, la sortie, les secrets, les clés, les fichiers, les journaux et les données (livrées) : la seule route hors du bac est le proxy de sortie (`enclosure/egress.py`, mitmproxy épinglé avec ses dépendances par empreintes, politique dans `enclosure/egress_addon.py`). Dans le bac, `HTTPS_PROXY` mène, par la porte, à un socket monté en lecture seule ; un code qui ignore le proxy n'a aucune route. Le proxy termine TLS avec une autorité propre à la plateforme (seul certificat de confiance du bac, clé jamais dans le bac), n'autorise que @destinations, refuse les noms qui résolvent vers une adresse non publique et se connecte à l'adresse vérifiée, remplace `secret:NOM` dans un en-tête par la valeur du coffre au moment de l'envoi et seulement vers un hôte permis pour ce secret (ailleurs : refus et alarme), borne les réponses. Il sert aussi `keys.standard` (chiffrer, déchiffrer, HMAC, signer, vérifier avec les seules clés `product-*` du service de clés, sans jeton dans le bac) et `files.standard` (stockage par la plateforme, types @upload_types, taille @upload_max_bytes, quota @user_quota_bytes, restitution en pièce jointe). Le service de clés et le courtier sont OpenBao (`enclosure/keys.py`) ; la clé d'identité y est créée et la passerelle signe par lui. La sortie du produit est capturée par la plateforme, structurée, bornée et expurgée de tout secret connu (`enclosure/logs.py`), avec une configuration de collecteur OpenTelemetry (`enclosure/telemetry.py`). Les données : PostgreSQL sans écoute TCP, joint par un socket monté, rôle `product` sans mot de passe (`enclosure/data.py`). Le produit déclare pour qui il agit avec `standard.act_as(<jeton reçu>)` ; PostgreSQL vérifie lui-même la signature Ed25519 (PL/Python, langage où le produit ne peut écrire) et garde le sujet pour la seule transaction. Toute table créée avec `owner_id` ou `tenant_id` est aussitôt reprise par la plateforme : RLS activée et forcée, politique restrictive, droits de données rendus au produit, qui ne peut plus la désactiver. Oublier `act_as` ne rend aucune ligne. Les certificats mTLS des services sur machines distinctes viennent du moteur PKI d'OpenBao, et Envoy les présente (`gateway.mtls_cluster`) ; sur une même machine, les services se parlent par sockets Unix. Les refus de la sortie deviennent des leçons comme ceux de l'entrée. Vérifié de bout en bout : secret injecté en HTTP et en HTTPS sans jamais entrer dans le bac, destinations, adresses privées et secret vers un autre hôte refusés, connexion directe impossible, clés du produit seules utilisables, fichiers bornés, journaux expurgés, deux personnes connectées par OpenID Connect ne voyant chacune que leurs lignes à travers la passerelle et la base. Limites : la sortie passe par les réglages de proxy que les SDK honorent, pas par une redirection noyau ; l'échéance des appels sortants n'est pas encore imposée par le proxy ; OpenBao tourne en mode développement dans le prototype (en mémoire) ; une table sans `owner_id` ni `tenant_id` n'est pas filtrée.

Mesure et retour (livrés) : `instruments/platform_walls.py` mesure 13 murs au-delà du bac en tentant ce que chacun doit refuser, du point de vue d'un client, du code du produit et de son rôle de base de données (`python -m tools.platform_walls`, aussi en CI) ; les 13 tiennent ici. Une correction ou un refus de la plateforme en production devient un fait, `repo:code:platform refusals`, capté par T à `/__standard/platform` du lanceur (gate et sortie) : la cible `run-platform` en fait une dette, donc une tâche de réparation du code pour l'agent (D69). Les alarmes : le filtre d'appels système porte `SECCOMP_FILTER_FLAG_LOG`, et `enclosure/alarms.py` lit le journal du noyau, garde les appels qu'aucun code ordinaire ne fait (montage, namespaces, traçage, modules, trousseaux, BPF…), les attribue à l'exécution du bac par son groupe de contrôle et les écrit pour le contrôle caché et l'humain, jamais pour l'agent. L'intention métier déclarée commence à être sondée : `field-uses` (DATA-MIN) lit chaque réponse d'un usage déclaré dans @field_uses et refuse les champs en trop ; LOCKING, CONCURRENCY, VALIDATE-COMBO et TRANSACTION restent prévues, faute d'un oracle sans capacité ni route déclarées.

Restent : gVisor pour les agents et Kata+Firecracker pour l'isolation forte (même fichier OCI ; gVisor n'est pas téléchargeable depuis cet environnement, et Firecracker exige KVM), crun sur un hôte cgroup v2 pur (il efface le groupe avant lecture de ses compteurs : mur `cgroups` alors `unmeasured`), et T06.

**Principe.** Une protection que le produit doit adopter peut être oubliée ou contournée : le scanner constate l'adoption, il ne l'impose pas. Les cinq écarts de §20.7 ont une seule cause : chaque bloc réimplémente une propriété transversale (temps, sortie réseau, parsing, secrets). Standard impose donc ces propriétés par l'environnement d'exécution du produit. Le code du produit ne peut pas les violer, qu'il adopte quelque chose ou non : un oubli devient une panne fonctionnelle (pas de réseau, pas de secret), jamais une faille silencieuse. Seul reste en blocs ce que seul le code du produit peut décider.

**Le bac.** Chaque processus du produit tourne dans un bac défini par la release : un conteneur OCI exécuté par crun, dont le fichier `config.json` est généré à partir des murs. Namespaces dont un réseau vide hors boucle locale, système de fichiers en lecture seule hors des dossiers déclarés, environnement vide, aucune capacité, filtre seccomp en liste d'autorisation (le profil par défaut de Docker, épinglé), limites de groupes de contrôle (processus, mémoire, CPU) et rlimits. La séparation repose sur le noyau Linux. Pour le service géré, gVisor (`runsc`, qui lit le même fichier OCI) remplacera crun sans changer le contrat ; Firecracker reste une option. Les murs sont des données dérivées de la loi effective (`@hosts`, `@body_max_bytes`, `@request_timeout_s`…), jamais un réglage du produit. Une seule définition du bac (`enclosure/`) sert au précontrôle de l'agent, aux tests et à la production : ce qui passe dans l'un passe dans l'autre, et aucun second jail n'existe.

**Deux hébergements.** La plateforme fait partie de la release. En mode dépôt seul, le client exécute le même bac, la même passerelle et les mêmes services sur son infrastructure ; le service géré les exécute chez Standard. Un produit déployé hors de la plateforme n'a aucun des invariants ci-dessous, et la surface le dit.

| Invariant | Mécanisme de la plateforme | Remplace |
|---|---|---|
| Entrée | Passerelle unique, seul chemin vers le bac. Le produit écoute sur `127.0.0.1:$PORT`, la boucle locale privée de son bac, comme partout ailleurs ; la plateforme y relie un socket Unix depuis l'extérieur. Aucune interface réseau n'est ajoutée au bac. La passerelle applique : taille, profondeur, délai couvrant lecture et réponse, JSON canonique refusant doublons et collisions après normalisation Unicode, en-têtes de sécurité, CSP, CORS, CSRF, attributs de cookies, limites de débit. Le produit reçoit le JSON ré-écrit sous forme canonique, jamais les octets bruts : aucun écart entre deux analyseurs | web, input (forme), parse (entrée) |
| Identité | Session OIDC à la passerelle (PKCE, vérification du jeton, rotation, déconnexion, expiration). Le produit reçoit l'identité vérifiée dans un en-tête que la passerelle efface toujours à l'entrée : un jeton court signé par le service de clés, que le bloc access vérifie. Si un mur cédait, l'identité ne pourrait toujours pas être forgée | session |
| Sortie | Proxy transparent, seule route hors du bac : il termine le TLS avec une autorité propre au bac (clé détenue par le service de clés, jamais dans le bac) et rouvre la connexion vers l'hôte. Les SDK du marché fonctionnent sans modification. Hôtes `@hosts`, DNS résolu et vérifié par la plateforme, une redirection ne mène qu'à un hôte de `@hosts`, durée et volume bornés ; journal d'egress sans contenu | outbound, parse (réponses) |
| Secrets | Courtier : le produit ne tient qu'une référence (`secret:<nom>`) ; la valeur est ajoutée par le proxy de sortie ou le proxy de base de données, pour la seule destination déclarée. Connaissant les valeurs, la plateforme les efface des journaux et refuse toute sortie qui les porte vers un autre hôte | `Secret`, runtime (secrets) |
| Clés | Service de clés : chiffrer, déchiffrer, signer, HMAC par référence ; les clés ne quittent jamais la plateforme | crypto |
| Ressources | cgroups, rlimits et échéance de l'hôte pour tout le bac, sous-processus compris ; configuration injectée, santé et cycle de vie conduits par la plateforme | process, runtime |
| Données | Proxy de base de données (Postgres seul pour l'instant) : identifiants détenus par le courtier. À chaque transaction, il pose l'identité vérifiée, signée par la plateforme ; les politiques Row-Level Security vérifient cette signature et filtrent propriétaire et locataire. Le produit n'a ni la clé ni un rôle qui contourne ces politiques | data |
| Journaux | Capture de stdout/stderr, structurée, bornée, expurgée | log |
| Fichiers | Envois bornés et typés à la passerelle, stockage par la plateforme, aucune écriture hors des dossiers déclarés | files |

**Ce qui reste en blocs** (code du produit, par pile FastAPI et Next.js) : **access** — identifiant d'accès sur chaque route et action, décision par rôle et par objet à partir de l'identité reçue ; **render** — échappement en sortie (`SafeHtml`, `TrustedUrl`), complété par la CSP de la passerelle ; **front** — le code exécuté dans le navigateur (messages entre fenêtres, stockage local, intégrité des scripts, typage strict), que ni le bac ni la passerelle ne voient. La validation métier (schémas Pydantic ou Zod stricts) devient une règle qui emploie l'outil du framework, pas un bloc de Standard.

**Mesure.** Les murs se mesurent depuis l'intérieur du bac. Des sondes de Standard (instruments de T) tentent ce que le bac doit refuser : connexion directe, résolution DNS, écriture hors des dossiers, lecture d'un secret, corps lent, clés en collision, en-tête d'identité forgé, multiplication de processus. Un mur qui cède est une régression mesurée. Le fait `blocks` du scanner ne porte plus que sur les trois blocs restants.

**Qui tient chaque règle.** Chaque règle du catalogue déclare `held_by` : une partie de la plateforme (`platform:ingress`, `identity`, `egress`, `secrets`, `keys`, `data`, `resources`, `logs`, `files`), le code du produit (`code`, ou `code:access`, `code:render`, `code:front` quand un bloc l'aide), le fournisseur d'identité du client (`idp`, un réglage pour l'humain) ou la ligne de release de Standard (`release`). Une règle tenue par la plateforme l'est une fois sa partie de D68 livrée ; jusque-là, son bloc la tient toujours. Tri (octobre 2026) sur les 156 règles : 69 plateforme, 65 code (dont 19 avec un bloc), 19 fournisseur d'identité, 3 release. Les 19 attributions douteuses sont tranchées : NO-DEBUG passe au code (le réglage de débogage est celui de l'application) et SESSION-LIST au fournisseur d'identité (la liste des sessions est une fonction de son espace de compte) ; les 17 autres sont confirmées (la passerelle corrige cookies, type de contenu et redirections ; le service de fichiers déballe et adresse ; les serveurs de média TURN et DTLS restent la responsabilité du produit). Sept règles qui n'avaient que la revue sont confiées à un mur avec leur sonde prévue (`planned`) : ORIGIN-SPLIT, ADMIN-LAYERS et MSG-SIGN à la passerelle, AUTHZ-SUBJECT à RLS, LOG-PROTECT aux journaux, TLS-INTERNAL à la sortie, SERVICE-AUTH à l'identité ; ADAPTIVE-AUTHZ passe en `code:access`. Une sonde prévue apparaît dans la matrice sans donner de force tant qu'elle n'existe pas. Les intentions métier se déclarent dans les règles du jeu (`@limited`, `@field_rules`, `@field_uses`, `@operations`) ; LOCKING, CONCURRENCY, VALIDATE-COMBO, DATA-MIN et TRANSACTION les lisent et ont chacune une sonde prévue. Les réglages du fournisseur d'identité (BIOMETRIC, PSTN, RENEWAL-NOTICE) ont une sonde prévue par release. Le catalogue refuse désormais qu'une règle se dise vérifiée de façon déterministe sans contrôle déterministe, ou l'inverse. Le mur reste grossier par nature ; la granularité des 156 règles vit dans cette attribution, que la mission montre règle par règle (§4.11).

**Confiance.** La plateforme est hors K+T : elle n'atteste rien que K utilise, ne détient aucun credential de Standard et ne fait partir aucun effet ; son déploiement fait partie de l'effet de release déjà jugé. Le découpage K/T/U n'est pas rouvert. Elle devient en revanche la base de confiance *du produit* : compromise, elle fait tomber les invariants du produit, pas l'admission. Elle reste donc petite, épinglée dans la release et sans IA, comme la TCB. Les processus U de Standard passent sous la même plateforme (D66 sera repris en conséquence) ; K et T gardent leur propre isolation (T06).

**Construction : on écrit la politique, on réutilise les mécanismes.** Un composant éprouvé par l'industrie vaut mieux qu'un composant jeune, même petit. Standard réutilise crun et le profil seccomp de Docker pour le bac, pasta pour son réseau, Pingora (Rust, Cloudflare) pour la passerelle et le proxy de sortie, oauth2-proxy pour la session OIDC, mitmproxy comme proxy de sortie du prototype, OpenBao (moteur *transit*) pour le service de clés et le courtier de secrets, et la Row-Level Security native de Postgres. Chaque composant est épinglé dans la release et fait partie de la base de confiance du produit. Standard n'écrit que ce que personne ne fournit : la traduction de la loi en murs (le fichier OCI, les listes d'hôtes, les limites), le JSON canonique avec refus des collisions comme filtre de passerelle, la lecture des refus et la carte des capacités (§4.11), et les sondes de murs.

**Pile.** Les invariants de la plateforme valent pour tout langage ; seuls les trois blocs dépendent de la pile. Linux est requis, prototype local compris (une VM ailleurs).

**Mise en œuvre**, dans cet ordre : bac et sondes de murs ; passerelle d'entrée et session ; service de sortie, courtier de secrets et expurgation ; services de clés et de fichiers ; proxy de base de données et politiques RLS ; retrait des blocs absorbés et de leurs entrées `[block.*]`, en bascule unique sans alias (projet en v0).

### 4.11 Un mur, deux lectures (D69)

Statut : décision arrêtée. Livré : la carte des capacités (`enclosure/capabilities.py`, calculée depuis le fichier OCI exact du bac) et la lecture des leçons dans le précontrôle (`enclosure/refusals.py`, `agent/precheck.py`). Chaque exécution des tests et du contrat dans le bac est lue contre la carte ; une leçon nomme la capacité, la partie de la plateforme qui la tient et les règles du catalogue de même tenant (`held_by`). **Des tests verts sur un code qui a touché le mur ne sont pas un succès** : un candidat dont le code provoque une collision que le code de base ne provoquait pas n'est pas proposé, et ses leçons reviennent à l'agent. Sources : les compteurs du noyau et le délai (des faits), puis la sortie du programme (le texte du candidat, qui ne peut instruire que lui-même). Restent : les alarmes, qui exigent l'observation de la plateforme (journal noyau des appels refusés) et jamais la sortie du candidat ; les refus avalés sans trace, visibles seulement quand le proxy de sortie sera la seule route ; les refus de production en WorkItems.

**Principe.** L'agent conçoit librement à l'intérieur de limites physiques strictes ; un conflit entre son code et une limite devient une information d'ingénierie, sans que la sécurité ne se relâche jamais. Il n'y a qu'un seul mur : le bac de §4.10. La pédagogie n'est pas un second mur, c'est une **lecture** des refus de ce mur. Les deux silos restent séparés : le bac garantit et ne parle pas ; la lecture explique et ne garantit rien. Une lecture fausse dégrade l'apprentissage, jamais la sécurité.

**1. La carte des capacités, avant de concevoir.** Chaque mission (`context.missions.assemble`) la reçoit dans un seul endroit, l'entrée `autonomy`, avec ce que l'agent peut et ne peut pas faire et, pour chaque règle sélectionnée, qui la tient (`held_by`, §4.10). La carte décrit le bac où le code tournera : hôtes joignables, services disponibles (sortie, clés, fichiers, base via le proxy), références de secrets sans valeurs, dossiers inscriptibles, limites de ressources. Elle est dérivée des mêmes données que les murs, jamais rédigée à part. L'essentiel du gain est là : un agent qui découvre les limites en s'y cognant produit des contournements et de mauvaises abstractions.

**2. Deux lectures d'un même refus.** Standard lit chaque refus observé avec la carte et le range dans une seule de deux cases :

- **Leçon** : le refus correspond à une capacité absente de la carte (un hôte non autorisé, un dossier non inscriptible, une limite atteinte). C'est une erreur honnête. L'agent reçoit un enregistrement de refus : opération tentée, composant, capacité manquante, interface autorisée qui répond au besoin, chemin pour la demander.
- **Alarme** : le refus ne correspond à rien qu'un code ordinaire tenterait (monter un système de fichiers, tracer un autre processus, créer un namespace, changer de privilèges). Il est signalé au contrôle caché (§11.7) ; l'agent ne reçoit rien de plus que l'échec brut de son programme.

Règle : **un enregistrement de refus ne dit jamais plus que la carte** ; il ne nomme ni le mécanisme, ni la règle, ni le seuil qui l'a produit. Ces enregistrements sont des diagnostics, pas des faits signés.

**3. Observer les refus.** Certains refus sont muets dans le bac. Le réseau est observé là où il passe de toute façon : le proxy de sortie, seule route hors du bac, voit chaque tentative. Les compteurs des groupes de contrôle disent quelles limites le noyau a appliquées. Le reste apparaît dans la sortie du programme ; un traducteur relie ces erreurs connues aux entrées de la carte. Une erreur qu'il ne sait pas relier reste brute, jamais devinée.

**4. Qui tranche.** Une capacité que la loi interdit : l'agent adapte son code. Une capacité dont le produit a légitimement besoin : l'agent rédige la valeur, l'humain la signe dans les règles du jeu. Rien ne s'élargit automatiquement. Des leçons répétées contre la même limite sous des formes différentes deviennent une alarme.

**5. Où les refus apparaissent.** Pendant le précontrôle et les tests, les leçons reviennent à l'agent dans le dossier du candidat. En production, une leçon est un incident qui ouvre une WorkItem ; une alarme est escaladée à l'humain.

**Confiance.** La carte, le traducteur et les enregistrements sont hors base de confiance du produit. Seul le bac porte les invariants de §4.10.

### 4.12 La matrice de retour (D70)

Statut : décision arrêtée, mise en œuvre en cours. Livré : la matrice et le filtre (`context/feedback.py`), le dossier unique du précontrôle (mur, tests, contrat, sondes locales, lint et typage passent tous par lui ; c'est lui que l'agent relit à l'essai suivant) et le plancher de force par règle (`catalog/feedback_floor.json`, gardé par les tests). Mesuré : 77 règles ont un fait mesuré à l'admission, 62 un contrôle statique pour plus forte source, 17 la seule revue, aucune n'est sans source ; aucune n'a encore la force « mur », qui exige un mur en place là où tourne le produit. Depuis : chaque leçon du mur porte la pile du code de l'agent (`fichier:ligne`, un observateur lu par Python rend visibles les refus réseau même avalés) ; la réfutation du scanner à l'admission entre dans le même dossier comme faits liés à leurs règles ; la colonne vertébrale donne, avant de coder, pour chaque fichier touché, ses définitions avec le code et les tests qui les utilisent, celles qu'aucun test ne couvre, et les définitions voisines à réutiliser (`before_coding`) ; le taux de passage au premier essai est enregistré (`agent/attempts.py`) ; `python -m surface matrix [RÈGLE]` montre la matrice, les trous et ce taux. Qualité (`agent/quality.py`, `agent/acceptance.py`) : le précontrôle mesure la complexité (radon) et la duplication des fonctions ajoutées ; au-delà des limites, c'est un problème que l'agent corrige. Il mute un échantillon des lignes changées et rejoue les tests de main : un mutant qui survit dit que les tests ne voient pas ce comportement. Comme l'agent ne peut pas écrire de tests dans un dépôt maintenu, ces survivants vont à l'humain (dans le dossier et le message de la proposition), jamais en refus. Les tests d'acceptation peuvent être rédigés par un agent distinct, depuis la seule spécification, en lecture seule, avant toute implémentation (`python -m agent acceptance`) ; c'est un brouillon que l'humain corrige et signe comme contrat. Restent : les sources de production, qui arrivent avec la plateforme.

**Principe.** L'agent a plusieurs sources de retour : le mur, les tests, le lint et le typage, la SAST, le scanner des blocs, les sondes, et en production la passerelle, le proxy de sortie, RLS et le courtier de secrets. Elles ne forment qu'**une seule voie de retour**, dont la clé commune est la règle du catalogue (chaque règle déclare qui la tient, §4.10). La matrice croise les 156 règles et quatre moments ; chaque retour, d'où qu'il vienne, est rattaché à une règle et à un moment, puis passe par un seul filtre. Une nouvelle source se branche sur ce format, jamais à côté.

| Moment | Sources | Rôle |
|---|---|---|
| Avant de coder (mission) | Contrat de chaque règle, carte des capacités, tenant | Prévenir |
| Construction (précontrôle, dans le bac) | Mur, tests, lint et typage, SAST, scanner des blocs, sondes locales | Corriger avant de proposer |
| Admission (T, K) | Instruments épinglés sur le commit exact | Juger : des faits, pas des leçons |
| Production (RUN) | Passerelle, proxy de sortie, RLS, courtier, sondes de murs, télémétrie | Réparer : un refus ouvre une WorkItem |

**Le filtre.** (1) Un format unique : source, moment, règles, tentative, confiance (fait mesuré ou diagnostic), destinataire. (2) Déduplication : une même règle au même endroit donne un seul retour, quelles que soient les sources. (3) Ordre : les faits avant les diagnostics, ce que le candidat introduit avant ce qui existait. (4) Divulgation bornée : jamais plus que la carte et le contrat de la règle. (5) Routage : une leçon va à l'agent, un fait à K, une alarme au contrôle caché (jamais à l'agent), un besoin légitime devient une valeur rédigée pour l'humain. (6) Budget : l'agent reçoit d'abord les retours les plus importants, dans la limite de son contexte.

**Force d'une règle.** Pour chaque règle, la matrice dit quelles sources la couvrent à quel moment, et sa source la plus forte : un fait mesuré à l'admission (sonde, test, fait), puis le mur effectivement en place, puis un contrôle statique déterministe (blocs, SAST, typage), puis la patrouille ou l'humain. Un mur seulement prévu ne compte pas. Mesuré sur le catalogue (octobre 2026) : les 156 règles ont un retour avant de coder ; 139 ont au moins un contrôle déterministe ; 17 n'ont que la patrouille ou l'humain ; le mur ne donne des leçons en précontrôle que pour 16 des 67 règles tenues par la plateforme. À terme, environ 11 des 17 deviennent mesurables (mur, vérification du fournisseur d'identité, vérification dans le code) ; environ 6 ne le seront jamais par une machine seule (DATA-MIN, VALIDATE-COMBO, TRANSACTION, LOCKING, CONCURRENCY, MULTI-APPROVAL) et deviennent sondables seulement quand l'humain déclare l'intention métier dans les règles du jeu.

**Règle de transition.** On ne retire jamais la source d'une règle sans une source au moins aussi forte qui la remplace. La force de chaque règle est consignée dans la release (`catalog/feedback_floor.json`) ; une baisse est refusée par les tests, une hausse met à jour le plancher. Le retrait des blocs absorbés par D68 ne peut donc pas faire baisser la couverture sans que ce soit visible et refusé.

## 5. Architecture en couches

### 5.1 Quatre couches autour du noyau

Plus une couche est proche du noyau, **moins elle reçoit de signaux**. Les connexions sont limitées, typées et orientées vers l'intérieur.

```
┌──────────────────────────────────────────────────────────────┐
│ SURFACE   humains : maintenu, trous de couverture, dettes,   │
│           décisions attendues, escalades                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ U  AUTONOMIE   agents, WorkItems, découverte,          │  │
│  │                BUILD/RUN, intégrations, Work Engine    │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │ T  CONFIANCE   identités, temps, journal, pins,  │  │  │
│  │  │                second juge, instruments, garde,  │  │  │
│  │  │                readback                          │  │  │
│  │  │  ┌────────────────────────────────────────────┐  │  │  │
│  │  │  │ K  NOYAU   jugement déterministe unique    │  │  │  │
│  │  │  └────────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

| Couche | Reçoit | Produit | Peut | Ne peut jamais |
|---|---|---|---|---|
| **K** | Préfixe authentique, entrée signée canonique, loi et code épinglés, temps transmis | Verdict, raison stable, delta exhaustif, obligations, autorisation d'effet bornée en données | Juger | Lire une horloge ambiante, le réseau, un fournisseur, un secret ou un agent ; exécuter ; contenir de l'IA |
| **T** | Décisions de K, signatures, mesures, réponses fournisseurs | Prémisses qualifiées, commit ancré, effet parti ou `UNKNOWN`, reçus | Attester, ancrer, garder les secrets, faire partir l'effet jugé | Décider `allowed` |
| **U** | Loi effective projetée, tâches, état du dépôt | Propositions signées, WorkItems, diagnostics, patches | Travailler sous capacités bornées | Définir la loi, détenir un credential privilégié, fabriquer une preuve, fermer une dette |
| **Surface** | Vues de K et U | Décisions humaines signées | Montrer, solliciter | Masquer un `FAULT` ou un trou de couverture ; présenter `IDLE` comme une certification |

**TCB effective = K + T.** U et la Surface sont hors TCB : sous les prémisses physiques qualifiées, leur défaillance ne peut pas admettre un effet interdit. U garde néanmoins des risques propres avant l'admission (lecture de données, egress, consommation de ressources, qualité des propositions) ; ses exécutions candidates doivent être confinées et ses impasses mesurées.

Le silo **U** est le seul qui ne soit pas précisément délimité : c'est un chantier de **couverture**, pas de précision. Tous les autres silos ont des frontières exactes.

### 5.2 Règle d'appartenance

Un composant appartient à T (et à la TCB effective) dès qu'il :

- atteste une observation que K utilise pour accorder un droit ou fermer une obligation de sûreté ;
- détient un secret privilégié ou un credential d'écriture ;
- fait partir un effet ;
- conserve le journal, une épingle ou une ancre.

Un scanner, un adaptateur ou un outil déjà présent dans l'entreprise suit le même critère, même s'il s'appelle « adaptateur » et même si son code est hors du dépôt. Son coût, son installation et ses modes de défaillance sont inventoriés séparément.

### 5.3 Inventaire de confiance, sans plafond de lignes

Les responsabilités restent classées par ce qu'une défaillance peut casser ; aucun plafond de lignes ne bloque le développement.

| Responsabilité | Code | Impact d'une défaillance |
|---|---|---|
| Sûreté logique | `kernel/`, déclarations de release `catalog/floors.py` | Admission d'un effet, élargissement ou réécriture interdits |
| Frontière physique | `bt/` hors second juge, assemblage privilégié `runtime/` | Mauvaise prémisse, mauvais départ, perte du préfixe ou de sa preuve |
| Contrôle restrictif indépendant | `bt/checker.py` | Peut arrêter ; ne peut admettre ce que K refuse |
| Visibilité déterministe | `kernel/accountability.py` | Peut masquer ou inventer un écart ; n'admet ni n'exécute |
| Calcul des mesures | `instruments/` | Un programme erroné peut produire un fait erroné ; le rejeu seul ne prouve pas sa justesse |

`make layers` vérifie les imports, la séparation du second juge et l'absence d'import de modules d'effets physiques dans K. Il affiche le volume de code à titre informatif. Ce contrôle statique ne prouve ni l'isolation réelle ni l'absence de chemins dynamiques.

L'empreinte du socle couvre K et BT. L'empreinte d'une installation du produit couvre **aussi** `catalog/`, `catalog/floors.py` et tout `runtime/` : déplacer l'opérateur hors de BT ne retire ni ses privilèges ni sa responsabilité de confiance. Les programmes restent liés par leur méthode épinglée dans les floors.

Un ajout de mesure utilise un programme et un contrat ; un ajout de fournisseur utilise un adaptateur qualifié. Aucun déplacement, renommage ou compactage ne compte comme réduction de confiance. Les plafonds numériques et leur fichier de budget ont été retirés par D39 ; les bornes constitutionnelles (temps, taille d'entrée, nombre de faits, profondeur de chaîne) restent inchangées.

---

## 6. Le noyau (K)

### 6.1 Contrat d'évaluation

`decide(préfixe, entrée_signée) → (verdict, raison, delta, obligations, autorisation_d_effet?)`

- **Entrée** : état canonique pré-transition, constitution et code épinglés, proposition authentifiée, assertions externes **qualifiées par T**, temps transmis.
- **Sortie** : verdict déterministe parmi `ACCEPT | REJECT | PENDING_EXTERNAL | ESCALATION_DUE`, raison stable (`MÉCANISME.RAISON`), delta complet, obligations créées/maintenues/fermées, et le cas échéant une autorisation bornée **en données**, jamais une exécution.
- `PENDING_EXTERNAL` signifie qu'une attestation ou un contrat T manque. Ce n'est **jamais** une permission implicite.
- **Déterminisme** : mêmes octets + même préfixe + mêmes hypothèses temporelles → même verdict, même delta.
- **Totalité** : toute entrée admissible a un verdict ; toute entrée malformée, ambiguë, non canonique (flottants, `-0`, clés dupliquées, surrogates) est refusée.
- **Pureté** : aucun effet de bord, aucune lecture d'horloge ambiante, de réseau, de fournisseur, de secret ou d'agent.
- `Kernel.commit` rejoue les octets signés et refuse toute divergence, tout delta incomplet ou additionnel et tout préfixe périmé. Seul le journal (T04) réalise le commit durable, après contrôle indépendant (T05) et rétention de l'épingle.

### 6.2 Contrats logiques

Responsabilités, pas modules imposés. Elles peuvent être regroupées en un code court ; aucune ne peut être supprimée.

| | Responsabilité | Refus essentiel |
|---|---|---|
| **K01** Modèle canonique | Formes fermées, identités stables, encodage unique et versionné, aucune donnée métier privilégiée | Forme ambiguë, champ caché, flottant, deux sens pour un même digest |
| **K02** Identité | Signature liée au domaine, à la déclaration, à la ressource, au type, à la version et au préfixe exacts. Une clé n'a qu'un encodage canonique [V6-9]. Enveloppe fermée, une signature par clé, triée [V6-env] | Réutilisation cross-domaine, cross-époque, cross-ressource ; même clé enrôlée deux fois |
| **K03** Autorité | Atténuation monotone, aucun privilège par défaut, révocation et gel immédiats au préfixe, élargissement signé par l'unique humain de la racine | Un acteur se donne une capacité ; un second humain enrôlé |
| **K04** Constitution | Composition non affaiblissante ; changements de racine, dégel et droits par procédure ; genèse et récupération sans exception souveraine | Clause client qui affaiblit un floor |
| **K05** État et transition | Fonction pure unique ; préconditions, delta requis **et** interdit, conflits sérialisés, aucune mutation non déclarée | Deux writers divergents ; delta « permis » mais incomplet |
| **K06** Recevabilité des preuves | Sujet exact, méthode, couverture, fraîcheur, source, indépendance, invalidation. Signature ≠ vérité. Le silence n'est jamais `healthy` | Mesure signée mensongère ; périmètre non couvert ; auto-attestation |
| **K07** Obligations | Une dette stable par exigence × sujet × épisode ; tentatives et WorkItems ne touchent pas l'échéance ; retrait ≠ réparation ; clôture sur preuve admissible | Huit retries créent huit dates ; un renommage masque l'écart |
| **K08** Intention d'effet | Destination, payload, transformation, préconditions, auteur, fenêtre, réconciliation ; re-jugement au départ ; aucune exécution | Même opération avec d'autres arguments ; capacité révoquée avant départ |
| **K09** Escalade | Condition constitutionnelle d'escalade, indépendante de tout scheduler. Une tentative échouée ne ferme rien | Échéance dépassée et obligation faussement close |
| **K10** Jugement | **Un seul** chemin sémantique combinant K01–K09 ; trace rejouable | Divergence entre sous-moteurs ; fallback `allowed=true` ; résultat dépendant d'un ordre arbitraire |

### 6.3 Forme du noyau : hybride relationnel à jugement unique

**Décision D01 (§18).** Relations typées, contraintes positives bornées et transitions à delta exhaustif partagent **une seule** sémantique et **un seul** jugement. Le modèle de données est extensible ; la sémantique des primitives constitutionnelles est fermée, versionnée et non redéfinissable par un adaptateur.

Pourquoi : les trois candidats de la campagne V ont chacun un risque connu.

| Candidat | Risque |
|---|---|
| A — transitions seules | Preuves et obligations temporelles couplées au catalogue de transitions |
| B — contraintes seules | Vérifier « rien d'interdit » manque un delta **requis** et laisse des obligations sans propriétaire |
| C — composition hybride | Divergence d'ordre et de sémantique si plusieurs moteurs |

La forme retenue prend C **avec un seul moteur** : les contraintes portent sur le delta exhaustif d'une transition, dans la même fonction. Toute optimisation incrémentale doit être prouvée équivalente au jugement complet (différentiel, §21).

### 6.4 Séparation interne : le noyau ne se fait pas confiance

- **Second juge (T05, responsabilité restrictive seule).** Il ne juge qu'après une admission du noyau, sur un **instantané des déclarations épinglées** de la loi, jamais sur les champs compilés du premier juge [V6-§3.6]. Il **n'appelle pas** le noyau, son évaluateur ni ses structures pour obtenir son verdict. Il recalcule l'effet canonique exact, et les deux octets sont comparés avant le port [V6-§3.5]. Ses gestionnaires sont appelés par une table explicite limitée aux genres du noyau [V6-8].
- **Désaccord** : arrêt persistant de la frontière touchée. L'arrêt est local et n'est pas une mutation non signée du journal (F0-2).
- **Matrice de couverture** : pour chaque règle critique, elle distingue calcul indépendant, dépendance commune et règle à juge unique (profil prudent, flags, expirations, destination physique inclus). La tolérance à une faute est promise **uniquement** dans cette matrice. Aucun « un bug seul ne suffit pas » universel n'est revendiqué.
- **Dépendances communes déclarées** : spécification, parsing canonique, cryptographie, runtime, état réduit, stockage, OS.
- **Différentiel** : `tests/test_differential.py` rejoue des historiques aléatoires (graine fixe, 12 en `make check`, 200 en CI) à travers les deux juges : toute entrée admise par le noyau doit passer le second juge inchangée, et chaque delta altéré après admission (opération retirée, valeur changée, écriture ajoutée) doit être refusé [V6-causes-4, D47]. C'est une campagne bornée, pas une preuve d'équivalence.
- **Composition recontrôlée** : le second juge vérifie lui-même que la loi effective contient chaque floor de la release, lié aux identités du client et seulement durci (G03 sur deux juges, D47). Il restate aussi `HIST.AHEAD`, `retry_of` et les `when` des obligations de niveau `refuse`.
- **Isolation physique** : K/T tournent dans un processus opérateur distinct de U, avec comptes OS distincts. Le démarrage vérifie le manifeste de code **avant import et avant tout accès aux secrets** ; le bytecode est ignoré [R04].

### 6.5 Langage d'implémentation

Python pour l'instant (**D02**). Le choix final (Python, Rust, SPARK) se fera sur trois critères : sûreté, performance, fiabilité. Un changement de langage passe par le différentiel de §21.

---

## 7. Les cinq contrats transversaux

Les constats de la revue V7/M2 se ramènent à **six pertes de sens** entre objets. Chacune est portée par un contrat.

| Cause | Perte de sens | Contrat |
|---|---|---|
| Transition incomplète | Modification permise confondue avec modification exigée | Transition |
| Temps implicite | Date d'entrée confondue avec horizon actuel d'action | Temps |
| Preuve aplatie | Statut confondu avec preuve d'un sujet sous une méthode | Preuve |
| Effet incomplet | Nom d'opération confondu avec destination et conséquence exactes | Effet |
| Frontière physique implicite | Vérification logique confondue avec contrôle des credentials et de la persistance | Effet + déploiement |
| Travail fragmenté | Effets, écarts et plans séparés confondus avec un cycle complet | Obligation |

La frontière physique n'est pas un langage métier : c'est la condition d'exécution des contrats. Sans elle, le système peut proposer mais ne revendique pas le contrôle des effets.

### 7.1 Transition

Une transition lie une entrée signée, un préfixe, la loi en vigueur et un état résultant exact.

| Élément | Sens |
|---|---|
| Préconditions | Identités, signatures, polarité, sujet existant, autorité, temps, état antérieur |
| Delta obligatoire | Modifications requises, avec nombre, clé et valeur |
| Delta interdit | Toute autre modification, y compris doublon ou écrasement non prévu |
| Conséquences | Obligations ouvertes/consommées, état de la ligne d'effet |

Exemple `freeze` : pour `id=F`, `scope=S`, le delta est **exactement** `frozen[S] = F` plus l'enregistrement historique. Un delta vide, un autre scope, une autre valeur ou deux écritures sont refusés. Le dégel nomme l'occurrence F ; un gel ultérieur de S invalide ce dégel proposé. L'activation supprime obligatoirement la proposition.

Les déclarations OBL de la loi ajoutent leur propre delta, vérifié exhaustivement ; elles ne peuvent pas modifier les tables d'autorité.

### 7.2 Temps

| Temps | Origine | Usage autorisé |
|---|---|---|
| `statement_at` | Entrée signée admise | Ordre historique, relecture déterministe |
| `anchor_at` | Un témoin sur un préfixe exact | Borne d'admission |
| `evaluated_at` | Horloge de la frontière d'exécution | Expiration actuelle des droits et des preuves |

- L'horloge d'exécution est une dépendance de confiance explicite (T03) : source, précision, protection contre le recul, domaine de panne. Une valeur fournie par un agent ne suffit jamais.
- L'exécuteur vérifie à l'horizon **actuel** capacités, preuves, restrictions, profils et fenêtre de départ. Il ne remplace jamais l'heure actuelle par `min(now, anchor + allowance)` pour obtenir une admission [R03].
- Hors de l'horizon attesté : aucun départ. La projection ouvre `renew-time`, adressée aux témoins, avec ouverture et échéance stables. Un checkpoint au préfixe courant permet une nouvelle évaluation sans renouveler les grants.
- Un humain signe uniquement sa revue ou son attestation avec **sa** clé ; il ne reçoit jamais les clés des témoins [R11]. Sous une ancre périmée, sa demande attend le renouvellement.
- Un reçu qui revient après la fenêtre est conservé durablement, lié à la réservation, sans devenir une clôture. Après renouvellement, l'entrée distingue temps du départ, du reçu et de l'admission.
- Une restriction peut partager le dernier instant (F0-6) : aucune borne haute ne peut affamer les gels [V6-5].
- **Séparation** : avancer l'horizon d'évaluation peut expirer une autorité ou ouvrir un écart ; cela ne change pas le préfixe et ne crée aucun droit.

### 7.3 Preuve

Une preuve est une affirmation limitée, structurée, attribuée.

| Champ | Contrat minimal |
|---|---|
| Sujet | Identifiant exact ; snapshot immuable ; digest des entrées pertinentes |
| Exigence | Identifiant et digest du contrat applicable dans la loi nommée |
| Affirmation | Propriété précise, résultat, et limites de ce que le résultat signifie |
| Méthode | Identité et version de l'outil, configuration, définition **protégée** des checks |
| Couverture | Univers déclaré, éléments couverts, exclusions et raisons, identités vérifiables |
| Rapport | Digest d'un rapport conservé et accessible (stockage par contenu) |
| Validité | Collecte, expiration, événements invalidants définis par l'exigence |
| Provenance | Identité, chaîne de détenteurs, signatures, dépendances connues |

**Relation de qualification :**
`qualifies(preuve, exigence, sujet_exact, méthode, couverture, provenance, evaluated_at)`.

Règles :

- Une signature prouve l'attribution, pas la vérité. Un digest prouve le lien aux octets, pas le sens [L-01].
- L'univers à couvrir est défini **indépendamment** du filtre de l'instrument. Un fichier exclu par incapacité de la méthode (NUL, trop grand) ouvre `restore-coverage` ; ce n'est jamais une couverture complète silencieuse [R12]. Une exclusion autorisée par l'exigence est différente d'une incapacité.
- Le collecteur fige **un** snapshot avant les mesures ; des sondes sur des commits différents ne font pas une preuve commune [R07].
- **CI** : le sujet nomme tête **et** base testées, configuration des checks, workflow, événement et tentative. Une tentative récente en attente empêche une ancienne réussite de servir de preuve [R05]. Tester la tête seule ne prouve rien sur une base qui a changé.
- **Dépendances** : distinguer déclarations directes, lock résolu, fermeture transitive et environnement ciblé. Un fichier de pins ne prouve pas la fermeture [R13].
- **Licences** : sur versions et artefacts exacts, selon une politique d'expressions épinglée. Jamais par présence d'une sous-chaîne (`MIT`) [R14].
- **L'instrument n'est pas contrôlé par le sujet** : la configuration de la CI, de pytest, les `# nosec`, les octets du dépôt mesuré ne pilotent pas la mesure [M2-r2].
- Les faits produits en exécutant le code du sujet (`tests`) sont **nécessaires, jamais suffisants** : ce code peut mentir sur lui-même.
- Une sonde ne répond pas « OK faute d'erreur » [M2-r1].
- Les rapports volumineux vivent hors du journal par adresse de contenu ; leur disparition invalide la qualification.
- **Deux clôtures distinctes** : la preuve d'**application** résout l'incertitude d'une réservation ; une preuve qualifiée de l'**état résultant** résout l'écart de l'exigence. Une PR fusionnée peut laisser la vulnérabilité présente.
- **Conformité** : relation contrôlée clause ↔ affirmation. Une attestation « procédure à jour » ne prouve pas une notification faite dans le délai [R18]. Sorties : `satisfied`, `missing`, `partial`, `not_applicable` gouverné, `fault`. Une clause satisfaite n'est pas une certification.
- Une invalidation par un humain habilité ou par la source retire immédiatement la recevabilité.

### 7.4 Effet

L'effet désigne une conséquence exacte, indépendante du fournisseur.

| Élément | Contenu |
|---|---|
| Destination | Fournisseur, compte/tenant, ressource, opération, paramètres exacts |
| Sujet et préconditions | Snapshot source, base, diff, checks, politique de scope, invalidations |
| Autorité | Capacité, contrat d'opération, profil humain, restrictions actuelles |
| Sortie de données | Destinataire, classes de données, périmètre, digest du contenu autorisé |
| Reprise | Clé de réservation, déduplication, méthode de réconciliation, preuves recevables |

- **Sont des effets** : créer un commit, une branche, une ref ou une PR ; écrire une config ; **envoyer du contexte à un modèle externe** (sortie de données). La fusion n'est pas la seule frontière [M2-r1, R15].
- Plusieurs requêtes fournisseur pour une proposition forment des étapes identifiées ; une reprise ne les recommence pas en bloc.
- **Scope sémantique** : une capacité autonome de dépendances porte sur la transformation (paquets, versions, sources, hashes, fermeture), pas sur une liste de chemins. Modifier le backend de build ou les checks dans un fichier autorisé exige une autre autorité [R06].
- **Secrets** : le modèle ne reçoit qu'un contexte autorisé et expurgé. Si la classification ou l'expurgation échoue, la sortie est refusée et le travail part vers une méthode locale ou un humain. Découvrir un secret n'accorde jamais le droit de l'envoyer [R15].
- L'agent n'écrit jamais dans `.git/` ni hors des chemins de sortie autorisés ; pas de liens symboliques suivis [M2-r1].

### 7.5 Obligation

Voir §9 pour le cycle complet.

| Élément | Sémantique |
|---|---|
| Identité stable | Exigence/propriété × sujet ou périmètre stable × contrat applicable × génération d'écart. Suit `(ressource, propriété)`, pas le nom de la cible [V6-6] |
| Cause | `observe`, `repair`, `restore-coverage`, `renew-time`, `reconcile`, `prove`, `restore-integrity`, `restore-route` |
| Horodatage | Première ouverture et échéance du manque continu, conservées pendant les relances |
| Route | Rôle, opération, méthode, capacité requise, disponibilité constatée |
| Satisfaction | Relation de preuve explicitement requise |
| Historique | Tentatives, reçus, invalidations, escalades, motif de sortie |

---

## 8. La ligne d'effet

### 8.1 Automate unique

Un seul automate dans FLOOR-0, lu par les deux juges. `(genre, résultat) → (états de départ admis, état d'arrivée)` :

| Entrée | Depuis | Vers |
|---|---|---|
| `intent` | — | `intended` |
| `token` | `intended` | `tokened` |
| `reservation` | `tokened` | `reserved` |
| `execution: ok` | `reserved`, `expired` | `proving` |
| `execution: failed` | `reserved`, `expired` | `failed` |
| `execution: unknown` | `reserved`, `expired` | `uncertain` |
| `reconciliation: applied` | `uncertain`, `expired` | `proving` |
| `reconciliation: not_applied` | `uncertain`, `expired` | `failed` |

- `expired` = réservation au-delà de `DISPATCH_MS`. Plus aucune garde ne peut l'envoyer ; **alors seulement** un réconciliateur peut la régler. Cela ferme la double exécution [V6-1].
- Les étapes avant tout effet (`pending`, `unredeemed`) expirent par le temps. **Après une réservation, rien n'expire.**

### 8.2 Départ

1. La garde écrit une réservation **signée, durable, épinglée**. Une réservation consommée ne peut pas être reprise, même après un crash. Aucun enregistrement non signé ne sert d'autorité.
2. Sous le verrou d'écriture, noyau et second juge **re-jugent** autorité, restrictions, conditions, profil humain et fenêtre de départ. Chacun produit l'effet exact ; un désaccord d'octets = arrêt persistant.
3. L'**envoi** à l'adaptateur a lieu **avant** la libération du verrou. Seule l'**attente** de la réponse peut se faire hors verrou, et elle ne peut contractuellement lancer aucun autre effet [V6-§3.4].
4. Une restriction admise avant l'envoi bloque l'effet. Après l'envoi, elle ne le rappelle pas.
5. Toute exception après entrée dans l'adaptateur, y compris pendant l'attente, est `unknown`. Le même jeton ne peut pas être retenté.
6. L'entrée candidate exacte est conservée **avant** l'épingle ; la reprise restaure la queue sans candidat perdu [V6-10].
7. Un contrat T manquant ou une restriction au dernier contrôle : **rien n'est envoyé**, et la garde rapporte `failed`, qu'elle sait avec certitude puisqu'aucun adaptateur n'a été appelé. Une fois l'adaptateur appelé, toute erreur devient `unknown`.

### 8.3 Réconciliation

| Issue | Preuve exigée | Suite |
|---|---|---|
| `applied` | Conséquence constatée sur la destination et le sujet exacts | Qualifier l'exigence (§7.3, deux clôtures) |
| `not_applied` | Absence **définitive** de l'effet de cette réservation, aucune demande encore susceptible d'aboutir | Examen d'une nouvelle tentative sous nouvelle autorisation |
| `indeterminate` | Information insuffisante, incohérente, ou appel encore susceptible d'aboutir | Réconciliation conservée ; répétition bloquée |

- Un timeout ferme le droit de départ local ; il ne supprime pas une demande déjà transmise.
- Une PR ouverte, un silence ou un commentaire ne prouvent pas une non-application.
- Une intervention humaine ne fabrique pas une preuve de non-application ; une dérogation au risque est un nouveau contrat gouverné.

### 8.4 Reprise de chaque état

| Situation | Travail dérivé | Droit de répéter |
|---|---|---|
| Preuve absente ou périmée | Observer le sujet actuel | Aucun |
| Couverture insuffisante | `restore-coverage` | Aucun |
| Intention sans token, délai passé | Abandon sans départ ; nouvelle intention sur faits frais | Sous nouvelle autorisation |
| Token sans réservation, délai passé | Idem ; l'ancien token est inutilisable [R10] | Sous nouvelle autorisation |
| Réservation dans sa fenêtre | Attendre le départ déjà engagé | Non |
| Réservation expirée ou réponse inconnue | `reconcile` | Non, jusqu'à preuve définitive |
| Effet appliqué | Preuve de résultat puis qualification de l'exigence | Pas pour la même incertitude |
| Non-application définitive | Réobserver, proposer à nouveau | Sous nouvelle autorisation |
| Route sans acteur, capacité ou adaptateur | `restore-route`, adressé au propriétaire | Aucun départ de secours |
| Intégrité ou auditeur en panne | `fault`, restaurer la frontière | Aucun droit issu du rapport |

### 8.5 Exécuteur minimal

- Agents et planificateurs ne possèdent **aucun** credential d'effet gouverné. Un exécuteur distinct les détient et ne reçoit que des requêtes canoniques. Une séparation par objet Python dans un même processus n'est pas une isolation.
- Credentials limités par opération et destination. Une configuration fournisseur qui laisse une autre voie d'écriture invalide la revendication de contrôle exclusif (G15).
- Démarrage par une entrée vérifiée **avant import et accès aux secrets**, depuis une installation immuable approuvée de l'extérieur. Le manifeste couvre les adaptateurs et tout code capable de contourner le port.
- Le journal survit au job. Les épingles survivent dans un domaine de restauration indépendant. L'acquittement de la réservation précède le départ. Les exports Git sont des copies de lecture [R08].
- Un verrou local ne couvre pas deux exécuteurs : **un seul writer** (D06).

### 8.6 Limites fournisseur

- Si le fournisseur ne peut pas appliquer atomiquement destination, base et préconditions, un GET puis PUT ne suffit pas ; une seconde lecture ne ferme pas la course. L'adaptateur emploie une primitive adéquate ou déclare l'opération **inexécutable** [R09].
- **GitHub** (D05) : fast-forward de `main` de `base` vers son enfant direct `head` via `updateRefs` avec `beforeOid=base`, `afterOid=head`, `force=false`. `main == head` → `ok` ; base différente avant envoi → `failed` ; réponse incertaine → `unknown`. Un commentaire contenant une clé n'établit pas l'idempotence.
- Une tentative locale unique ne garantit pas un effet distant unique sans déduplication honorée par le fournisseur.

---

## 9. Obligations et cycle de maintenance

### 9.1 Boucle

```
Exigence + sujet ──► Qualification des preuves
                         │ insuffisant            │ suffisant
                         ▼                        ▼
                 Obligation persistante    Satisfaction au préfixe nommé
                         │                        │ expiration / invalidation
                         ▼                        └──────────► Obligation
                  Travail proposé (U)
                         ▼
                 Autorité + effet exact (K)
                         ▼
              Réservation puis exécution (T) ── indéterminé ──► Obligation (reconcile)
                         ▼
                  Résultat attesté (T06) ──► Qualification des preuves
```

Un effet réussi ne satisfait **jamais** automatiquement l'exigence qui l'a motivé.

### 9.2 Continuité de la dette (G08)

- **Même écart** = même `(exigence, ressource, propriété)` tant que le manque est continu, à travers noms, versions, commits et tentatives. Démontré sur 8 cycles malgré 1 → 4 propositions (campagne IV-H) ; le renommage et le rollback restent à éprouver.
- Un changement de commit ne repousse pas l'échéance ; la preuve doit porter sur le nouveau snapshot.
- Un changement gouverné de contrat conserve la dette si le manque subsiste ; il ne réutilise pas une ancienne preuve.
- Une nouvelle déclaration ne peut pas repousser une échéance déjà ouverte.
- L'expiration d'une preuve instrumentée utilise la plus courte fraîcheur applicable.
- `debt` est une **projection déterministe** de responsabilité, jamais un second chemin d'autorisation.

### 9.3 Escalade et progrès (G16)

- K juge devoirs, permissions, échéances et **exigibilité** de l'escalade. Une tentative échouée n'est jamais une clôture.
- U réalise ordonnancement, retries, backoff. Les escalades sont visibles dans la console (D61 : plus de T09).
- **Propriété de progrès conditionnel** : si les sources externes requises restent disponibles, si une action permise existe et si l'ordonnancement est équitable, le système réalise une transition observable **ou** produit une escalade explicite dans une borne définie.
- Observé en campagne IV : périodes sans action, reprise après 25 h, 21 lignes ouvertes sans escalade pendant la fenêtre. Ces cas sont des défauts d'implémentation U/T, pas des raisons de mettre un scheduler dans K.

### 9.4 États visibles

- Normaux : `PROVEN`, `IN_PROGRESS`, `ESCALATED`. Quatrième résultat : `FAULT`.
- `PROVEN` porte sur les cibles déclarées, au préfixe et à l'horizon nommés.
- Une vue `FAULT` contient toujours : préfixe connu ou explicitement inconnu, horizon demandé, frontière en échec, informations encore fiables. Les consommateurs ne présument aucun autre champ [R16].
- Les rapports sont produits même après l'échec d'un rôle, par une voie de lecture indépendante. Une panne du rapport est elle-même observable.
- Un audit dépassé est refusé par défaut ; un audit historique est demandé explicitement et étiqueté `current: false`.
- **Toutes les vues** (maintenance, opérations, conformité, Surface) lisent la **même** projection issue de la loi effective, cibles client comprises. Elles priorisent différemment ; elles ne définissent pas différemment ce qui est résolu [R17].

---

## 10. La frontière de confiance (T)

Huit **responsabilités**, regroupables. Ce ne sont ni huit services ni une attestation globale obligatoire. Une opération ne requiert que les T dont elle dépend :

| Opération | T requis |
|---|---|
| Préfixe et restrictions signées | T01, T02, T04, T05 |
| Opération temporelle | + T03 |
| Observation, mesure, preuve | + T06 |
| Réconciliation | + T08 |
| Effet et garde | + T07, T08 |

Une panne T03 n'empêche pas un gel ou une révocation signés. Aucune opération dépendante ne progresse sans son contrat. Les contrôles sont répétés sous le verrou juste avant le départ physique.

| | Port | Règle | Test de falsification | Condition physique |
|---|---|---|---|---|
| **T01** Release / runtime | `verify_release(runtime, genesis, law)` | Installer et ancrer hors de l'agent ; aucun downgrade, aucune genèse discrète | Binaire substitué ; genèse réinitialisée | Installation authentique |
| **T02** Clés / identité physique | `authenticate(statement, roles)` | Custody exclusive ; liaison physique documentée | Une clé humaine copiée sur l'hôte de l'opérateur | La clé de l'humain sur ses seuls appareils |
| **T03** Temps | `attest_time(event, uncertainty)` | Horloge de l'opérateur signée par `clock`, refus du recul | Faux futur accordant un droit | Horloge de l'opérateur juste |
| **T04** Préfixe durable | `commit(expected_head, delta)` | Append-only, CAS atomique, ancre hors du domaine de restauration | Rollback journal + pin ; crash entre pin et commit | Domaines de restauration indépendants |
| **T05** Vérification indépendante | `check(inputs, decision, delta)` | Implémentation et domaine de panne distincts ; désaccord bloquant | Deux copies identiques acceptent le même bug | Domaine de panne réellement distinct |
| **T06** Instruments | `attest_measurement(subject, method, coverage)` | Source et périmètre instrumentés, indépendants du bénéficiaire | Monde réel faux avec payload signé identique | Vérité et couverture réellement mesurées |
| **T07** Garde des effets | `reserve_and_dispatch(effect, authority)` | Credentials et egress exclusifs, départ sérialisé, comparaison d'octets | Secret CI secondaire qui déploie sans garde | Aucun chemin privilégié parallèle |
| **T08** Readback | `reconcile(reservation, provider_state)` | `applied / not_applied / unknown` sans déduction abusive ; idempotence prouvée avant retry | ACK perdu après application ; double action | Idempotence fournisseur, readback indépendant |

**Déclaration de déploiement.** Pour chaque T : fournisseur, trust domain, possession des clés, droits de restauration, chemins réseau, dépendances communes, protocole de panne, test réel. Des services distincts sous un même administrateur ne sont pas indépendants. La qualification est liée à une release, une genèse, une installation et une route.

**Réalisation dans le prototype.**

| T | Où | Ce qui est tenu |
|---|---|---|
| T04, T05 | `bt/journal.py`, `bt/checker.py` | Journal SQLite append-only, pins sur un autre volume ; second juge qui reformule chaque admission |
| T06 | `bt/isolation.py`, `bt/host.py` | Les programmes épinglés tournent sous `standard-runner` (sudo limité à `/usr/bin/env`), environnement vide, `unshare -rn` (aucun réseau), `prlimit` mémoire. **Échec fermé (D46) :** sans `runner_user`, aucun code candidat ne tourne ; seule une démo peut l'accepter explicitement (`[tests] unconfined = true`, refusé hors `demo`), et `qualify.py` le signale. **Frontière incomplète :** les suites et l'installation des dépendances candidates ne sont pas confinées côté système de fichiers ; l'hôte refuse donc les jobs candidats avant leur exécution et la sonde T06 échoue. Le précontrôle U possède un jail distinct, qui ne répare pas T06. |
| T06, T07, T08 | `bt/transactions.py`, `host.py`, `register.py`, `adapters.py`,  `guard.py` ; `instruments/` et `tools/replay.py` hors T | Toute entrée et toute sortie sont des **transactions de frontière** (§10.1) |

### 10.1 Transactions de frontière (D38)

**K juge. T garantit la frontière. U accomplit le travail.** Toute affirmation qui entre et tout effet qui sort passent par une **transaction de frontière** (BT), sous un contrat que les floors déclarent (`catalog.floors.CONTRACTS`). Une BT ne remplace aucun contrat T01–T08 : elle unifie leur représentation. Elle n'est pas une transaction ACID et n'ajoute aucune sémantique constitutionnelle : CAP, OBL, NIV, PROV, TYPE et HIST restent au noyau.

Une BT est un enregistrement, gardé par empreinte dans le magasin de preuves et listé dans `transactions.jsonl` :

| Propriété | Contenu |
|---|---|
| Identité | qui : le scanner, la garde, l'oracle ; jamais un agent |
| Sujet | quoi exactement : un job et les ressources dont il a parlé, ou la ressource jugée |
| Autorité | sous quoi : le contrat, la capacité, la clé de réservation |
| Contrat | comment c'est justifié : `reproducible`, `attested`, `composite` (observation) ; `cas`, `observable` (effet) |
| Matériel | ce qui a été lu ou envoyé, par empreinte : l'enregistrement d'exécution, la requête canonique, ce qui a été relu |
| Causalité | la genèse, la tête du journal et la loi au moment de la transaction, et les transactions auxquelles elle répond |
| Issue | `established` / `refused` ; `ok` / `failed` / `unknown` ; `applied` / `not_applied` / `unknown` |

**OBSERVE — faire entrer une affirmation.** L'hôte exécute un job des programmes épinglés sur des entrées identifiées par empreinte, sous l'exécutant isolé. Seul ce que le **contrat du job** l'autorise à dire est signé (propriétés et préfixes de ressources) ; le reste est refusé, enregistré, jamais signé. Une propriété réservée au scanner est signée comme mesure dont la méthode nomme le contrat : `programs@<empreinte>/suite`. Le noyau n'admet `tests` que de la méthode `…/suite` : **un programme de production compromis ne peut pas signer un fait de test** (test adversarial, critère D). Trois formes de justification :

| Contrat | Jobs | Forme | Ce qu'il peut dire | Ce sur quoi il repose |
|---|---|---|---|---|
| `floors` | sondes des floors | composite | les propriétés des cibles techniques et de réglage, sur `repo:` | l'instantané de données tierces épinglé (D17), les réglages de main que donne le fournisseur |
| `suite` | réparation, règles, demande implémentée, contribution | reproductible | `tests`, `regressions`, `reproduced`, `acceptance`, `configured` | rien d'autre que les entrées identifiées |
| `request` | contrat d'une demande | reproductible | `contract`, `accepted` sur `build:request/` | idem |
| `production` | production | composite | couverture, `slo`, `lag`, ce qui est sur chaque bascule, les nombres (D36), sur `run:` | les métriques du produit (sa propre parole), les mesures du lanceur, les réponses des sondes |
| `capture` | (l'hôte) | attestée | rien de signé : les octets que chaque source a renvoyés, datés | la source à ce moment-là |

Le rejeu (`tools/replay.py`, sonde `qualify`) prouve la reproductibilité d'une mesure, pas la justesse du programme ; une signature prouve une attribution, pas la vérité physique. Une forme `composite` vaut sa source la plus faible, et la BT la nomme.

**EFFECT — faire sortir un effet.** U prépare l'intention exacte, K la juge, la garde réserve, re-juge avec les deux juges et part une fois sous le verrou (ligne d'effet de FLOOR-0 inchangée). Le port de la garde n'atteint qu'un adaptateur dont le **profil physique** est celui que le contrat de l'opération exige ; sinon la route est non qualifiée et rien ne part (`failed:unqualified`, enregistré).

| Profil | Garantie | Opérations |
|---|---|---|
| `cas` | compare-and-swap sur l'état lui-même : l'adaptateur s'exécute jusqu'au bout ; l'état relu décide | `remediate`, `integrate`, `implement`, `configure` (main) ; `deploy`, `rollback`, `canary`, `abort` (registres) |
| `observable` | seule une demande part ; l'effet est établi par une observation ultérieure | `restart` (le lanceur redémarre ; un nouveau processus de cette version, démarré après la demande, l'établit) |

Un redémarrage n'est pas un compare-and-swap parce qu'on l'écrit dans un registre : le registre ne fait que demander. Les profils « commande idempotente » et « action irréversible » ne sont pas encore utilisés ; une opération qui les exigerait n'a pas de route tant qu'aucun adaptateur ne les tient.

**RESOLVE — établir les conséquences.** Après un effet incertain ou expiré, l'oracle relit, par profil :

- `cas` : `applied` quand l'état montre le mouvement de cette clé ; `not_applied` quand il ne s'est pas produit et qu'aucune demande ne peut encore aboutir (git local : main ne contient pas la tête, et main n'avance que par le CAS de la garde ; registres : la clé n'est jamais entrée dans l'historique, écrit avant le mouvement). Sur GitHub, une requête distante peut encore aboutir après une réponse perdue : jamais `not_applied`.
- `observable` : `applied` seulement quand l'observation le montre ; **jamais `not_applied` une fois la demande partie** ; `not_applied` seulement si la demande n'a jamais quitté la garde.
- Aucun délai, aucun ACK perdu, aucun silence ne prouve une non-application. Un `unknown` ne se relance pas.

Que l'effet soit appliqué n'est pas que son but soit atteint : la **preuve** reste une étape distincte (main contient la tête ; la version servie est celle basculée ; un nouveau processus tourne), signée par l'oracle.

**Composition.** Une livraison est une suite de BT liées par empreinte : OBSERVE (tests du commit exact, sous `suite`) → K admet `integrate` → EFFECT (`cas` sur main) → RESOLVE → OBSERVE (production : candidat, nombres) → K admet `deploy` → EFFECT (`cas` sur `current`) → RESOLVE → OBSERVE (version servie) → preuve → K ferme l'obligation. Chaque fait signé garde sa provenance : méthode (programmes et contrat) et artefact (la BT, qui nomme son exécution).

**Invariant de croissance.** Une nouvelle mesure réalisable par les primitives existantes ajoute un programme épinglé et un contrat, sans nouvelle sémantique dans K. Un nouveau fournisseur ajoute un adaptateur d'un profil existant, **toujours classé dans la confiance physique** : ce code n'est pas rendu neutre par son nom ou son dossier. Une empreinte ne rend pas un programme fiable : il est relu, épinglé par la release, exécuté isolé, rejoué. Trois choses sont inventoriées séparément : les sources de confiance (`make layers`, volume informatif sans plafond), les dépendances physiques extérieures (la colonne « ce sur quoi il repose »), les privilèges réels (sonde `qualify` « privileges around the guard »). Une dépendance reconnue sans code local reste dans la base de confiance effective.

**Limites.** Restent dans T et hors de portée du rejeu : l'honnêteté du relevé (l'hôte a reçu ces octets), l'exclusivité des effets (T07 : aucun autre chemin privilégié), la justesse des adaptateurs. Un programme épinglé faux produit un fait faux que le rejeu recalcule à l'identique. T09 (livraison) n'est pas encore une BT.

**Évaluation signée.** Une frontière (`TrustBoundary`) qualifie seulement les rôles utilisés par l'opération. Une évaluation Ed25519 signée lie release, genèse, journal et registre ; les clés de l'évaluateur sont épinglées par l'installation, hors de portée de l'agent. Sans temps fiable, une restriction peut être contrôlée à la date d'émission signée de l'évaluation ; cette voie ne peut jamais élargir. Une déclaration `VERIFIED` signée ne démontre pas la réalité physique.

---

## 11. L'autonomie (U)

### 11.1 Composants

| | Composant | Contrat | Interdit |
|---|---|---|---|
| U01 | Découverte | Inventorier dépôts, outils existants (CI, IAM, scanners, SRE), couverture ; proposer des observations. Catégories `PRESENT_UNQUALIFIED` ou `NOT_FOUND` | Déclarer une couverture complète sans T06 |
| U02 | Projection | Convertir la loi effective en objectifs observables, expliquer les écarts | Modifier la loi pour simplifier une cible |
| U03 | Work Engine | Créer, louer, reprendre, réessayer ; conserve tentatives, délais et échéance initiale à travers les redémarrages | Confondre WorkItem et obligation ; repousser une échéance |
| U04 | Agents | Claude via API : planifier, coder, tester, proposer sous capacités bornées | Détenir un secret privilégié ou une signature souveraine |
| U05 | Demandes | Produire un changement sous contrat accepté, avec le parcours commun des candidats | Modifier le contrat ou s’affranchir des contrôles |
| U06 | Obligations et observation | Observer, réparer un écart sous son échéance, avec le même parcours des candidats | Clore une dette sur un scan vert |
| U07 | Intégrations | Git, CI, cloud, IAM, SRE, exposés en modèles génériques | Autoriser une action, fabriquer un fait qualifié |
| U08 | Surface | Couverture, objectifs, risques, dettes, décisions, escalades | Traiter un risque non couvert comme sain |

**L'agent** (`python -m agent run`, un processus, une clé, une capacité) :

| Pièce | Fichier | Fait | Ne fait jamais |
|---|---|---|---|
| Lecture des coups | `context/moves.py` | Statut de chaque coup (`ready`, `decided`, `yours`, `measuring`, `refuted`, `frozen`, `playing`, `done`), route qui tient, file de l'humain | Décider : le noyau rejuge |
| Boucle | `agent/loop.py` | Joue les coups prêts ou décidés, une bascule par passe ; tactiques qui retiennent seulement | Choisir une route, un seuil, une capacité |
| Réparateur | `agent/repair.py` | Écrit des candidats pour les écarts des floors : recette reproductible ou modèle, précontrôle ; un candidat réfuté devient une leçon | Soumettre quoi que ce soit lui-même |
| Constructeur | `agent/build.py` | Implémente une demande contractée (`Standard-Request: <rid>`), livre quand main passe le contrat | Écrire sous `tests/`, `.github/`, `standard/` |
| Règles | `context/policy.py` | Schéma de chaque réglage, brouillon des nouvelles règles, valeurs effectives, socle | Signer : seul l'humain signe |

### 11.2 Routes

Chaque responsabilité de l'installation a une route vérifiable : **réutiliser, envelopper, compléter, créer, ou signaler l'impossibilité**. Une route décrit un sujet, un besoin, les cibles effectivement prises en charge et les T requis. BUILD/RUN ne filtre plus ces routes. États : `AVAILABLE`, `TRUST_BLOCKED`, `NO_ROUTE`, `HUMAN_REVIEW`. La route de réparation installée ne prétend plus traiter toutes les cibles `repo:*` : elle nomme celles du socle et les scopes clients configurés. En l’absence de moyen pour couvrir, observer, réparer ou prouver, la projection conserve le besoin original en `NO_ROUTE` et ajoute un travail `investigate` portant la même obligation, la même date d’ouverture et la même échéance. Ce travail est informatif ; il ne crée aucun droit ni ne ferme une dette. Les preuves d’application sur `intent:*` ont la route oracle, distincte des mesures scanner.

- Une route déclarée ne prouve pas son fournisseur. Une route non qualifiée reste inactive pour les opérations qui en dépendent, produit du **travail de qualification** distinct de la dette constitutionnelle, et n'empêche pas les restrictions immédiates.
- La présence d'un outil n'est ni une preuve de couverture ni une raison de le remplacer.

### 11.3 WorkItems

- Les tâches sont dérivées de la vue canonique ; elles gardent l’id et l’échéance de leur obligation. Leur état U ne remplace jamais une admission.
- Une mission identifie son origine : demande acceptée, obligation ou exploration. La file persistante suit les obligations ; les demandes gardent leur cycle contractuel et l’exploration reste consultative. BUILD/RUN sont des vues, pas des partitions de travail.
- Une tâche ne disparaît qu'après une nouvelle vue constitutionnelle où l'obligation n'est plus ouverte. `complete_attempt` libère seulement la tentative.
- La base opérationnelle (leases, tentatives) n'est ni le journal ni une ancre et ne confère aucun droit.
- Une proposition reste attachée à sa base et à son besoin. Les producteurs reprennent sur une nouvelle base, conservent les enseignements des refus et appliquent leurs budgets et backoffs configurés. Aucune tentative ne déplace l’échéance constitutionnelle.

### 11.4 Autonomie = faits mesurés (D51)

Une réparation passe sans humain **seulement** par une route autonome du socle, sur la transition exacte `base → head` :

- `reproduced` : `tests = green` et `reproduced = yes` (un instrument indépendant a recalculé exactement son contenu depuis la base et des données de confiance), **ou**
- `scoped` : `tests = green`, `regressions = none` et `scoped = yes` (le scanner a vérifié que chaque chemin modifié est dans le périmètre d'écriture de la cible, `instruments/scope.py`, une seule définition).

Sinon, elle attend la route humaine : `decision = approve` signée par l'humain, liée à la ressource exacte (jamais à un pointeur mutable) [M2-r2], depuis la console ou `python -m surface yes RESOURCE`. L'agent nomme la cible dans le commit (`Standard-Target:`) : c'est une donnée non fiable qui sert seulement à nommer la ressource ; les faits restent liés à la transition exacte. Le sujet de l'effet est la transition `repo:{area}:{item}/{base}/{head}` ; les faits qui l'autorisent portent sur cette ressource exacte. La comparaison d'arbres inclut chemins, contenus, **modes et gitlinks**.

### 11.5 Point d'entrée agent

- `python -m surface` : tâche courante, loi effective (floors + client) et routes T, en texte lisible lié au préfixe et au digest. L'agent ne lit ni README ni sérialisation de la constitution.
- `status`, `moves`, `queue`, `tasks`, `context TASK_ID`, `law SECTION/ID` pour lire ; `yes RESOURCE`, `no RESOURCE`, `release`, `rules set|route` pour que l'humain signe, avec sa propre clé, ses trois gestes.
- `submit` recontrôle route et préfixe, refuse une enveloppe qui ne traite pas exactement la tâche et sa ressource, puis la confie au **seul** chemin d'admission.
- Un travailleur externe lit la vue sur stdin et renvoie une enveloppe signée par son identité U sur stdout. Aucun retour ne ferme une dette ni ne déclenche un effet.
- `AGENTS.md` à la racine signale ce point d'entrée.

### 11.6 Interface d'admission

U parle à K/T par **une socket Unix étroite** (mode 0600/0660, répertoire non accessible en écriture à tous) exposant seulement `view`, `status`, `qualify`, `admit`. Jamais garde, clés ni ports fournisseur.

**Règle :** toute requête reçoit une réponse. Une erreur interne, y compris de sérialisation, produit un refus typé `{"ok": false, "error": TYPE}`, jamais une connexion coupée ni un détail interne [HK-1].

### 11.7 Contrôle caché

Pour certains risques, un contrôle IA parallèle, caché de l'agent, peut être ajouté. Il reste dans U, ne décide rien, et au plus le signale à l'humain, qui gèle s'il le juge utile (le `flag` de sentinelle a disparu avec D51).

---

### 11.8 Ce que l'agent reçoit pour bien coder (D25)

Le juge reste séparé ; l'agent reçoit tout ce qui l'aide à réussir et rien de ce qui l'aiderait à contourner. Rien de ce qui suit n'ouvre un droit.

| Besoin | Pièce | Où |
|---|---|---|
| Savoir **où** est l'écart | Les instruments publient leurs constats à côté des faits : `chemin:ligne:règle`, test en échec et sa trace. Un secret est localisé, jamais cité. Fichier `findings.json` lisible par le groupe de l'agent ; `surface --findings … context` | T06 (publication), U (lecture) |
| Savoir **pourquoi** le juge a refusé | Le verdict du scanner sur la proposition exacte (tests, régressions, périmètre) ; une réfutation devient une leçon et la proposition est refaite | `agent/repair.py` |
| Exécuter sans risque | Le bac de D68 (`enclosure/`) : conteneur OCI, réseau vide, système en lecture seule, environnement nettoyé, runtime seul et scratch montés, seccomp en liste d'autorisation, groupe de contrôle et délai | `agent/sandbox.py`, `enclosure/` |
| Ne pas ouvrir un autre écart | Précontrôle de **toute la loi** sur le candidat : toutes les sondes locales avant/après, la suite de `main` dans le bac à sable, ruff (erreurs réelles) et mypy sur les fichiers modifiés. Une régression qu'une recette referme au tour suivant (SBOM périmé après une montée de version) est un suivi, pas un blocage | `agent/precheck.py` |
| Ne pas tourner en rond | Mémoire par obligation (tentative, base, issue, cause) relue avant chaque essai ; budget de tentatives par base de `main` ; au-delà l'agent s'arrête et laisse un dossier (`surface --memory … tasks`). L'escalade du registre reste celle de l'échéance : l'abandon de l'agent est visible, pas un fait | `agent/memory.py` |
| Comprendre le dépôt | Carte AST : modules, définitions, imports, qui appelle quoi ; les appelants des fichiers en cause sont donnés au modèle | `context/repository.py` |
| Monter une dépendance | L'instantané figé porte aussi les versions publiées après l'épingle, leur date et l'URL du changelog | `tools/refresh_data.py` |
| Faciliter la décision | Chaque proposition qui attend l'humain porte un dossier dans son message de commit : pourquoi, quoi, ce que l'agent a vérifié et comment, risques ; `surface dossier HEAD --repo …` | `agent/repair.py` |
| Choisir le modèle | Porte unique vers les LLM (Anthropic, ou tout point compatible OpenAI) ; niveau `small` ou `frontier` selon la cible ; tout secret détecté masqué ; une ligne de journal par envoi (fournisseur, modèle, octets, masquages, SHA-256 du prompt, jamais le contenu) ; une réponse qui écrit un masque est refusée | `agent/llm.py` |

Avec un modèle, l'agent itère : candidat, précontrôle, retour des problèmes au modèle, nouveau candidat ; il ne propose que ce qui passe ses propres contrôles. Le juge mesure ensuite le commit exact, sous une autre identité.

### 11.8.1 Construction, revues et simplification (D62)

Les workers restent dans U, sous une seule identité et capacité gouvernées. Le constructeur est le seul écrivain ; les reviewers n’ont que lecture/recherche, avec des historiques séparés, sur un brouillon immuable identifié par digest. Ils reçoivent le besoin initial, les règles choisies et les changements, sans la justification du constructeur. Les dépendances et la conception sont examinées par ces mêmes lecteurs ; aucun mot-clé ne déclenche une passe préalable distincte. Le reviewer fonctionnel cherche les défauts ; le reviewer simplicité conteste chaque couche, état ou dépendance sans besoin actuel. Aucun quota de constats, aucun plafond de lignes. Une réponse vide est valide ; un constat doit nommer fichier, problème, effet et correction. Le constructeur répond à chaque constat : correction ou désaccord motivé. Une correction doit être revue sur son nouveau digest ; l’épuisement du budget ne publie pas une version non revue.

Les candidats portent `files = {chemin: contenu | null}` ; `null` supprime explicitement un fichier. Écriture et suppression passent par le même périmètre ; les tests et le contrat accepté restent protégés. Git matérialise le résultat dans un enfant exact de la base, sans modifier l’arbre de travail, et préserve les modes exécutables des fichiers édités. Déplacer consiste à supprimer puis écrire. Le contexte et la carte comprennent Python, JavaScript/TypeScript, les entrées Next.js et les fichiers de rendu ; les omissions dues au budget du contexte sont annoncées. La carte JS reste lexicale, sans prétention à une analyse complète des appels.

Budget par défaut : deux tours de revue, délai de 180 s par paire, huit étapes de recherche par dialogue. `[agent.review]` borne `rounds` entre 1 et 3 et `timeout_s` entre 1 et 600 ; `[agent] research_steps` entre 1 et 32. Au maximum : une construction initiale, trois dialogues par tour (deux lecteurs et une correction), chacun sous son budget d’étapes. Les lecteurs utilisent `frontier`, ou les providers optionnels `[llm.correctness]`, `[llm.simplicity]`. Aucun worker ne délègue récursivement. Une requête HTTP déjà partie peut dépasser le délai de revue jusqu’à son timeout fournisseur de 120 s : sa réponse tardive n’est pas consommée et aucune nouvelle étape n’en part. Une panne de reviewer est visible ; les précontrôles et mesures indépendantes restent obligatoires. Traces expurgées dans les notes de recherche et de travail existantes, et dans le dossier de construction.

La patrouille de simplicité recherche doublons, code mort, responsabilités dispersées, couches inutiles et occasions de remplacer plusieurs mécanismes par une abstraction suffisante. La mission n’est pas de réduire aveuglément la taille. La rotation persistée alterne `simplicity` et les catégories du catalogue, avec des périmètres dépôt/sous-répertoire. `simplicity:app` ou `rules:authorization:app` nomment une exploration locale avec les mêmes outils et le même mécanisme. Cadence par défaut : un tour par heure après les coups ; `[agent] patrol_interval_ms` entre 60000 et 86400000. Une panne réserve aussi le prochain créneau pour éviter une tempête de relances. `python -m agent patrol standard.toml simplicity` lance un examen manuel ; `patrol-results` liste les propositions et marque `stale` celles dont main ou la loi ont changé. Une proposition retenue sert une dette existante dans son périmètre ou devient une demande BUILD avec contrat signé pour un refactoring transversal. Elle ne crée pas elle-même une obligation constitutionnelle, ne modifie pas les règles et ne touche pas la TCB du client.

### 11.9 L'interface (D27)

`python -m surface.web standard.toml` : une application web sous son propre utilisateur Unix (`standard-web`), à l'écoute de `localhost` seulement (tunnel SSH ou proxy TLS devant). **La première page s'appelle Run** : tous les composants du produit, pas seulement ses APIs, chacun avec ses signaux d'astreinte, reconnus selon les conventions OpenTelemetry dans des métriques Prometheus (`surface/telemetry.py`) : APIs (déclarées dans `openapi.json` et observées : req/s, 5xx, p50/p95/p99, disponibilité, budget d'erreur contre le SLO), workers et files (débit, échecs, latence, messages en attente), tâches planifiées (dernier succès, durée, période, retard, échec), bases de données (opérations/s, erreurs, latences), services externes appelés (appels/s, erreurs, latences), processus (CPU, mémoire, ancienneté). Un échec est un statut 5xx ou une étiquette `error_type`, comme le définissent les conventions. Plus le trafic, les mises en production et l'état des sources de métriques. Ces chiffres sont des informations pour l'équipe : ils n'ouvrent aucun droit. Le reste de l'interface, en deux groupes (Run, Construction) plus ce qui est commun :

| Page | Groupe | Contenu |
|---|---|---|
| **Run** | Run | Composants et signaux, version en production, SLO et budgets, frontière d'autonomie par composant (Voit, Prévient, Agit, Prouve, D29), écarts non couverts en tête, et ce que l'agent retient et pourquoi |
| **Décisions** (D51) | Commun | La file de l'humain : chaque coup qui attend son oui, avec les faits mesurés, la route qui manque et ce qu'une règle coupée laisse à sa main ; oui (`decision = approve`) ou non (gel), signés dans le navigateur |
| **Alertes** (D30) | Run | Une alerte s'ouvre quand un composant passe dégradé ou en échec sur 5 minutes, quand un SLO brûle vite (page) ou lentement (ticket), quand une source se tait ou quand une obligation dépasse son échéance ; silences dans les règles du jeu, fermeture au retour du composant. Bandeau sur toutes les pages, badge, titre de l'onglet. Ni e-mail ni messagerie |
| **Règles du jeu** (D51) | Commun | Qui joue chaque coup (routes autonomes allumées ou coupées), seuils des routes avec la borne du socle, production (objectif, latence, fenêtre, canari), SLO, composants, sondes, silences et historique. Le serveur rédige le document complet (`POST /api/rules/draft`), le navigateur le signe (`law`), il est en vigueur aussitôt ; le noyau refuse ce qui serait plus lâche que le socle |
| **Autonomie, Activité** | Run | Ce que l'agent fait seul ou avec un oui ; les exigences du socle (sécurité du code, dépendances et chaîne logicielle, CI, gouvernance du code) ; les écarts rangés par qui s'en occupe, les réparations de l'agent, ses abandons et leur dossier |
| **Demandes** (D34) | Construction | Écrire une demande et ses tests d'acceptation, voir le contrat mesuré (`red` = demande du nouveau ; `passes:N` = ne promet rien), signer le contrat, suivre l'implémentation, l'acceptation et la livraison |
| **Contributions** | Construction | La boîte de dépôt et les faits mesurés (tests, régressions, décision), avec la raison exacte d'un blocage (`secrets: found:1 -> found:2 [app.py:15…]`) |
| **Preuves, Clé** | Commun | Preuves, exigences et loi en vigueur ; import de la clé de la personne |

Ce que l'interface ne fait pas : elle ne détient aucune clé et ne décide rien. Elle lit par la passerelle (la vue, qui publie aussi les faits sur les transitions exactes) et ce qui est publié pour les personnes (constats, notes de l'agent, dépôts en lecture), et transmet au noyau les enveloppes signées. **La signature se fait dans le navigateur** : la clé est importée dans WebCrypto, non exportable, gardée dans IndexedDB ; le navigateur construit lui-même l'énoncé canonique, le PAE et l'enveloppe à partir du corps qu'il affiche (`surface/static/sign.js`, identique octet pour octet à `bt/signing.py`, vérifié par un test). **Correction (revue d'octobre 2026) :** l'affirmation antérieure selon laquelle un serveur web compromis ne pouvait pas faire signer autre chose que ce que le navigateur montre est fausse. Le serveur sert lui-même `sign.js` et `app.js` : compromis, il peut servir un script qui signe n'importe quel corps avec la clé non exportable, ou capter le fichier de clé au moment de l'import. La clé non exportable empêche seulement sa copie. Tant que les scripts de signature ne viennent pas d'une origine distincte et épinglée (ou d'un authentificateur qui affiche ce qu'il signe), `standard-web` est dans la confiance des personnes qui y signent. Les requêtes adressées à un autre nom d'hôte que `localhost` (ou un nom déclaré par `--allow-host`) sont refusées, ce qui ferme la lecture et l'écriture par DNS rebinding. En production, une passkey : le noyau vérifie déjà les assertions WebAuthn ES256, il reste à les enrôler par une rotation de racine. **Limite :** la lecture n'est pas authentifiée ; l'interface écoute localhost et compte sur le tunnel ou le proxy devant elle.

## 12. Floors de la release

Les floors portent la direction (autonomie, sécurité, conformité) dans le **même langage** qu'une loi client.

**Rôles** que tout client lie à ses identités : `owner`, `inventory_source`, `scanner` (D51 : plus de `compliance_officer`).

**Clôture sur preuve indépendante (F1).** Tout effet laisse une obligation `proof` que seule une preuve indépendante de niveau `real` ferme.

**Couverture (F2).** Chaque univers déclaré doit être observé complet par une source indépendante, sinon c'est un écart : `inventory` (dépôt) et `run-sources` (production).

**Mesures techniques** (observées par `@scanner`, réparées par `remediate`) — fraîcheur / échéance en jours :

| Id | Ressource | Attendu | Fraîcheur | Échéance |
|---|---|---|---|---|
| vulns | `repo:deps:vulns` | aucune haute | 1 | 7 |
| deps-age | `repo:deps:age` | aucune majeure en retard | 7 | 30 |
| licenses | `repo:deps:licenses` | conforme à la politique | 7 | 30 |
| secrets | `repo:code:secrets` | aucune fuite | 1 | 1 |
| sast | `repo:code:sast` | aucune haute | 1 | 30 |
| ci | `repo:ci:main` | verte | 1 | 2 |
| actions | `repo:ci:actions` | toutes épinglées | 7 | 30 |
| sbom | `repo:supply:sbom` | à jour | 7 | 7 |

**Réglages** (observés, réparés par des humains) : protection de `main` (seule la garde la déplace) ; lignée (tout commit de `main` depuis l'ancre est la tête d'un effet jugé).

**Mesures organisationnelles :** retirées (D51). ISMS, RH, fournisseurs, SoA et attestations ne sont pas l'objet de Standard ; ISO 27001 et DORA ne servent plus que de motif à des règles techniques précises et vérifiables (lot du catalogue de règles).

**Entrée dans `main` et production : les routes de chaque coup (F0-12).** Toutes les opérations de `MAIN_OPS` partagent le même CAS de la garde. `@nom` est un seuil des règles du jeu, borné par le socle (valeur du socle entre parenthèses) ; *recommandé* est la valeur que l'installation signe à la genèse.

| Opération | Ressource | Routes autonomes | Route humaine |
|---|---|---|---|
| `remediate` | `repo:{area}:{item}/{base}/{head}` | `reproduced` : `tests = green`, `reproduced = yes` ; `scoped` : `tests = green`, `regressions = none`, `scoped = yes` | `tests`, `regressions`, `decision` |
| `integrate` | `repo:contrib:{contributeur}/{base}/{head}` | — | `tests = green`, `regressions = none`, `decision` |
| `implement` (D34) | `repo:feature:{request}/{base}/{head}` | `accepted` : `acceptance = green`, `tests = green`, `regressions = none`, `scoped = yes` | les mêmes faits sans `scoped`, plus `decision` |
| `deploy` | `run:release:all/{from}/{to}` | `direct` : `candidate`, `window = open`, `budget_pct ≥ @freeze_below` (0) ; `promote` : `candidate`, `canary_error_delta ≤ @canary_max_error_delta` (2 ; recommandé 0,5), `canary_requests ≥ @canary_min_requests` (20 ; 100), `canary_baked_min ≥ @canary_bake_min` (1 ; 10) | `candidate`, `decision` |
| `canary` | `run:canary:all/{from}/{to}` | `auto` : `candidate`, `window = open`, `budget_pct ≥ @freeze_below` | `candidate`, `decision` |
| `rollback` | `run:service:all/{from}/{to}` | `previous`, `proven`, `migrations_crossed ≤ @rollback_migrations`, puis `burn` : `switched_min ≤ @rollback_horizon_min` (240 ; 30) et `burn_fast ≥ @burn_fast` (14,4) ; `failing` : même horizon et `failing_pct ≥ @failing` (5) ; `unanswered` : `unanswered_s ≥ 90` | `previous`, `decision` |
| `restart` | `run:process:all/{release}/{n}` | `failing`, `burn` : `live`, `restarts_last_hour ≤ @restarts_per_hour` (11 ; 2) et le seuil correspondant — **coupées dans les règles recommandées** | `decision` |
| `abort` | `run:canary:abort/{from}/{to}` | `auto` : `running` (retirer un canari est toujours sûr) | `decision` |

`window` et `budget_pct` sont mesurés par le scanner depuis les règles en vigueur (`instruments/production.py`). Une route coupée dans les règles laisse le coup à l'humain ; aucune règle ne coupe la route humaine.

**Demandes (D34).** Ressource typée `request` (`build:request/<rid>`, champs `title`, `spec`, `contract` en digests) : `proposed → contracted` exige `contract = red` (les tests d'acceptation échouent sur main : la demande demande du nouveau), `contracted → delivered` exige `accepted = yes` (main passe le contrat), `withdraw` depuis les deux premiers états. Enregistrer et contracter : le rôle produit (`register:request`, `transition:request:contract`).

**Décisions humaines (D46, D51).** Une seule forme : `decision = approve`, signée par une identité de genre `human` de la racine en vigueur, sur la ressource exacte du coup (atome `observed` à quatre arguments, `DECISION` de FLOOR-0). Un instrument, l'oracle ou l'agent ne remplace pas une personne. Un non est un gel de la ressource.

**Production (D30–D36)** — cibles observées par `@scanner`, fraîcheur 15 min :

| Id | Ressource | Attendu | Échéance | Réparation |
|---|---|---|---|---|
| run-sources | `run:sources:all` | couverture complète | 1 h | humaine |
| run-slo | `run:service:all` | `slo = met` (aucun composant compté à 5 % d'échecs ou plus, aucun SLO qui consomme à 14,4 ou plus) | 30 min | `rollback` |
| run-live | `run:release:all` | `lag = none` | 1 jour | `deploy` |

**Instruments épinglés (D33, D37).** Les floors réservent à `@scanner` : `tests`, `regressions`, `reproduced`, `scoped`, `acceptance`, `contract`, `accepted`, `window` et tous les faits de production ci-dessus. Leur méthode est l'empreinte du paquet de programmes (`programs@sha256:…`, calculée par les floors) : changer un programme change la release, donc la genèse. Seule une `measurement` de cette source, avec cette méthode, le porte ; son artefact est l'enregistrement rejouable.

**Projection conformité :** retirée (D51). Aucune étiquette ISO/DORA/NIS2 n'est plus affichée comme couverture.

---

## 13. Protocole et parcours produit

### 13.1 Protocole de bout en bout

```
proposer (U)
 → authentifier, qualifier les prémisses (T01–T03, T06)
 → juger (K)
 → vérifier indépendamment (T05)
 → committer atomiquement au préfixe ancré (T04)
 → réserver, re-juger au départ, envoyer l'effet exact (T07)
 → résultat confirmé ou UNKNOWN (T08)
 → réconcilier
 → nouvelle mesure qualifiée (T06)
 → clôture, maintien ou escalade de l'obligation (K ; visible dans la console)
```

### 13.2 Parcours

1. **Constituer.** Épingler release, genèse, FLOOR-0 et floors ; composer la loi client ; établir identités (un humain, l'agent, les machines, l'horloge). Le provisionnement des T a une provenance indépendante de l'agent.
2. **Découvrir et qualifier.** Inventorier, choisir une route par responsabilité, tester réellement les T nécessaires.
3. **Projeter.** Mesure absente, couverture inconnue, instrument indisponible, risque constaté et effet incertain sont cinq états distincts.
4. **Travailler.** Les agents reprennent les obligations, en BUILD ou RUN.
5. **Décider et effectuer.** Selon §13.1.
6. **Vérifier et poursuivre.** Clôture sur preuve ; sinon reprise, réconciliation, restauration de route ou escalade.

**Règle de réalisation :** toute intégration se rattache à une étape du parcours, à un propriétaire K/T/U, à un contrat de preuve et à un scénario d'échec. Une fonctionnalité de démo ne devient une capacité de Standard que si elle fonctionne sous la loi effective, emprunte la frontière physique requise, conserve la dette et expose sa couverture.

---

## 14. Garanties G01–G16

Découpage **figé conditionnellement 16/16**. Aucune garantie n'est démontrée en production.

| G | Garantie | K (non délégable) | T (dépendance) | U (délégué) | Falsificateur |
|---|---|---|---|---|---|
| G01 | Aucun élargissement par un acteur seul | Signature de l'unique humain | Custody de sa clé | Solliciter | Racine de clés tenues par une personne |
| G02 | Restriction immédiate | Restriction et re-jugement dans l'ordre | Ordre atomique de départ, fencing | Stopper les travaux | Révocation pendant réservation, avant les octets |
| G03 | Floors inaffaiblissables | Composition additive | Release / runtime authentiques | Proposer plus strict | Autre code, floor plus faible |
| G04 | Transition canonique déterministe | Delta exhaustif | Journal durable, ordre | Proposer | Deux têtes divergentes acceptées |
| G05 | Sens des signatures | Domaine, contenu, identité logique | Crypto, clés, identité physique | Préparer | Collusion, clé compromise |
| G06 | Le temps n'accorde rien | Contraintes temporelles | Temps fiable | Retry, backoff | Deux sources de temps incohérentes |
| G07 | Preuve qualifiée | Sujet, source, méthode, fraîcheur, couverture | Vérité de la mesure | Scanner | Même payload pour deux mondes |
| G08 | Dette persistante | Ouverture, continuité, échéance, clôture | Rétention, observation couvrante | WorkItems, retries | Renommage ou panne de scanner masque la dette |
| G09 | Aucun effet hors intention | Effet exact re-jugé | Garde, egress exclusifs, octets | Plans | Egress alternatif |
| G10 | Effet incertain jamais présumé | Réservation, `UNKNOWN`, réconciliation | Fencing, idempotence, readback | Résoudre | ACK perdu puis retry |
| G11 | Historique non régressable | Rejet d'un préfixe incompatible | Pins indépendants | Proposer recovery | Rollback coordonné journal + pin |
| G12 | Second juge indépendant | Exiger le contrôle, bloquer | Vérificateur réellement indépendant | Diagnostics | Deux juges partagent le bug |
| G13 | Santé ≠ fait démontré | Clôture sur preuve seulement | Vérité, complétude | Inventaire | Fausse attestation saine |
| G14 | Aucun mode god | Genèse, racine, récupération gouvernées | Installer, clés racines | Préparer | Restore god-mode |
| G15 | Aucun egress privilégié alternatif | Contrat d'effet sur toutes les interfaces | Exclusivité OS/réseau/API, inventaire des chemins | Exécuter sous capacité | Job CI avec secret d'écriture hors garde |
| G16 | Autonomie sans souveraineté | Devoirs, permissions, exigibilité d'escalade | Livraison, disponibilité, équité | Scheduling, notification | Zéro progrès ni escalade ; auto-validation |

G04 n'implique pas que chaque effet physique correspond à une transition : G09/G10 s'examinent séparément.

---

## 15. Limites : établies et choisies

### 15.1 Limites établies

| | Limite | Statut | Conséquence |
|---|---|---|---|
| **L-01** | Une attestation signée n'implique pas la vérité physique : le payload est identique que la vérité soit vraie ou fausse | Logique, établie | K garde provenance, sujet, méthode, fraîcheur, couverture, indépendance, clôture. T fournit la mesure qualifiée. U ne qualifie jamais sa propre affirmation |
| **L-02** | Un jugement logiciel pur ne peut pas empêcher physiquement un egress | Logique, sous la prémisse « K sans credentials » | K spécifie et re-juge ; T impose l'exclusivité |
| **L-03** | Un hash ne prouve pas qu'un acteur physique est un humain distinct | Logique | K impose un seul humain logique ; T établit liaison et custody |
| **L-04** | Résister au rollback exige une ancre durable indépendante | Contrat externe requis | K rejette les historiques invalides quand il a l'ancre ; T protège l'ancre |
| **L-05** | Une autorisation n'implique aucun progrès équitable | Logique | K garde obligations et exigibilité d'escalade ; T/U fournissent l'exécution observable |

**Non établi (ouvert)** : effet distant exactement-une-fois sous ambiguïté fournisseur ; fencing multi-hôte ; indépendance de deux juges déployés ; vérité et couverture réelles des sources ; stabilité des dettes sous réparations répétées et renommages ; custody des clés au bootstrap ; absence vérifiée d'egress alternatif.

Autres limites assumées : pas de preuve formelle de convergence ; pas de consensus multi-hôte ; une signature fournisseur ne prouve pas qu'une personne a reçu l'alerte ; la conformité ne se déduit pas de `PROVEN` ; le système fait confiance au noyau Linux pour l'isolation interne ; un appel synchrone bloqué retarde les écritures (l'adaptateur doit borner ses I/O).

### 15.2 Ce que « garantie physique » veut dire ici

Le noyau raisonne sur des signatures et des faits. Plusieurs garanties reposent sur des propriétés du monde réel qu'il ne peut pas voir. Elles ne sont démontrées que **sur une installation précise**, par des essais réels :

| Garantie | Prémisse physique | Essai qui la démontre |
|---|---|---|
| Humain (G01) | La clé est celle de l'humain | Enrôlement et custody de sa clé vérifiés par un tiers |
| Un seul chemin vers `main` (G09, G15) | Seule la garde peut écrire | Git local : deux utilisateurs Unix (`ceremony.py separate`), dépôt possédé par la garde sans écriture de groupe ni d'autres, umask 027 de la garde, store de l'agent cloné sans hardlinks. **Démontré** (D22). GitHub : tenter d'écrire avec chaque autre token, App ou règle de bypass existante |
| Anti-rollback (G11) | Pins hors du domaine de restauration du journal | Restaurer le disque du journal seul, puis les deux ensemble |
| Temps (G06) | Horloge de l'opérateur juste | Décaler ou compromettre l'horloge de l'opérateur |
| Second juge (G12) | Domaine de panne distinct | Faute injectée dans un juge, l'autre bloque |

Le code fournit des **sondes de qualification** (`tools/qualify.py`) qui vérifient ce qui est vérifiable localement et listent explicitement ce qu'elles ne prouvent pas. Une évaluation T signée par l'opérateur lui-même est marquée **auto-évaluée** : elle fait tourner le système, elle ne qualifie rien.

### 15.3 Couverture retenue

La couverture n'est pas « tout ». Elle se choisit cible par cible, avec une route honnête pour chacune :

| Route | Cibles | Pourquoi ce choix |
|---|---|---|
| **Autonome** (recette reproductible + tests) | `sbom`, `vulns`, `actions` | Le correctif est une fonction déterministe de la base et de données épinglées : un instrument indépendant peut le recalculer octet pour octet |
| **Revue humaine signée** (proposition de l'agent) | `secrets`, `sast`, `ci`, `deps-age`, `licenses` | Le correctif demande du jugement : aucun instrument ne peut le reproduire, donc un humain habilité signe la revue de la transition exacte |
| **Humaine** (réglage ou attestation) | `branch`, `lineage` | Ce sont des réglages du fournisseur : Standard les mesure ; l’humain intervient chez le fournisseur |

L'agent fait seul tout ce qui ne demande que du calcul : mesurer pour lui-même, proposer, soumettre. Il ne certifie jamais son propre résultat (F0-8) ; c'est un instrument distinct, automatique lui aussi, qui atteste.

### 15.4 Limites choisies

Ce que Standard **ne prétend pas** couvrir dans cette version, volontairement :

- **Écosystèmes.** Dépendances Python via un `requirements.txt` à épinglage exact, workflows GitHub Actions, dépôts git. Tout autre manifeste rend la cible `uncovered`, visible, jamais verte par défaut.
- **Fournisseurs.** GitHub et git local. Un autre fournisseur est `NO_ROUTE` jusqu'à ce qu'un adaptateur avec une primitive atomique existe.
- **Données de sécurité.** Les avis de vulnérabilités, métadonnées de paquets et résolutions d'actions sont des **instantanés épinglés par digest**, rafraîchis par l'opérateur. Une faille publiée après l'instantané n'existe pas pour Standard jusqu'au rafraîchissement ; la fraîcheur de l'instantané est bornée par celle de la cible.
- **Vérité des outils.** pip-audit, bandit ou la base d'avis peuvent se tromper ; Standard garantit qu'ils ont été appliqués à l'univers complet et au bon sujet, pas qu'ils sont exacts (L-01).
- **Tests.** Une suite verte est nécessaire, jamais suffisante : elle ne couvre que ce qu'elle teste.
- **Conformité.** Standard produit des preuves et des écarts sur ses propres cibles. Les étiquettes ISO 27001, NIS2 et DORA ne sont que des projections par thème ; aucun rattachement vérifié aux clauses ni aucune certification ne sont encore produits.
- **Installation.** Un seul hôte, un seul writer (D06). Les témoins et l'évaluateur d'une démo tournent chez l'opérateur : la démo est auto-évaluée.
- **Redevabilité.** Elle tourne dans le processus T, pas dans un worker confiné. Son défaut ne peut que masquer ou inventer un écart (budget visibilité), et `status` le montre en `FAULT`.

---

## 16. Modèle de menace

### 16.1 Acteurs et pannes

- Agent qui propose entrées, code, fichiers, sorties d'outils arbitraires, sans admission privilégiée.
- Clé individuelle compromise (agent, observateur, témoin, garde).
- Instrument défectueux ou malveillant qui signe des rapports faux.
- Journal ou garde arrêté à n'importe quel point ; stockage restauré en arrière.
- Deux processus ou hôtes partageant un fournisseur sans partager le verrou.
- Fournisseur qui retarde, duplique, applique partiellement ou ne confirme pas.
- Déployeur capable de modifier runtime, secrets ou identifiant de release.
- **Sujet mesuré qui contrôle son instrument** (config CI, pytest, `nosec`, octets du dépôt).

### 16.2 Frontières à qualifier

| Frontière | Entrée non fiable | Échec qui doit fermer |
|---|---|---|
| signature → identité | DSSE, WebAuthn, clés | Encodage, replay, signature invalide |
| déclarations → loi | Constitution client | Compilation ambiguë, exception cachée |
| état → décision | Préfixe, temps attesté | Mutation silencieuse, droit indu |
| observateur → preuve | Analyse externe | Auto-certification, couverture insuffisante |
| décision → journal | Entrée candidate, pins | Rollback, double écriture, divergence |
| journal → départ | Token, réservation, horloge | TOCTOU, réservation répétée |
| garde → fournisseur | Requête, secret, endpoint | Autre endpoint, effet partiel, retry illégitime |
| exécution → clôture | Retour fournisseur | Succès déclaré sans vérification |
| release → exécution | Code, dépendances, OS, CI | Import contourné, autre credential |

### 16.3 Campagnes d'attaque de référence

A01 loi équivalente en apparence mais moins restrictive · A02 horodatages au plafond et restriction simultanée · A03 même humain sous deux identités · A04 couverture « complete » sur ensemble incomplet · A05 scanner qui signe un `reproduced` faux · A06 mutation invisible dans le delta · A07 crash avant/après ancre, journal, publication · A08 deux gardes sous verrou local, hôtes différents · A09 fournisseur qui reçoit et ne répond pas · A10 egress vers une autre destination à arguments logiques égaux · A11 preuve d'application réutilisée pour un autre sujet · A12 retrait ou renommage d'exigence sans régler la dette · A13 run et bootstrap avec credentials de contournement · A14 confusion entre deux releases · A15 réconciliation d'un effet encore susceptible de partir.

Risques d'autonomie à instrumenter en priorité : CI fluctuante, obligations stables sous réparations répétées, découverte d'un dépôt vide, système SRE préexistant, agents multiples concurrents, absence de réponse humaine à une escalade.

### 16.4 Mesures du laboratoire

| Mesure | Ce qui est compté |
|---|---|
| **SV** Safety violations | Violations reproductibles du contrat de permission et de transition |
| **PF** Progress failures | Impasses injustifiées malgré préconditions valides, distinguées des arrêts exigés |
| **IE** Indeterminate effects | Effets inconnus, part réconciliée par preuve indépendante, absence de retry dangereux |
| **OC** Obligation continuity | Persistance des dettes et des échéances à travers échecs, redémarrages, renommages, changements de loi |
| **PB** Privilege boundary | Inventaire complet des credentials, propriétaires, canaux d'egress, exemptions |
| **ES** Evidence soundness | Précision sujet/méthode/univers ; capacité d'une observation fausse à débloquer une action |

**Ne jamais optimiser l'autonomie en affaiblissant FLOOR-0.**

Le Work Engine conserve les événements de tentative avec base de lecture (préfixe, loi, commit principal et empreintes des findings/réglages), obligation, route, issue et raison stable. Une nouvelle base annule l'ancien délai et l'ancien bail. `standard-progress/v1` compte comme PF confirmée seulement une réparation encore ouverte, à route disponible, abandonnée après son budget. Un jail U indisponible est enregistré comme `trust_blocked` sans consommer ce budget ; `TRUST_BLOCKED`, `NO_ROUTE` et l'attente humaine restent des arrêts visibles, hors PF. Ce compteur est volontairement étroit : il ne mesure pas encore les occasions manquées sans tentative ni toutes les causes organisationnelles d'immobilité.

---

## 17. Registre des constats (non-régression)

Chaque constat est **fermé par une règle** de ce document et doit avoir un test de non-régression dans le nouveau code. Aucun ne peut réapparaître.

### 17.1 Revue V6 — 4 causes racines

| Cause | Constats | Structure qui ferme la classe |
|---|---|---|
| **Polarité appliquée au seul portail** | V6-2, V6-5, V6-7, saturation des faits | Une obligation bloquante ne vise que les genres qui agissent, attestent ou atténuent ; le client n'ajoute jamais de preuve sous le niveau du floor ; une restriction peut partager le dernier instant ; une condition ne voit que les faits qu'elle nomme pour sa ressource |
| **Cycle d'effet implicite** | V6-1, V6-10 | Automate `LINE` unique lu par les deux juges ; départ dans `DISPATCH_MS` ou jamais ; réconciliation seulement après ; entrée exacte conservée avant l'épingle |
| **Identité portée par la représentation** | V6-6, V6-9, enveloppe | Une clé, un encodage canonique ; enveloppe fermée ; dette suivie par `(ressource, propriété)` |
| **Provenance et jointure par listes** | V6-3, V6-4, V6-8, portes | Instances d'obligation étiquetées par la provenance de l'ouvreur ; une fenêtre ou porte ouverte par la chaîne de l'acteur ne lui sert pas ; `where` limité aux chaînes et entiers ; table explicite des gestionnaires ; différentiel continu des deux juges |

| # | Constat | Règle |
|---|---|---|
| V6-1 | Réconciliation avant envoi → double effet | §8.1 |
| V6-2 | Une loi pouvait désactiver veto, révocation, gel | §4.5, F0-3 |
| V6-3 | Booléen sur chemin pointé → arrêt du journal par n'importe quel agent | §4.4 |
| V6-4 | L'agent ouvrait lui-même la fenêtre qui l'autorise | F0-8 |
| V6-5 | Horodatage au plafond → plus aucun gel admissible | F0-6, §7.2 |
| V6-6 | Renommer une cible remettait l'échéance à zéro | §7.5, §9.2 |
| V6-7 | Preuve client sous le niveau du floor | §4.5 |
| V6-8 | Nom de preuve = méthode interne → arrêt persistant | §6.4 |
| V6-9 | Même passkey enrôlée deux fois (point compressé/non compressé) | K02 |
| V6-10 | Crash entre épingle et commit → journal bloqué | §8.2.6 |
| V6-env | Champs non signés dans l'enveloppe changent la tête | K02 |
| V6-sat | Saturation des faits rendant `BOUND.EXCEEDED` les effets des autres | §4.4 |
| V6-§3.1 | Preuve d'une ressource (PR 42) restée valide quand la cible désigne une autre (PR 43) | §4.6 |
| V6-§3.2 | Ancien délai utilisé après changement de loi | §4.6 |
| V6-§3.3 | Loi mal formée activée, détectée seulement par le travailleur | Validation complète des cibles **avant** admission |
| V6-§3.4 | Verrou relâché avant l'appel fournisseur | §8.2 |
| V6-§3.5 | Effet du premier juge non comparé par le second | §6.4 |
| V6-§3.6 | Champs compilés du noyau recopiés dans le second juge | §6.4 |
| V6-§3.7 | Ancienne obligation soldée selon une nouvelle règle | §4.6 |
| V6-§3.8 | Activation comptabilisée sous la mauvaise loi | §4.5 |
| V6-§3.9 | Route de réparation contrôlée par motif textuel | Types, valeurs répétées et bornes des paramètres ; inversion déterministe du template |

**Ce qui a tenu en V6** (à conserver) : 14 400 entrées hostiles → refus sans exception ; JSON canonique strict ; liaison au domaine ; quorum sur identités distinctes ; veto et dépassement ; atténuation et budgets ; indépendance des chaînes ; usage unique face à deux gardes en course et à un redémarrage ; épingles, détection de fourche et de régression.

### 17.2 Revue V7/M2 — 18 constats

| # | Constat | Règle |
|---|---|---|
| R01 | Restriction acquittée sans application | §7.1 delta exact |
| R02 | Flag/prudence absents du second profil | §6.4 matrice |
| R03 | Temps ops plafonné à l'ancre | §7.2 |
| R04 | Lancement non vérifié | §6.4, §8.5 |
| R05 | Ancienne CI verte prise comme preuve | §7.3 |
| R06 | Scope de dépendances trop large | §7.4 |
| R07 | Snapshot du scanner absent | §7.3 |
| R08 | État publié après l'effet | §8.5 |
| R09 | Destination/base de fusion non garanties | §8.6 |
| R10 | Intention/token périmés bloqués | §8.4 |
| R11 | Humain dépendant des clés témoins | §7.2 |
| R12 | Univers des secrets filtré par la méthode | §7.3 |
| R13 | Pins pris pour fermeture transitive | §7.3 |
| R14 | Licence par sous-chaîne | §7.3 |
| R15 | Secret envoyé au modèle | §7.4 |
| R16 | `FAULT` casse le rapport | §9.4 |
| R17 | Plans et cibles divergents entre vues | §9.4 |
| R18 | Conformité trop large | §7.3 |

### 17.3 Revues M2 (tours 1 et 2)

| | Constat | Règle |
|---|---|---|
| M2-r1 | PR de fork autonome ; journal remplaçable ; `.git/config` écrit par le modèle ; code tiers près des clés ; sondes « OK » faute d'erreur ; blocages | §7.4, §8.5, §7.3 |
| M2-r2 | Instrument contrôlé par le sujet (CI, pytest, `nosec`, octet NUL) ; périmètre calculé sur noms de fichiers ; commit fusionné ≠ commit jugé ; pannes non isolées ; revue liée à un pointeur mutable | §7.3, §7.4, §11.4 |

### 17.4 Laboratoire (campagnes II–IV)

| | Constat | Leçon |
|---|---|---|
| LAB-1 | Seconds `redeem` refusés pour `HIST.TIME`, pas pour usage unique | Un refus pour une autre raison ne prouve pas la garantie testée |
| LAB-2 | Contrôle « sain » invalide (runner qui n'enlevait pas l'écart) | Tout oracle a un contrôle positif **et** négatif vérifiés |
| LAB-3 | Traceback masquée par `tee` ; CI verte | L'instrumentation de test est elle-même vérifiée |
| LAB-4 | Liste `obligations` vide ≠ absence d'obligation constitutionnelle | Lire la projection canonique, pas un champ dérivé |

### 17.5 Prototype hybride

| | Constat | Règle |
|---|---|---|
| HK-1 | La passerelle coupait la connexion quand la réponse n'était pas sérialisable (`GATEWAY.RESPONSE`), et `make check` échouait alors que le registre affichait PASS | §11.6 ; un registre de validation est régénéré à chaque commit, jamais recopié |

### 17.6 Revue de code d'octobre 2026

Chaque constat a un falsificateur dans `tests/test_review.py` (ou le fichier cité).

| # | Constat | Règle |
|---|---|---|
| RV-1 | Sans `runner_user`, le code candidat tournait sous l'opérateur, avec ses clés | Échec fermé ; `unconfined` explicite et démo seulement (D46) |
| RV-2 | Une identité machine signait `review = approved` et ouvrait la route revue | Auteur humain exigé dans la loi (D46) |
| RV-3 | La recette `vulns` prenait le plus petit correctif de toutes les branches : rétrogradation autonome | En avant, même version majeure, sinon pas de recette |
| RV-4 | Jeton d'écriture GitHub dans argv, lisible dans `/proc` | Passé par l'environnement |
| RV-5 | Lecture et écriture de l'interface par DNS rebinding ; signature navigateur surévaluée | Contrôle de `Host` ; §11.9 corrigé |
| RV-6 | Base64 non canonique et ECDSA high-S : deux enveloppes, deux têtes pour un énoncé | Encodages canoniques, DER strict, s bas (D47) |
| RV-7 | Composition de la loi, `HIST.AHEAD`, `retry_of`, `when` sur un seul juge ; différentiel annoncé absent | Recalculés par le second juge ; différentiel aléatoire (D47) |
| RV-8 | Une mesure plus ancienne remplaçait une plus récente | Refus `PROV.STALE` |
| RV-9 | Une violation de niveau `escalate` restait ESCALATED pour toujours | Close par un humain (`resolved`), jamais par une machine |
| RV-10 | Non-régression par compte de constats, aveugle quand la base était non couverte, absente de `remediate-reviewed` | Comparaison de mesures ; exigée en revue (D48) |
| RV-11 | Registres non durables ; clé enregistrée lue `ok` sans mouvement | fsync ; achèvement sous verrou ou `unknown` (D48) |
| RV-12 | Pli de redevabilité muté par deux threads | Verrou ; pli à moitié appliqué jamais réutilisé |
| RV-13 | Le rejeu comparait l'enregistrement à lui-même, pas au statut signé | Le fait du journal doit figurer dans l'enregistrement |
| RV-14 | Écriture O(n) : 10 → 55 ms par entrée à 4 000 | Copies détachées sans copie profonde des énoncés (D49) |
| RV-15 | Témoins à la milliseconde près ; monotonie perdue au redémarrage ; démarrage sans témoins | Écart borné, valeur prudente, état persisté, configuration `[clock]` (D50) |
| RV-16 | Dépendances de la TCB non épinglées, hors empreinte | Clôture épinglée par hash, dans l'empreinte d'installation (D49) |
| RV-17 | `git archive` appliquait les `.gitattributes` du sujet (export-ignore) aux instruments | Export des blobs depuis la base d'objets (D48) |

---

## 18. Décisions

Ce registre conserve des décisions remplacées pour tracer les choix. Leurs mécanismes retirés ne sont pas des instructions d’implémentation ; les sections courantes et la dernière décision qui les remplace prévalent.

Ce registre est chronologique : une décision ultérieure peut remplacer un mécanisme ou déplacer son fichier sans effacer la raison de la décision antérieure. Les anciens chemins `bt/runtime.py`, `bt/deploy.py`, `bt/policy.py` et `bt/slo.py` cités dans D30–D32 ne sont plus des chemins du code courant ; voir l'inventaire §20 et les décisions D36–D39. « Arrêtée » qualifie le choix architectural à cette date, pas une preuve que chaque détail de sa première implémentation subsiste.

| # | Décision | Statut |
|---|---|---|
| D01 | Noyau hybride relationnel à **jugement unique** (§6.3) | Arrêtée |
| D02 | TCB en Python pour l'instant ; choix final sur sûreté, performance, fiabilité | Arrêtée |
| D03 | Découpage K/T/U des 16 garanties figé conditionnellement ; ne se rouvre que sur contre-exemple (§22) | Arrêtée |
| D04 | **Autorité hébergée** par un service durable unique d'admission et d'exécution ; exports Git en lecture seule | Arrêtée |
| D05 | Fusion GitHub par `updateRefs` avec précondition atomique sur la base ; route inactive si la primitive n'est pas garantie | Arrêtée |
| D06 | **Un seul writer** par journal. Le multi-instance est interdit tant qu'un protocole de fencing n'est pas démontré | Arrêtée |
| D07 | Horloge de départ = horloge de l'exécuteur, protégée contre le recul, confrontée à l'ancre ; incertitude non nulle refusée | Arrêtée |
| D08 | Interface native ; WorkItems canoniques ; Jira et synchronisation de tickets hors périmètre | Arrêtée |
| D09 | Non-application définitive prouvée **par réservation**, jamais par absence | Arrêtée |
| D10 | Rapports de preuve en stockage par contenu ; métadonnées bornées dans le journal | Arrêtée |
| D11 | Autonomie de dépendances par transformations sémantiques étroites, par écosystème | Arrêtée |
| D12 | Floors = niveau intermédiaire qui porte l'autonomie ; pas de lois d'exploitation Standard séparées | Arrêtée |
| D13 | Deux hébergements (dépôt seul, service géré) sur le même protocole (§19) | Arrêtée |
| D14 | Le refacto part du code existant (constitution 0.6, noyau hybride) et le reconstruit dans ce dépôt selon §20 ; aucune compatibilité de genèse | Arrêtée |
| D15 | Jalon investisseur : maintenance + sécurité + conformité ensemble, démo sur un dépôt dédié, agents Claude via API, ISO 27001 + NIS2 + DORA | Arrêtée |
| D16 | Trois routes de réparation par cible (§15.3) : autonome seulement si reproductible ; revue humaine signée pour un correctif de jugement ; humaine pour réglages et organisation | Arrêtée |
| D17 | Données de sécurité tierces = instantanés épinglés par digest, partagés par l'agent et l'instrument, rafraîchis par l'opérateur | Arrêtée |
| D18 | La genèse n'accorde aucune capacité : la cérémonie se fait en deux phases, séparées par le délai attesté de FLOOR-0 (1 h). FLOOR-0 n'est pas affaibli pour une démo | Arrêtée |
| D19 | Une évaluation T émise par l'opérateur est marquée auto-évaluée et affichée comme telle ; seule une évaluation par un évaluateur épinglé indépendant compte pour la production | Arrêtée |
| D20 | Périmètre : Python (`requirements.txt` épinglé), GitHub Actions, git, GitHub. Le reste est `uncovered` ou `NO_ROUTE`, visible (§15.4) | Arrêtée |
| D21 | La redevabilité reste dans le processus T pour cette version ; son isolation dans un worker confiné est reportée, la limite est déclarée | Arrêtée |
| D22 | Le produit se prouve d'abord en **git local** ; GitHub reste un adaptateur | En git local, « seule la garde déplace `main` » est tenu par deux utilisateurs Unix et vérifié par `qualify.py` ; sur GitHub il dépend de tokens, rulesets et d'une offre payante pour les dépôts privés. Les propositions de l'agent sur GitHub sont des branches `standard/proposals/*` (protégeables par ruleset) ; là où GraphQL est inaccessible, la garde fait le même CAS par `git push --force-with-lease=main:<base>` |
| D23 | **Produit souverain** : notre interface, nos serveurs git, nos agents, des LLM frontier par API seulement quand une recette ne suffit pas. GitHub n'est plus qu'un adaptateur facultatif | Trois chantiers. (1) **Hébergement** : les dépôts clients vivent chez nous ; les clients passent par une passerelle SSH (commande forcée) qui lit le dépôt canonique et n'écrit que dans une boîte de dépôt, sous `refs/heads/<identité>/*` ; `main` ne bouge que par le CAS de la garde. (2) **Interface** : une application web au-dessus de `surface/` ; aucune clé humaine sur le serveur (signature côté navigateur ou clé matérielle), sinon le quorum humain est du théâtre. (3) **LLM** : une seule porte d'egress, multi-fournisseurs, avec masquage des secrets et journal de chaque envoi (R15). Conséquence de périmètre : la cible GitHub Actions de D20 devient secondaire ; la CI qui exécute les tests est la nôtre et entre dans la TCB |
| D24 | Le travail d'un client entre dans `main` par une opération de la loi, `integrate`, jamais par un droit d'écriture | Même ligne d'effet que `remediate` (CAS de la garde, readback, preuve, lignée) ; condition `integrate-reviewed` = tests de `main` verts sur le code de la contribution + revue humaine signée de cette transition exacte. Un commit par contribution, directement enfant du `main` courant, pour que chaque commit de `main` reste la tête d'un effet jugé. Le relecteur doit être une autre personne que l'auteur : tenu par l'organisation (les identités de l'hébergement ne sont pas des humains de la loi), pas encore par le noyau |
| D25 | L'agent reçoit des **aides**, jamais des droits : constats localisés, verdicts du juge, bac à sable sans réseau, précontrôle de toute la loi, mémoire et budget, carte du dépôt, données de mise à jour, dossier du relecteur, porte LLM unique | Un agent qui oublie ses exigences en route est rejugé à chaque transition par la loi entière ; ces aides servent à ce qu'il réussisse du premier coup. Le précontrôle et le bac à sable ne prouvent rien : le juge reste séparé (§11.8) |
| D26 | Une contribution ne peut pas ouvrir de nouvel écart | `integrate-reviewed` exige aussi `regressions = none`, mesuré par le scanner en comparant chaque cible des floors entre `main` et la contribution. Le relecteur juge le sens du changement ; la loi garantit qu'il n'ajoute ni secret, ni faille, ni licence interdite, ni action non épinglée, même s'il les a manqués. Les suivis qu'une recette referme seule ne bloquent pas. L'agent applique la même comparaison dans son précontrôle |
| D27 | L'interface est une lecture plus un relais : aucune clé, aucune décision, signature dans le navigateur | Le serveur web est le composant le plus exposé ; il ne doit rien pouvoir faire qu'une personne n'ait signé elle-même. Il écoute localhost, sous son propre utilisateur ; le navigateur construit les octets qu'il signe (§11.9) |
| D28 | L'autonomie est **dite**, globalement et pour chaque élément, avec sa limite et la raison de cette limite ; chaque état d'exploitation dit la règle qui l'a décidé | Quatre niveaux : **autonome** (une preuve indépendante suffit : la correction se recalcule à l'identique), **supervisée** (la correction demande un jugement qu'aucun instrument ne prouve : une personne signe), **humaine** (ce qui est demandé n'est pas dans le code : une personne atteste), **observation** (Standard mesure mais la loi n'a aucune opération d'exploitation ; une telle opération passerait par la garde). Les états Opérationnel, Dégradé, En échec, Aucun trafic ont des seuils publiés (objectif de disponibilité, 5 % d'erreurs, p99 à 1 s, deux périodes pour une tâche) et chaque ligne affiche la valeur mesurée et le seuil franchi |
| D29 | Sur Run, chaque composant porte sa **frontière d'autonomie** à côté de son état : Voit, Prévient, Agit, Prouve, chacun avec sa raison ; un composant dégradé ou en échec que rien ne prend en charge est listé en tête comme **écart non couvert** | « Opérationnel » ne dit rien si l'on ignore ce qui se passe quand ça cesse de l'être. Aujourd'hui Standard voit tout (13 sur 13) mais ne prévient personne, n'agit pas en production et ne prouve rien de l'exploitation : la personne doit le savoir, composant par composant |
| D30 | **Prévenir, agir, prouver en production.** Prouver : le scanner lit les mêmes métriques que la console (`bt/runtime.py`, mêmes règles, partagées) et signe `run:sources:all coverage` et `run:service:all slo` (`met`, `breached:N` ou `uncovered`, jamais « bien » par défaut ; les services externes sont montrés mais non comptés). Agir : opérations `deploy` (`run:release:all/{from}/{to}`) et `rollback` (`run:service:all/{from}/{to}`), exécutées par la garde (`bt/deploy.py` : lien `current` basculé par renommage atomique sous verrou, compare-and-swap sur `from`), chacune autonome seulement sur un fait signé de cette bascule exacte : `deployable = yes` (la tête de main, jamais retirée) et `regressed = yes` (l'objectif casse moins de 30 min après la bascule et la version remplacée l'avait tenu). Une version retirée n'est jamais redéployée : l'écart `run-live` va aux personnes. Prévenir : dans l'interface seulement (page Alertes, bandeau, badge, titre d'onglet) ; une alerte se prend en charge par une signature `ack = taken` faite dans le navigateur et gardée au journal | La production était vue mais ni prouvée ni réparée. Les mêmes principes que le code s'y appliquent : un fait indépendant ouvre le droit, la garde exécute par compare-and-swap, l'oracle relit et prouve. Pas d'e-mail ni de messagerie pour l'instant, par choix : la preuve qu'une personne a été prévenue est sa propre signature, pas un reçu de livraison |
| D31 | **Les ingénieurs règlent la production, et la production est vérifiée de l'extérieur.** Réglages (page « Objectifs et réglages ») : objectif de disponibilité, seuil d'échec, p99 maximal, fenêtre, retard des tâches, globalement et par composant (y compris le compter ou non dans l'objectif signé) ; autonomie (mise en production, retour arrière et son horizon, redémarrage et son budget horaire, retour à travers une migration compatible) ; sondes externes. Chaque réglage est une signature `run:policy/<portée>/<clé>` sous le droit `engineer`, gardée au journal ; T ne lit que ce droit (`bt/policy.py`). **Plus strict : immédiat ; plus souple : après le délai témoigné de la loi**, affiché en attente. Les bascules que l'ingénieur garde pour lui passent par la loi : `deploy-reviewed` (`candidate` du scanner et `approved` de l'ingénieur), `rollback-reviewed` (`previous` et `requested`), `restart` autonome (`restartable`, hors bascule récente et dans le budget) ou demandé. Prouver la mise en production, c'est prouver **la version servie** (`build_info{version}`) et, pour un redémarrage, un processus plus récent que la demande. Un retour ne va qu'à une version déjà en production, jamais à une version retirée, jamais à travers une migration non déclarée `.compatible.sql`. Le lanceur du produit (`runtime/runner.py`) bascule sans coupure et seulement vers une version qui répond à sa santé ; une version qui ne démarre jamais déclenche le retour | Un objectif imposé ne convient à aucun produit réel, et un produit qui se déclare sain ne prouve rien. La forme suit la loi : le réglage qui ouvre un droit est signé, un relâchement attend, et ce qui est servi se mesure plutôt que ce qui est pointé. Restent hors champ : capacité, sauvegardes et restauration, secrets et configuration, logs et traces, e-mail et messagerie |
| D32 | **Des réglages d'ingénieur, pas seulement des seuils.** SLO à budget d'erreur (`bt/slo.py`) : indicateur de disponibilité ou de latence sous un seuil, sélection de composants, cible, fenêtre glissante en jours, sur des comptes par minute gardés 90 jours ; budget restant et consommation sur 5 min, 30 min, 1 h, 6 h. Alertes multi-fenêtres : rapide (1 h et 5 min au-dessus de `burn_fast`, 14,4 par défaut) qui rompt l'objectif signé, lente (6 h et 30 min au-dessus de `burn_slow`, 6) qui prévient ; un composant compté en échec rompt aussi, un composant dégradé prévient seulement. Politique de mise en production : stratégie directe ou canary (part du trafic, durée d'essai, écart d'erreurs toléré, requêtes minimales ; le lanceur envoie la part au canary et mesure chaque version devant elles, le scanner compare, puis `deploy` promeut ou `abort` retire, une version retirée ne revient jamais), fenêtres de jours et d'heures avec fuseau, gel manuel, gel sous un reste de budget. Silences de maintenance (signés, qui ne changent aucun fait). Aperçu d'un SLO sur l'historique enregistré avant de le signer. Réglages en code : le document complet, comparé et signé changement par changement, chacun classé plus strict ou plus souple | Un ingénieur raisonne en SLO, en budget et en consommation, pas en seuils instantanés ; il veut choisir comment une version arrive et quand. Tout reste sous la loi : chaque réglage est signé, un relâchement attend, chaque bascule est un fait indépendant exécuté par la garde |
| D33 | **Deux trous fermés.** (1) Pour mesurer « tests », le côté de confiance exécutait le code d'une contribution sous l'utilisateur de la garde, qui lit les clés : une contribution hostile pouvait signer n'importe quoi. Ce code tourne désormais sous un compte sans clé ni groupe de la garde (`[tests] runner_user`, via `sudo -n -u … env -i`), dans un espace de noms sans réseau (`unshare -rn`), sous limite mémoire, sur une copie du dépôt (`bt/isolation.py`) ; la qualification le vérifie (T06). (2) Les conditions exigeaient un fait indépendant de l'acteur, pas un fait de l'instrument : un relecteur pouvait signer lui-même « tests au vert ». Les faits qui ouvrent un droit (tests, régressions, reproduction, acceptation, faits de production) sont maintenant des **instruments épinglés** dans les planchers : le noyau ne les admet que comme mesures du scanner (méthode, couverture, fraîcheur), le second juge aussi | Deux promesses centrales (« un agent ou un client compromis ne peut rien signer », « une personne ne remplace pas une mesure par une opinion ») ne tenaient pas ; le noyau avait déjà le mécanisme des instruments, inutilisé |
| D34 | **Construire sous la loi.** Une demande est une ressource typée (`request` : proposée, contrat signé, livrée, retirée). Son contrat est un fichier de tests d'acceptation écrit par une personne avant tout code, gardé par son empreinte. Le contrat ne se signe que si le scanner a vu chacun de ses tests échouer sur main (un test qui passe déjà ne promet rien). L'agent implémente (code seulement, jamais un test, le contrat recopié à l'octet), vérifie dans son bac à sable, propose ; l'op `implement` exige acceptation au vert sur cette transition exacte, tests de main au vert, aucune régression et une revue signée. Un contributeur peut aussi implémenter (même contrat, trailer `Standard-Request:`). La demande est livrée quand main passe le contrat (`accepted`), et l'agent l'enregistre | Ce que la loi ne savait pas vérifier (« le changement fait ce qui était demandé ») devient un fait mesuré contre un contrat signé, avec la même chaîne que la maintenance. Limites : sans modèle configuré, l'agent n'implémente pas ; un contrat ne couvre que ce que ses tests disent |
| D35 | **Les règles dans le dépôt ; la loi borne le jugement du scanner.** `standard/rules.json` sur main est la source de tous les réglages sauf les silences : on le change par une contribution relue, ou depuis l'interface en signant une fois le nouveau fichier (l'agent le commit à l'identique, le scanner vérifie que seul ce fichier change et que l'empreinte est celle signée par un ingénieur pour ce main, l'op `configure` l'intègre). Le noyau gagne un atome `compare` (comparaison décimale exacte, recalculée par le second juge) : les planchers bornent de l'extérieur ce que le jugement du scanner peut ouvrir (canary : au plus 2 points d'erreurs de plus, au moins 20 requêtes et une minute ; retour arrière dans les 240 min ; pas de 12e redémarrage dans l'heure) | Git pour l'ingénieur, le journal pour l'auditeur, un clic pour la personne pressée. Le jugement fin reste côté confiance (réglages plus stricts), mais un défaut de ce code ne peut plus dépasser les bornes que le noyau vérifie. La base de confiance n'a pas rétréci : la partie production est passée à 1 205 lignes |
| D36 | **Le scanner mesure, la loi borne, l'agent se retient.** Le scanner ne juge plus rien de réglable : il signe ce qui est sur chaque bascule exacte (`candidate`, `previous`, `proven`, `live`, `running`) et des nombres (`burn_fast`, `failing_pct`, `switched_min`, `unanswered_s`, `restarts_last_hour`, `migrations_crossed`, `budget_pct`, deltas du canary). Les floors fixent la preuve minimale pour agir seul (§12), comparée par le noyau. Les réglages des ingénieurs passent dans U (`agent/policy.py`) : l'agent les applique avant de soumettre, et ils ne peuvent qu'exiger plus que la loi. Le délai sur les assouplissements de D31 disparaît des réglages : il reste là où il garantit quelque chose, sur la loi et les capacités (resserrer, révoquer, geler : tout de suite ; élargir : après le délai témoigné) | La production était 1 205 lignes de jugement non relu dans la TCB, dont 320 de réglages et ~150 de décisions qui ouvraient des droits. Un défaut dans la retenue de l'agent ne donne plus que ce que la loi permet déjà ; un défaut du scanner reste possible, mais sur des mesures, plus simples à vérifier qu'un jugement. Prix : un ingénieur qui assouplit un réglage, dans les bornes de la loi, est suivi dès l'intégration |
| D37 | **Hôte générique : les mesures sont des programmes épinglés et rejouables, les effets des registres.** T ne contient plus aucune mesure : un hôte générique résout les entrées par leur identité, exécute un paquet de programmes (`instruments/`) épinglé par empreinte dans les floors sous l'exécutant isolé, garde chaque enregistrement (entrées par empreinte, réponse) et le scanner signe ce que le programme répond, avec la méthode `programs@<empreinte>` et l'enregistrement en artefact. Le monde réel entre par des relevés bruts, datés, gardés par empreinte, que le programme lit. Les bascules de production deviennent des registres déplacés par compare-and-swap ; le lanceur du produit construit lui-même ce qu'il sert. `tools/replay.py` rejoue n'importe quel enregistrement ailleurs ; les plafonds numériques associés ont été retirés par D39, sans retirer les mécanismes de contrôle | La confiance passe de « ce processus a dit vrai » à « cette fonction figée, que chacun peut recalculer, a répondu ceci à ces entrées ». Ajouter une mesure ajoute un programme, jamais une ligne de T (démontré par l'analyse canary ci-dessous : un changement de mesure sans toucher T). Restent dans T et non vérifiables par rejeu : l'honnêteté du relevé (l'hôte a récupéré ces octets), la vérité de la source (le produit dit ses propres métriques), l'exclusivité des effets (T07) ; un programme épinglé faux produit un fait faux que le rejeu ne révèle pas (il recalcule la même erreur) : sa relecture reste nécessaire |
| D38 | **Transactions de frontière.** Toute interaction de T avec le monde extérieur est une BT (OBSERVE, EFFECT, RESOLVE) sous un contrat des floors, enregistrée avec identité, sujet, autorité, contrat, matériel, causalité et issue (§10.1). Chaque job ne signe que ce que son contrat permet, et la méthode d'une mesure nomme le contrat, que le noyau vérifie ; chaque opération exige un profil physique (`cas`, `observable`) ; RESOLVE établit `not_applied` par l'état pour un `cas` local et jamais par le silence pour un effet `observable` ; la preuve du but reste distincte de l'application | La revue BT a montré trois trous : un programme compromis avait toute l'autorité du scanner ; le redémarrage était présenté comme un compare-and-swap alors que le produit l'exécute ; les privilèges réels n'étaient pas comptés. Coût : T passe de 2 039 à 2 253 lignes, une fois, pour des mécanismes génériques ; ajouter une mesure ou un effet n'en ajoute toujours aucune. Corrigé au passage : `canary` et `abort` n'étaient jamais relus (T08) |
| D40 | **Socle invariant et travail extensible.** Une seule surface de loi effective et de capacités publiques nourrit la maintenance et BUILD ; une route absente ouvre une recherche informative sous la même obligation. Lecture/recherche, sources HTTPS configurées, expérimentation isolée et scopes de réparation génériques sous revue | CI main raccordée, rapports vides/ignorés/incohérents refusés, qualification liée à la genèse. Aucun outil de l’agent ne s’inscrit seul comme instrument ni ne ferme une dette ; conditions de confiance et limites décrites en §20.5. |
| D39 | **Socle K / BT / instruments et composants communs de Standard, sans plafonds de lignes.** Le noyau et ses bornes constitutionnelles restent inchangés ; l'assemblage privilégié et le scanner de Standard sont dans `runtime/`, les floors actuels dans `catalog/floors.py`. K et BT ne dépendent pas de l’assemblage de Standard. Les adaptateurs Git sont regroupés. `make layers` contrôle les frontières, pas un nombre de lignes | Le déplacement ne réduit pas la TCB effective : l'empreinte d'installation inclut le runtime privilégié et les floors. Les anciens journaux ne sont pas réinterprétés avec la nouvelle release ; pas de migration de genèse implicite. La lecture du code et les limites restantes sont consignées en §20.1. |
| D41 | **Surface de loi fidèle à la redevabilité.** L'état « tenu » de l'interface, du drift et de la carte vient des preuves et obligations du pli de redevabilité ; les findings localisent et expliquent, ils ne prévalent pas sur la dette. Un paquet JSON versionné alimente les modèles. La patrouille LLM s'exécute uniquement dans U avec lecture/recherche, et ses soupçons restent des notes. Les mécanismes recouvrant une cible déclarent leur méthode et leur autorité (§20.5) | Motif et falsificateur : un finding `green` avec obligation encore ouverte ne doit plus afficher « tenue » ou « auditable » ; une cible `ci` doit pointer vers son probe enregistré et non vers un instrument fictif. Aucun droit nouveau n'est créé, aucun fait n'est signé par une vue. Lier atomiquement findings/settings/préfixe, valider humainement un binding persistant et lancer la patrouille depuis le web restent ouverts. |
| D42 | **Un modèle de lecture dérivé, sans nouveau juge.** `context/model.py` assemble la loi effective entière et les relations vers ressources, routes, programmes, faits, diagnostics, code candidat, réglages et références externes. Drift, carte, contexte agent, CLI, web et inventaire statique réutilisent ses interprétations communes. Motif : réduire les reconstructions divergentes. Falsificateurs : santé et loi de heads différents, finding d'un autre commit classant la dette courante, ou référence OWASP affichée couverte sans lien validé. `bt/service.py` refuse une vue mixte ; chaque relation nomme son origine et son statut. Impact confiance : lecture uniquement ; ni le juge, ni son vérificateur indépendant, ni les droits, ni la chaîne d'admission ne consultent ce modèle. Restent ouverts : snapshot atomique multi-source, revue humaine de liens précis, correspondances externes contrôle par contrôle. |
| D43 | **Lectures BUILD/RUN et configuration sans parseur parallèle.** Les vues BUILD/RUN interrogent le même `ReadModel`, puis `surface/views.py` les projette et fait leurs lectures Git sans pouvoir d'admission ; `web.py` garde la passerelle, les fichiers d'entrée, l'HTTP et la signature relayée. La vue des objectifs et sa logique de signature sont isolées dans `static/objectives.js`, sans changement des API. Les configurations passent par le parseur TOML standard ; l'ancien support `tomli`/Python 3.9-3.10 est remplacé par D44. Motif : éviter les divergences de lecture et les rejets de TOML valide. Falsificateurs : une chaîne contenant `#` est tronquée, une demande BUILD lit une autre base que le modèle, ou une obligation humaine ouverte apparaît « en mesure ». Impact confiance : aucun nouveau droit ; le noyau, le checker et les contrats d'enveloppe restent inchangés. Les collectes de télémétrie et les bindings de code vérifiés ne sont pas unifiés par cette décision. |
| D44 | **Frontières U et release.** Python 3.11+ permet `tomllib` sans shim local. Chaque source Python de l'assemblage privilégié fait varier le digest ; les programmes de mesure restent épinglés séparément par `PROGRAMS`. Le précontrôle refuse l'exécution si son jail réseau/fichiers est indisponible ; les dépendances exactes sont téléchargées comme roues, puis installées et démarrées dans le jail. Une nouvelle genèse est requise pour une nouvelle release ; aucun journal ancien n'est réinterprété. Limite : l'isolation physique doit être qualifiée sur Linux et l'empreinte calculée après import ne prouve pas le code effectivement chargé. |
| D45 | **Portée conformité et progrès non souverains.** Les portées ISO/DORA/NIS2 sont des déclarations `coarse` épinglées dans les floors, hors loi effective ; leur lecture ne peut pas produire `satisfied` ni certifier un contrôle. OWASP reste sans mapping. Le Work Engine conserve les issues et raisons des tentatives ; PF ne compte que l'abandon d'une réparation encore ouverte avec route disponible. Ces lectures n'ouvrent aucun droit. |

| D46 | **Personnes et code candidat, fermés par défaut.** (1) Une décision gardée pour les personnes (`review`, `approved`, `requested`) ne compte que signée par un humain de la racine en vigueur : l'atome `observed` accepte un quatrième argument, le genre de l'auteur du fait, tiré de la liste fermée de FLOOR-0 ; noyau et second juge le calculent chacun. (2) Sans exécutant isolé, aucun code candidat ne tourne ; une démo peut l'accepter explicitement (`[tests] unconfined`), jamais une installation de production | Falsificateurs : un `review = approved` signé par le scanner ouvrait `remediate-reviewed` ; une installation sans `runner_user` exécutait une contribution sous l'opérateur. Impact confiance : la loi exprime enfin la promesse D16 ; T06 échoue fermé. Nouvelle genèse requise (floors et noyau changent) |
| D47 | **Second juge plus indépendant, une seule enveloppe par énoncé.** Le second juge reçoit les floors de la release et vérifie la contenance de chaque loi effective ; il restate `HIST.AHEAD`, `retry_of`, `when`. Base64 canonique, DER strict et s bas pour ECDSA. Une mesure plus ancienne ne remplace jamais une plus récente. Une violation `escalate` se ferme par un humain. Différentiel aléatoire en CI | Falsificateurs : loi effective affaiblie acceptée par le second juge ; même énoncé, deux têtes ; lecture ancienne gagnante. Limite : le différentiel est une campagne bornée, pas une équivalence prouvée |
| D48 | **Instruments que le sujet ne pilote pas, effets durables.** Exports par objets (pas `git archive`), non-régression par comparaison de mesures, `regressions` exigé en revue, liens symboliques déclarés, verrou exempt de dépendance mesuré, registres fsync, rejeu comparé au journal | Falsificateurs : `export-ignore` cachait un fichier ; un constat échangé contre un autre passait ; un crash entre historique et registre laissait un `ok` sans mouvement |
| D49 | **Clôture de release et coût constant.** Les dépendances sont épinglées par hash (`requirements.hashes`) et entrent dans l'empreinte d'installation ; installations et CI installent avec `--require-hashes`. Les lectures et écritures du journal ne copient plus profondément les énoncés : 6 à 8 ms par écriture de 0 à 20 000 entrées mesurés, au lieu de 10 → 55 ms à 4 000 | Limite : la clôture est calculée pour Linux x86_64 et Python 3.11+ ; une autre plateforme régénère le verrou (`make lock`) et le relit |
| D50 | **Témoins configurables** (remplacée par D61). `[clock] kind = "witnesses"` assemble `WitnessClock` (HTTPS, quorum, `tolerance_ms` borné à 5 s, état persisté). La lecture retourne la cotation la plus tardive : prudente pour toutes ses utilisations (fenêtre de départ, expirations, horizon), les délais d'élargissement restant sur les checkpoints témoignés | Limite : l'indépendance réelle des témoins reste une propriété à qualifier |
| D51 | **Une personne, un agent, les règles du jeu.** FLOOR-0 descend à un humain, un témoin, aucun délai ; un élargissement prend effet avec sa propre entrée (les options d'équipe sont retirées par D61). F0-12 : chaque opération déclare ses routes ; la route humaine porte `decision = approve` par un humain ; une loi coupe des routes autonomes, jamais l'humaine. Réglages, règles et loi ne font qu'un document client signé (`routes`, `settings` liés par `@nom`, bornés par le socle) ; `standard/rules.json`, `configure`, la sentinelle, `flag`, `heartbeat`, les profils, `compliance_officer`, les cibles organisationnelles et la projection de conformité sont retirés. L'humain a trois gestes : oui, non (gel), règles | Arrêtée |
| D52 | **L'agent est une boucle sur les coups.** `moves.py` est la lecture commune (agent et humain) : statut, route, file. `loop.py` joue ce qui est prêt ou décidé sous une seule capacité ; ses producteurs (réparation, construction) n'écrivent que des candidats. Les tactiques ne font que retenir. Deux nouveaux faits du scanner : `scoped` (une seule définition du périmètre d'écriture, `instruments/scope.py`) et `window` (fenêtre de mise en production lue dans les règles en vigueur) | Arrêtée |
| D53 | **Une cérémonie, l'horloge de l'opérateur.** Identités `human`, `agent`, `guard`, `scanner`, `oracle`, `clock` ; capacités `scanner`, `oracle`, `agent`, `human` ; genèse signée par l'humain, ancre par `clock` tant que la loi ne demande pas plus de témoins ; `[clock] kind = "witnesses"` reste l'option d'équipe (au moins deux). `qualify.py` : T02 « l'humain détient sa propre clé », T03 « temps » selon le quorum rejoué | Options de témoins remplacées par D61 ; seul le temps de l’opérateur reste courant |
| D54 | **Le catalogue de règles comme données.** 156 règles tirées d'OWASP ASVS 5.0 (345 exigences toutes rendues ou écartées avec raison), CWE Top 25 2025 et la liste de lancement SRE ; format unique pour tous les langages ; mots vagues remplacés par des valeurs nommées à défaut strict ; partie de l'empreinte de la release. Identité par un fournisseur OpenID Connect : les règles de mot de passe, MFA, réinitialisation et énumération vivent dans sa configuration ; les règles de serveur d'autorisation deviennent une seule règle, NO-OWN-AS | Arrêtée |
| D55 | **Les blocs.** 13 blocs Python (FastAPI d'abord) et un kit front JS, épinglés dans la release ; interdits vérifiés sur l'arbre syntaxique ; fait `blocks` exigé par les routes autonomes `scoped` et `accepted`, la route humaine inchangée ; une copie d'un bloc dans le produit casse | Arrêtée |
| D56 | **Sondes et couverture.** Sondes de Standard sur l'application du produit (`@app`), dans un processus séparé ; une cible par catégorie de règles ; dette = enfreinte ou non mesurée par manque de déclaration ; patrouille et lacunes de la release visibles, jamais dette ; adoption d'un bloc = dette, pas refus | Arrêtée |
| D57 | **Ancien ordonnancement des trois passes** | Remplacé par D62 ; sélection des règles conservée, générations fixes retirées |
| D58 | **La console des règles.** Couverture par catégorie et par règle ; matrice d'accès signée d'un seul geste ; valeurs nommées éditées et signées dans les règles du jeu ; CLI `coverage` et `rule` | Arrêtée |
| D60 | **Au-delà des référentiels.** Les blocs rendent les erreurs impossibles à écrire, bornent tout, ferment les contournements connus, échouent fermés, ne s'étendent que vers plus strict et versionnent ce qu'ils stockent ; même durcissement sur FastAPI et Next.js ; sessions et limites dans un magasin partagé ; `blocks/HARDENING.md` | Arrêtée |
| D61 | **Plus d'options d'équipe.** La racine tient exactement un humain (jusqu'à huit clés) et au moins un témoin ; plus de seuil, de propositions, de délais, d'activation ni de veto (genres `activate` et `veto` retirés) ; la loi n'a plus de sections `delays` ni `witnesses` ; le temps vient de l'horloge de l'opérateur seule (`bt/clock.py` retiré) ; T09 et son outbox (`bt/delivery.py`) sont retirés, les escalades restent visibles dans la console. Le second juge restate les mêmes règles | Arrêtée |
| D59 | **Deux piles, un contrat.** Un contrat par bloc, une implémentation FastAPI et une Next.js (web, session, access, input d'abord) ; adoption due par pile et seulement pour les blocs que la pile possède ; détection des points d'entrée Next par emplacement ; sondes HTTP quand `@app` est une URL ; les blocs JS sont épinglés dans la release | Arrêtée |
| D62 | **Un constructeur, deux reviewers, une patrouille de simplicité.** Contexte sélectionné sur la base et le brouillon ; lecteurs parallèles sans écriture ; corrections bornées et revues renouvelées ; suppressions explicites sous périmètre ; propositions exploratoires sans autorité. Pannes de mesure visibles et couverture des catégories dynamiques raccordée. Détails et limites en §4.9 et §11.8.1 | Implémenté ; les tests locaux ne qualifient pas une installation ni les performances d’un vrai modèle |
| D63 | **Catalogue commun des exigences.** Cibles, paramètres signés et contrats techniques définis dans le catalogue ; compilation vers la loi existante ; contexte borné commun aux missions et déclarations complètes accessibles par les outils de lecture existants. Dossiers dérivés du contexte, exploration unique avec question/périmètre. Suppression des niveaux de passes et des assemblages parallèles. K/BT et les conditions d’admission restent distincts ; les garanties des blocs ne valent pas preuve d’adoption | Implémenté ; validation locale, sans qualification physique ni démonstration avec un vrai modèle |
| D64 | **Retrait des chemins résiduels.** Un seul parcours de construction par modèle, revues comprises ; valeurs issues du contexte signé ; projection commune des fonctionnalités déclarées pour scanner et missions ; sélection de catégorie/vérificateur dans le catalogue ; même définition de mission patrol pour surface et exécution. Les champs de contexte portent les mêmes noms dans la console et chez l’agent, sans anciens alias | Implémenté ; cas de cohérence et de refus vérifiés, qualification physique distincte |
| D65 | **Responsabilités et parcours communs.** Dossiers à la racine par rôle ; contexte partagé hors agent ; précontrôles communs ; une file d’obligations sans partition BUILD/RUN ; collecte de production unique par BT et publication limitée aux captures de métriques ; surface dérivée, sans collecte de repli. Migration des délais, tentatives, leases et historique ; aucun ancien paquet ou alias de compatibilité | Implémenté ; validations fonctionnelles et de refus, qualification physique distincte |
| D66 | **Standard consomme ses blocs aux frontières compatibles.** Motif : supprimer les clients HTTP parallèles de U et les parseurs permissifs sur les entrées non fiables. Modèles, recherche et rafraîchissement des métadonnées utilisent l'entrée synchrone du bloc outbound existant ; HTTPS, aucun proxy ambiant ni redirection, DNS vérifié à la connexion, réponses et durée bornées. Clés des modèles lues par le bloc runtime, conservées en `Secret` ; JSON externe et propositions stricts ; console : JSON POST strict et logs structurés sur stderr. Falsificateurs : une redirection reçoit le secret du modèle, une clé JSON dupliquée atteint l'admission, un secret typé devient une marque masquée avant son envoi, une entrée signée est normalisée, ou un bloc importe l'autorité. Impact confiance : aucun changement dans K/BT, instruments ou conditions d'admission ; dépendances déjà verrouillées, code des blocs déjà épinglé. Paramètres des services Standard issus de la configuration opérateur, distincts de la loi du produit. Les imports sont directs depuis les sources, sans copie ni façade. | Adoption ciblée implémentée et testée ; ce n'est pas une conformité globale. La console HTTP/DOM n'utilise pas le guard ASGI complet ; processus Git/jail, preuves et cryptographie physique gardent leurs contrats spécifiques. Nouvelle empreinte de release ; aucune qualification physique ni exécution avec un vrai fournisseur revendiquée |

| D67 | **Python ne signifie pas FastAPI.** Motif : les scripts et agents Python étaient classés FastAPI par leur extension, alors que neuf blocs ne dépendent pas de ce framework. Définitions `.python` génériques et `.fastapi` pour les intégrations ; héritage résolu une seule fois dans le catalogue, puis transmis comme données inertes aux instruments et aux missions. Dépendances web regroupées dans l'extra `[web]` du paquet 0.3.0 ; les helpers ASGI de runtime/render sont nommés explicitement. Falsificateurs : un CLI reçoit une API FastAPI, un produit FastAPI perd la protection outbound, ou une primitive ne peut être importée sans le framework. Impact confiance : K/BT et conditions d'admission inchangés ; modification des programmes épinglés de détection/couverture et de l'empreinte de release. | Correction implémentée et vérifiée ; revue des blocs consignée en §20.7, sans prétendre avoir corrigé ces écarts ni qualifié leur déploiement |
| D68 | **Les invariants transversaux sont imposés par la plateforme, plus par l'adoption de blocs.** Motif : les cinq écarts de §20.7 viennent tous d'une propriété transversale réimplémentée bloc par bloc, et le scanner constate l'adoption sans pouvoir l'imposer. Le produit tourne dans un bac (conteneur OCI exécuté par crun : réseau vide, groupes de contrôle, seccomp en liste d'autorisation, fichiers en lecture seule) ; passerelle d'entrée unique portant la session OIDC, proxy de sortie transparent, courtier de secrets, service de clés, proxy Postgres avec Row-Level Security (§4.10). Restent en blocs : access, render et front (le code du navigateur). Chaque règle déclare qui la tient (`held_by`). Le produit écoute sur la boucle locale privée de son bac, reliée par la plateforme ; l'identité lui arrive en jeton court signé, vérifié par le bloc access. La plateforme fait partie de la release (les deux hébergements l'exécutent) et une seule définition du bac sert au précontrôle, aux tests et à la production. Standard écrit la politique et réutilise les mécanismes éprouvés (crun, profil seccomp de Docker, pasta, Pingora, oauth2-proxy, OpenBao, RLS de Postgres). Falsificateurs : un processus du bac atteint le réseau hors du service de sortie ; une valeur de secret apparaît dans le bac, dans un journal ou dans une sortie vers un autre hôte ; une requête dépasse `@request_timeout_s` sans réponse de délai ; deux clés en collision après normalisation atteignent le produit ; une requête lit ou modifie une ligne d'un autre propriétaire ou locataire ; un en-tête d'identité non posé par la passerelle atteint le produit. Impact confiance : K, T, second juge et admission inchangés ; plateforme hors K+T, mesurée par des sondes de T ; elle devient la base de confiance du produit. Remplace D60 et D67 pour les blocs absorbés ; les corrections de §20.7 deviennent caduques à la bascule | Arrêtée ; étape 1 livrée (bac OCI de l'agent, 14 murs mesurés), voir §4.10 |
| D69 | **Un mur, deux lectures, et la carte des capacités.** Motif : un mur qui se contente de refuser n'apprend rien à l'agent, et un mur qui explique tout livre la carte des défenses. Il n'y a qu'un mur, le bac de D68 ; la pédagogie est une lecture de ses refus. Chaque mission reçoit la carte des capacités, dérivée des mêmes données que les murs. Un refus qui correspond à une capacité absente de la carte est une leçon pour l'agent, avec un enregistrement qui n'en dit jamais plus que la carte ; un refus qu'aucun code ordinaire ne provoquerait est une alarme pour le contrôle caché. Rien ne s'élargit automatiquement : l'agent rédige une valeur, l'humain la signe (§4.11). Falsificateurs : un enregistrement nomme un mécanisme, une règle ou un seuil absent de la carte ; une tentative d'évasion produit une leçon au lieu d'une alarme ; une capacité s'élargit sans signature humaine ; la carte et les murs divergent. Impact confiance : carte, traducteur et enregistrements hors base de confiance du produit ; seul le bac porte les invariants de D68 | Arrêtée ; carte des capacités et leçons du précontrôle livrées, alarmes et refus de production à faire |
| D70 | **La matrice de retour.** Motif : les sources de retour se multiplient (mur, tests, lint, SAST, scanner, sondes, passerelle, proxy, RLS, courtier) sans endroit qui les ordonne. Une seule voie de retour : règles × moments (avant de coder, construction, admission, production), un format unique, un filtre (déduplication, ordre, divulgation bornée, routage leçon/fait/alarme/besoin, budget). Chaque règle a une force (fait mesuré, mur en place, contrôle statique, patrouille) consignée dans la release ; aucune source ne se retire sans une source au moins aussi forte (§4.12). Falsificateurs : deux retours pour la même règle au même endroit ; une alarme atteint l'agent ; un retour en dit plus que la carte ou le contrat ; la force d'une règle baisse sans que les tests le refusent ; une nouvelle source contourne le filtre. Impact confiance : aucun ; la matrice et le filtre sont hors TCB, les faits restent jugés par K | Arrêtée ; matrice, filtre, dossier du précontrôle et plancher livrés ; admission et production à brancher |

**Restent ouverts** (empiriques, à trancher par mesure, pas par discussion) : fournisseur de chaque T en production ; preuve d'indépendance des domaines de restauration ; primitive d'idempotence par fournisseur au-delà de GitHub ; langage final de la TCB.



---

## 19. Hébergement et exploitation de Standard

- **Même protocole, deux hébergements.**
  - **Dépôt seul** : K/T tournent dans un processus opérateur distinct sur l'infrastructure du client. Les garanties physiques sont celles des T qualifiés de cette installation. Un état qui voyage par branches Git n'est **pas** une ancre durable (T04) : ce mode exige un pin store externe pour revendiquer G11.
  - **Service géré** : le produit commercial. Mêmes objets, même admission, même journal ; T qualifiés et opérés par Standard.
- **Interface native** : WorkItems, décisions humaines, couverture, escalades. Les empreintes et protocoles restent accessibles pour l'audit, pas comme UX principale.
- **Objectif double** : séduire un investisseur, rester crédible devant des ingénieurs de haut niveau. D'où la règle : chaque affirmation publique porte son statut (§0).

### 19.1 Deux processus, une installation

| Processus | Commande | Ce qu'il détient | Ce qu'il ne voit jamais |
|---|---|---|---|
| **Opérateur (K + T)** | `python -m runtime serve standard.toml` | Journal, pins, clés de la garde, des instruments, de l'oracle ; jeton fournisseur ; passerelle | Clé de l'agent, clé API du modèle |
| **Agent (U)** | `python -m agent run standard.toml` | Sa propre clé, son dépôt de propositions, la clé API Claude | Journal, pins, clé de la garde, jeton d'écriture |
| **Interface** | `python -m surface.web standard.toml` (utilisateur `standard-web`) | Rien : lit la vue, relaie des enveloppes signées dans le navigateur | Toute clé |
| **Exécutant** | `standard-runner`, appelé par la garde via `sudo -n -u standard-runner -- /usr/bin/env -i …` | Rien : exécute le code des contributions, sans réseau | Clés, journal, réseau |
| **Produit** | `runtime/runner.py DEPLOY PORT --repo CANONIQUE` (utilisateur `standard-demo`) | Ses données (`/srv/standard/data`) ; lit les registres, exporte lui-même le commit nommé depuis le dépôt canonique (lecture seule) et le sert | Le droit de déplacer un registre (la garde écrit `deploy/`). Démo : il lit le dépôt par le groupe de la garde, comme l'interface et la passerelle ; en production, par une lecture de la passerelle |
| **Humains** | `python -m surface review / attest`, ou l'interface | Leur propre clé | Tout le reste |

À chaque passe, l'opérateur fait témoigner le temps (démo seulement), mesure `main`, les propositions, les contributions et les demandes, mesure la production (sources, SLO, canary, version servie), fait partir les effets admis, réconcilie et prouve. L'agent projette les dettes, fabrique ses propositions et soumet ses intentions.

**Configuration** (`standard.toml`, sections ajoutées après la cérémonie) :

| Section | Clés | Effet |
|---|---|---|
| `[run]` | `metrics` (URLs Prometheus), `slo`, `base_url`, `interval`, `store` | Sources capturées par BT ; `store` et `interval` règlent uniquement le cache et le rafraîchissement de l’interface |
| `[deploy]` | `root`, `runner_metrics`, `restart` | Répertoire des releases que seule la garde bascule ; métriques du lanceur pour l'analyse canary ; commande de redémarrage. Sans `[deploy]`, Standard n'agit pas en production |
| `[tests]` | `install`, `runner_user`, `unconfined` | Installer les dépendances de test (wheels seulement) ; utilisateur isolé qui exécute le code des contributions ; sans `runner_user`, aucun code candidat ne tourne, sauf `unconfined = true` en démo (D46) |
| `[clock]` | `kind` | `local` : l'horloge de l'opérateur, signée par `clock` (D61) |
| `[build]` | `store` | Magasin des demandes et contrats, par digest (défaut `requests/`) |
| `[hosting]` | `config`, `gate_user` | Hébergement des dépôts clients, vérifié par `qualify.py` |
| `[llm.small]`, `[llm.frontier]` | `kind`, `model`, `key_file` | Porte LLM de l'agent |

Les réglages de comportement vivent dans le document client de la loi effective, notamment `settings`. L’interface en prépare une nouvelle version ; l’humain signe une entrée `law`, immédiatement en vigueur. `standard.toml` assemble l’installation et ses budgets opérationnels ; il n’accorde aucun droit. Le fichier `standard/rules.json` et l’opération `configure` sont retirés.

### 19.2 Laboratoire remplaçable

Le workspace et GitHub sont la source du code. Le VPS est un banc d'essai jetable, sans données client. Depuis un checkout propre du commit poussé, en root, `bash tools/install_server.sh` remplace l'unique installation de laboratoire dans `/opt/standard` et `/srv/standard`. Ces deux chemins sont refusés s'ils existent sans le marqueur `.standard-laboratory` ; les autres chemins et services ne sont pas effacés. L'installateur ne modifie ni SSH ni le pare-feu. Il installe les dépendances système, les rôles Unix et une copie immuable du commit, puis crée une nouvelle genèse. Un changement K/T ne réinterprète donc jamais le journal précédent. L'ancien état de laboratoire est volontairement perdu ; sauvegarder tout état intéressant avant le remplacement.

Le dépôt canonique `lab` part d'un commit Git vide sur `main` : aucun produit, métrique RUN, trafic artificiel, clé LLM ou client n'est créé. La cérémonie actuelle garde les clés humaines et témoins simulés sur le VPS et s'auto-évalue ; le runtime l'identifie par `demo = true`, l'interface l'affiche comme **laboratoire non qualifié**, et `qualify.py` doit exposer les garanties physiques manquantes. Les actions dépendant de T06 restent bloquées tant que le confinement des candidats n'est pas fermé ; `install = false` interdit l'installation de dépendances candidates dans ce laboratoire initial.

Après le délai FLOOR-0 d'une heure, `bash /opt/standard/tools/install_server.sh activate` active les capacités proposées, sépare garde et agent, démarre opérateur, agent et interface sur `127.0.0.1:8080`, puis écrit `/srv/standard/qualification.json`. Accéder à l'interface par un tunnel SSH. Une nouvelle version suit le même parcours depuis un nouveau commit poussé : remplacement explicite, nouvelle genèse, délai, vérification. Ce laboratoire valide le comportement de bout en bout observable, **pas** l'indépendance d'un quorum, des témoins, de l'anti-rollback ou de l'évaluation.

**Mode opératoire pour un autre agent.** Le VPS IONOS possède le compte `standard-preview` (clé SSH, sans `sudo`) et un checkout de `refactor/kernel-bt-clean` dans `/home/standard-preview/standard-src`. Obtenir l'adresse du VPS auprès du propriétaire, vérifier sa clé d'hôte hors bande avant la première connexion et ne jamais mettre de mot de passe, clé privée ou jeton dans le dépôt, la documentation ou les commandes journalisées. Le checkout et GitHub servent à préparer une release ; `/opt/standard` est une copie de commit, non un lieu d'édition. Les autres données du VPS sont à préserver. Pour mettre à jour la source et installer une nouvelle genèse, avec accord explicite du propriétaire pour l'action root :

```sh
ssh standard-preview@<VPS_IP>
git -C /home/standard-preview/standard-src status --short --branch
git -C /home/standard-preview/standard-src pull --ff-only
git -C /home/standard-preview/standard-src rev-parse HEAD
su -c 'bash /home/standard-preview/standard-src/tools/install_server.sh'
```

L'installateur vérifie lui-même que ce commit est la tête poussée de la branche et refuse les chemins non marqués. Il imprime l'heure minimale d'activation ; ne pas la devancer. Après cette heure, dans une nouvelle session SSH :

```sh
su -c 'bash /opt/standard/tools/install_server.sh activate'
curl -fsS http://127.0.0.1:8080/api/state
systemctl is-active standard-operator standard-agent standard-web
```

Depuis le poste local, `ssh -L 8080:127.0.0.1:8080 standard-preview@<VPS_IP>` donne accès à `http://127.0.0.1:8080/` sans ouvrir le port web au public. En cas d'échec, lire `journalctl -u standard-operator -u standard-agent -u standard-web` et `/srv/standard/qualification.json` avec l'identité appropriée ; ne pas transformer un échec en `PASS` manuel. Avant l'activation, l'interface et l'agent ne sont pas encore lancés. Même après activation, le dépôt vide ne produit aucune métrique RUN et T06 refuse l'exécution des candidats faute de confinement système de fichiers. Une réinstallation remplace seulement ce laboratoire, perd son état et relance le délai FLOOR-0. Tout mot de passe partagé hors canal sûr doit être renouvelé par son propriétaire.

**Héberger les dépôts clients (D23).** `python tools/hosting.py create hosting.toml NAME --from PATH --guard-user standard-guard --gate-user standard-gate` crée le dépôt canonique (à la garde) et sa boîte de dépôt (à la passerelle). `python tools/hosting.py authorize hosting.toml NAME alice --key alice.pub --write --gate-user standard-gate` donne à une clé SSH une commande forcée vers `bt/hosting.py` : `git fetch` lit le canonique, `git push` n'écrit que dans la boîte, sous `refs/heads/alice/*`. Pas de shell, pas d'autre dépôt, une seule réponse de refus qui ne dit pas ce qui existe. L'installation pointe sur le canonique (`ceremony.py init DIR --repo …/repos/NAME.git`) et déclare `[hosting] config, gate_user` pour que `qualify.py` le vérifie. Ce que les clients poussent atteint `main` par l'opération `integrate` des floors (D24) : la ressource `repo:contrib:<contributeur>/<base>/<head>` ne s'ouvre qu'avec `tests = green` (la suite de `main` contre le code de la contribution, mesurée par le scanner), `regressions = none` (toutes les sondes locales des floors sur `main` puis sur la contribution : aucune cible ne doit empirer, sauf un suivi qu'une recette referme seule, comme un SBOM périmé par une nouvelle dépendance ; D26) **et** `review = approved` signé par un humain relecteur (`python -m surface review contrib:alice BASE HEAD --identity h3 --key … --under <grant reviewer>`). L'agent soumet l'intention, la loi refuse jusqu'à ce que les deux faits existent, la garde fait le même CAS que pour `remediate`. Une contribution est un seul commit posé sur le `main` courant : l'auteur rebase et squash.

En git local, T07 est tenu par le noyau de l'hôte : l'agent ne peut ni verrouiller `refs/heads/main`, ni lire la clé de la garde, ni ouvrir le journal. La garde ne lance jamais git *dans* le store de l'agent (elle le lit de l'extérieur par `ls-remote`/`fetch`), pour que la configuration git écrite par U ne s'exécute jamais sous l'identité de la garde. Restent hors preuve : root, les règles sudo qui permettent de devenir la garde, et le processus de la garde lui-même.

Côté GitHub, l'installation doit garantir que seule la garde déplace `main` (ruleset avec la garde seule en bypass) et que l'agent ne peut pousser que les branches `standard/proposals/*` (une règle de ruleset sur un motif de branche, exprimable chez GitHub ; un ref hors `refs/heads` ne l'est pas). C'est T07 : `qualify.py` le vérifie en partie et dit le reste.

Ce que le laboratoire peut montrer : la loi refuse, attend les faits, autorise un départ unique et réconcilie l'effet dans les parcours dont les prémisses existent. Il ne démontre pas les garanties physiques (§15.2) : les rôles humains et témoins n'y sont que des identités de test.

---

## 20. Organisation du code

Tout le dépôt appartient à Standard ; aucun produit métier client n’a été commencé. Les responsabilités sont
nommées directement à la racine : `kernel`, `bt`, `catalog`, `blocks`, `instruments`, `context`, `agent`, `surface`,
`runtime`, `tools`. Le dossier intermédiaire `standard/` et ses anciens imports ne sont plus livrés.

| Dossier | Responsabilité | Point d’entrée |
|---|---|---|
| `kernel/`, `bt/` | Jugement et frontières indépendantes | Assemblés par l’opérateur |
| `catalog/`, `blocks/`, `instruments/` | Définir, implémenter, mesurer | `python -m tools.coverage` pour l’inventaire |
| `context/` | Lecture commune de la loi, des faits et des missions | Consommée par agents et interface |
| `agent/` | Demandes, réparations, candidats/revues, exploration, file et boucle | `python -m agent run CONFIG` |
| `surface/` | Vues, cache de captures et gestes humains | `python -m surface`, `python -m surface.web CONFIG` |
| `runtime/` | Assemblage opérateur et exécution des releases | `python -m runtime serve CONFIG`, `python -m runtime.runner ...` |
| `tools/` | Installation, hébergement, qualification et rejeu ponctuels | Commandes dédiées |

### 20.1 Constats de lecture et périmètre de cette consolidation

| Constat dans le code | Traitement / état |
|---|---|
| Ancien paquet de confiance mêlant mécanismes, scanner de Standard et démarrage de Standard | Assemblage et passes déplacés dans `runtime/`, toujours couverts par l'empreinte de l'installation |
| Deux modules de ports Git partageant le même contrat de départ | Regroupés dans `bt/adapters.py` ; lecture locale definitive et réponse distante incertaine restent distinctes |
| Plafonds exactement atteints imposant un relèvement pour une modification ordinaire | Plafonds retirés ; contrôles de couches et de provenance conservés |
| Deux jugements avec code similaire | Conservés séparément : leur duplication est un contrôle indépendant, pas un fichier inutile |
| Redevabilité située dans K mais hors admission | Conservée, pure et rejouable ; elle n'autorise aucune action et n'est pas déplacée dans l'agent |
| Index JSONL des BT, écrit après les échanges, sans transaction commune avec le journal | Limite existante : enregistrement d'audit distinct, pas une atomicité durable de bout en bout ; liens `answers` non alimentés dans ces parcours |
| Rejeu de mesure pouvant reproduire une erreur du programme ou des données de la source | Limite conservée : reproductibilité ≠ vérité ; une affirmation attestée/composite garde sa dépendance explicite |
| `RegisterEffect.satisfied` tolère une version servie inconnue | Standard à compléter : preuve de service à rendre stricte. L'interface lit désormais le registre `canary` comme un fichier |
| Séries de production | Une collecte par BT ; chunks de métriques publiés en lecture seule, cache d’affichage dérivé et indisponibilités explicites |
| Empreinte calculée après import ; vérification pré-import annoncée dans l'architecture | Ouvert : le calcul d'une empreinte ne démontre pas ce que le processus a chargé |
| Exécution des suites T sous utilisateur distinct et réseau coupé, mais sans jail de fichiers ; dépendances candidates installées avec réseau | Ouvert bloquant T06 : la sonde de qualification échoue explicitement. Le jail du précontrôle U ne couvre pas ce chemin. Sans `runner_user`, l'hôte refuse aussi (D46) : plus aucun repli sous l'opérateur |
| Deux tests créant des commits temporaires sans identité Git dans un environnement vierge | La commande `make test` fournit une identité de test uniquement au processus de vérification ; assertions et runtime inchangés |
| Ancien parseur TOML partiel et shim à la racine | Supprimés : Python 3.11+ et `tomllib` seul ; une chaîne valide contenant `#` reste entière |
| BUILD/RUN web reconstruisant leurs listes depuis `view` et `findings` | `surface/views.py` projette depuis un `ReadModel` commun ; le serveur garde lecture des fichiers, Git et HTTP. Les vues de télémétrie/production gardent leurs propres entrées, sans nouvelle autorité. |
| Second juge et tests adversariaux ciblés, sans démonstration générale ni domaine de panne distinct | Limite conservée : aucun énoncé universel de tolérance à un bug ; isolation physique à qualifier |

Les fonctions communes de Standard sont conservées avec leurs contrats de test. Cette consolidation ne certifie pas les propriétés physiques, ne transforme pas les inconnues en preuves et ne prétend pas achever toutes les capacités de Standard. Le répertoire réservé `standard/` d’un dépôt client ne donne aucune autorité à un fichier : seule la loi admise dans le journal fait foi. Les formes d’enveloppe de l’admission restent inchangées par le workflow de D62.

---

### 20.2 Couverture réelle des instruments

`make coverage` (ou `python -m tools.coverage --json`) inventorie les 31 cibles de la release (inventaire, 8 techniques, 17 catégories de règles, 2 réglages fournisseur, 3 RUN) en comparant les floors aux registres des probes, jobs, contrats et routes de réparation. La commande est informative : elle n’exécute aucun instrument, ne signe aucun fait et ne qualifie aucune installation. `REGISTERED` signifie présent dans la passe, pas complet ; `CONDITIONAL` dépend de la configuration ; `MANUAL` est une attestation humaine ; `MISSING` est une mesure absente. Une future cible inconnue reste manquante.

La couverture ci-dessous décrit le code actuel, pas une certification du service :

| Capacité | Détection et obligation | Correction et vérification | Limite / état de la chaîne |
|---|---|---|---|
| Inventaire du dépôt | Manifest du commit exact, blobs/gitlinks déclarés ; cible `inventory` | Passe scanner et faits de couverture | **Partiel** : lisibilité du manifest, pas couverture sémantique des langages ; contenu des sous-modules non analysé |
| Secrets du code | Expressions régulières sur blobs suivis ; fichiers ≥ 5 Mo non couverts | Modèle sous scope, revue humaine, nouvelle mesure | **Partiel** : pas révocation/rotation des identifiants divulgués, historique Git non scanné, formats non reconnus |
| Vulnérabilités | Pins exacts racine `requirements.txt` + instantané OSV frais | Recette de montée de version quand applicable, sinon modèle/revue ; tests et reproduction indépendante | **Partiel** : PyPI direct, pas fermeture transitive ni Node/Go/Rust/JVM/OS/images ; un correctif ne garantit pas la compatibilité |
| Âge des dépendances | Écart de version majeure selon métadonnées épinglées | Modèle/revue et nouvelle mesure | **Partiel** : pas évaluation EOL, support, correctifs mineurs ou compatibilité métier |
| Licences | Expression du package comparée à la politique épinglée | Remplacement proposé, revue, tests et nouvelle mesure | **Partiel** : pas résolution générale des expressions SPDX ni conformité des dépendances transitives |
| SBOM | Composants déclarés comparés aux pins racine | Recette exacte, tests, recomputation et nouvelle mesure | **Partiel** : inventaire direct, pas graphe transitive, provenance ou vérification d’artefact |
| SAST | Bandit sur Python, sans `nosec`, erreurs de lecture non couvertes | Modèle/revue, tests et nouvelle mesure | **Partiel** : seule sévérité HIGH retenue ; pas autre langage, DAST, analyse IaC, authentification ou logique métier |
| Épinglage CI | `uses` GitHub dans workflows/actions | Recette des références résolues et recomputation | **Partiel** : pas audit général des permissions, egress, scripts ou risque de l’action ; recette limitée aux workflows |
| Santé CI | Probe `ci` : suite du commit exact de main, sous l’exécutant des instruments ; dépendances selon `[tests] install` | Réparation du code sous revue, suite indépendante et nouvelle mesure de main | **Implémenté pour la CI Standard** : aucun badge fournisseur utilisé ; pas de workflow arbitraire GitHub. Suite vide/ignorée/incomplète ou processus incohérent ne donnent pas vert |
| Protection et lignée | Paramètres fournisseur / protections locales, commits confrontés aux effets jugés | Intervention humaine, puis nouvelle lecture | **Partiel** : dépend de l’exclusivité physique et du fournisseur ; pas audit cloud IAM/organisation complet |
| Tests et demandes BUILD | Suite de main sur base/head ; contrat d’acceptation signé, intact, initialement rouge puis vert | Propositions, revue signée, CAS main et preuve | **Implémenté sur le périmètre des suites** : code testé et lecteur du rapport partagent l’exécutant ; tests seuls insuffisants, pas preuve des besoins métier |
| Non-régression | Sondes locales sur base/head, conservation de la suite de main | Admission conditionnée aux faits/revue | **Partiel** : ne couvre que les sondes actuelles ; certaines réparations suivies par recette sont exemptées ; pas règle globale de performance/accessibilité |
| Service en exploitation | Métriques Prometheus reconnues, probes HTTP déclarés, budgets SLO, p99, jobs et processus | Agent release : deploy/rollback/restart/canary/abort ; registres CAS et relecture | **Conditionnel/partiel** : sources déclarées seulement ; métriques propres au service attestées, preuve de version inconnue encore permissive (§20.1) |
| Catalogue de règles | 17 catégories mesurées par les sondes et contrôles disponibles ; import, câblage syntaxique et comportement distingués | Construction/revues U, mesure indépendante, périmètre et non-régression | **Partiel** : lacunes de la release, règles patrouillées et limites lexicales restent visibles ; une catégorie inconnue ne peut pas devenir tenue |

Les 8 cibles techniques ont désormais 8 probes, dont la suite de main pour `ci`. Les 2 cibles de paramètres ont des probes. Les 17 catégories du catalogue ont leurs cibles dynamiques ; les anciennes cibles organisationnelles et la SOA sont retirées (D51). Les 3 cibles RUN nécessitent une configuration. Seules `sbom`, `vulns`, `actions` ont une recette reproductible ; une recette enregistrée peut néanmoins être inapplicable aux entrées. Ni un job ni un helper ne valent une chaîne complète.

### 20.3 Couverture réelle des outils de Standard

| Outil | Fonction actuelle | Ce qu’il reste à couvrir |
|---|---|---|
| `tools/ceremony.py` | Genèse signée, capacités en vigueur immédiatement, séparation garde/agent | Cycle de release/migration qualifiée, rotation opérationnelle et récupération multi-hôte ; pas de migration implicite |
| `tools/install_server.sh` | Laboratoire Ubuntu remplaçable, dépôt initial vide, comptes Unix, systemd, exécutant ; n'altère ni SSH ni pare-feu | Installation production indépendante, sauvegarde/restauration, contrôles de dérive ; ne pas l'utiliser avec des données client |
| `tools/hosting.py` | Dépôts canoniques/inbox, accès SSH forcé par identité | Gestion complète du cycle des accès, offboarding, sauvegarde/restauration et hébergement multi-tenant qualifié |
| `tools/refresh_data.py` | Instantané OSV/PyPI et résolution de références GitHub, pin par digest | Acquisition planifiée, données multi-écosystèmes, provenance/approbation, fraîcheur et redistribution à grande échelle |
| `tools/qualify.py` | Diagnostic local : empreinte comparée à une genèse signée et son pin (lecture seule), fichiers de clés non vides/valides/privés, identités humaines/témoins de genèse reconnues par clé même si renommées, assessment authentifié et lié, séparation et replay | Évaluateurs distincts, campagnes continues T01–T08, cloud IAM, vrais domaines de panne ; PASS n’est pas une qualification indépendante |
| `tools/replay.py` | Comparaison des faits enregistrés aux programmes épinglés | Véracité des sources, justesse des programmes, audit complet du journal/effets, export de dossiers pour évaluateur |
| `runtime/runner.py` | Export du commit, processus Python, santé, routage canary et mesures par release | Packaging/release multi-runtime, orchestrateurs, migrations qualifiées, secrets/config et récupération durable ; ce lanceur appartient à Standard, pas à un produit métier |
| `tools/check_layers.py`, `tools/coverage.py` | Frontières statiques, indépendance du second juge, inventaire du socle de cibles/routes ; diagnostic auxiliaire, pas une seconde loi | Isolation dynamique/physique ; cartographie des capacités absentes décrite ici, non déduite d’un nombre de fichiers |
| `examples/load.py`, `examples/demo/` | Trafic et faux dépôt d’application pour éprouver Standard | Démonstration uniquement ; aucun produit client commencé |

### 20.4 Chaînes encore absentes et ordre de complétion

Ces fonctions appartiennent au périmètre commun de Standard. Les documenter n’en reporte pas la responsabilité à un futur produit métier.

1. **Rendre la chaîne existante cohérente** : CI main raccordée, rapports de tests durcis et contexte commun transmis au modèle (§20.5). La provenance des relevés est désormais commune ; reste notamment la preuve stricte de version servie et la qualification physique des sources. Valider chaque chaîne jusqu’à la fermeture indépendante, et les chemins de refus/réconciliation.
2. **Étendre ce que Standard peut mesurer** : graphes de dépendances multi-écosystèmes, secrets dans l’historique et rotation, analyse de configurations/IaC/conteneurs, capacités/performance, logs/traces et dérive d’infrastructure. Chaque mesure nomme son univers, ses sources, sa fraîcheur, ses angles morts et son contrat ; une nouvelle recette n’est autonome qu’avec recomputation indépendante.
3. **Couvrir les opérations durables** : sauvegarde puis restauration réellement éprouvée, migrations de données et compatibilité, configuration/secrets, rotation/révocation opérationnelles, upgrades de Standard et reprise après panne. La présence d’une attestation `backup` ne couvre pas ces opérations.
4. **Relier sécurité, conformité et exploitation** : incidents/adversaires vers obligations, containment et remédiation vérifiés, contrôle effectif des accès/fournisseurs, continuité, conformité et RSE mesurables. Les comptes rendus humains restent possibles mais doivent être distingués des mesures ; coût et empreinte environnementale ne disposent actuellement d’aucun instrument dédié.

Les instruments et outils livrés sont le socle invariant de Standard : ils assurent les méthodes, contrôles et moyens de référence. Leur inventaire n’est pas une liste exhaustive de toutes les techniques que l’agent devra connaître. Un moyen spécialisé absent peut être recherché, expérimenté et proposé par l’agent. Ajouter un programme qui affirme un fait ouvrant un droit reste une évolution du socle : code relu, contrat défini, source indépendante, programmes épinglés et release correspondante. La recherche n’inscrit jamais elle-même cet instrument.

---

### 20.5 Surface commune et boucle de recherche de l’agent

**Nettoyage des chemins hérités (D64).** Motif : les branches de génération sans revue, la sélection propre au patrol et
les copies de paramètres pouvaient produire des lectures différentes d’une même loi. Contre-exemples falsifiables :
signer `@high_value = [payments.send]` doit rendre `MSG-SIGN` applicable chez le scanner, le constructeur et le patrol ;
une exploration `simplicity:domain` utilisant le bloc processus doit recevoir son contrat et ne peut lire `other/`.
La surface web et la mission en cours portent les mêmes règles, la même pile et le même périmètre. Un contexte sans
snapshot indique cette absence. Une investigation de catégorie conserve les exigences de sa cible sans dépendre des
chemins d’un finding. BUILD et réparation lisent les valeurs depuis leur contexte, et leur génération par modèle
passe toujours par le même constructeur et les deux lecteurs. Les recettes recomputables restent un moyen distinct.
Impact sur la confiance : aucun déplacement de K/BT ni assouplissement des routes ; l’alignement des fonctionnalités
déclarées peut rendre une mesure supplémentaire applicable. La revue reste un avis U, jamais une preuve.

`context/model.py` est le **modèle de lecture commun**, non un stockage ni un juge. Il représente toutes les sections de la loi effective, même celles sans lien de code connu, et ajoute des relations typées vers ressources, opérations, conditions, capacités, routes, tâches, entités, faits admis, transitions, preuves et dettes du noyau, instruments, findings, emplacements candidats, réglages et références externes. Il fournit aussi les lectures communes des entités, transitions, diagnostics et faits visibles à BUILD/RUN (`surface/views.py`) et aux contextes. Un consommateur qui lui donne une vue d'un autre préfixe ou d'une autre loi est refusé. Chaque relation expose `origin` et `status` : déclaration, registre, journal, redevabilité, diagnostic, analyse AST, ou projection non vérifiée ne sont jamais confondus. `python -m surface read-model --repo PATH` rend ce graphe à un humain via la passerelle locale ; l'index AST est Python seulement, syntactique et optionnel. L'interface web n'expose pas le graphe de code entier sans authentification ; ses vues BUILD/RUN sont des projections du même modèle. La télémétrie de production reste une lecture spécialisée, non absorbée par ce graphe ; dire que le modèle est l'arrière de **toutes** les lectures serait encore excessif. Les sources de vérité restent journal, Git et enregistrements des instruments. Le noyau et le checker indépendant ne dépendent pas de `read_model.py`.

`bt/service.py` recoupe désormais le head/la taille de la santé avec l'état de la vue et refuse un assemblage qui continue à bouger. Le modèle copie sa vue, ses findings et ses réglages à la construction et conserve leurs empreintes ; le web lit les réglages au commit `main` affiché. Les nouveaux findings portent la référence du relevé et le commit d'entrée quand le job en a un. Un finding provenant d'un autre commit ou digest de loi reste visible comme périmé et ne qualifie pas la dette courante. Cela **ne constitue pas encore** une transaction atomique entre journal, Git et fichier de diagnostics : l'association du document au préfixe reste `unverified`. Les faits de la passerelle sont bornés ; une absence dans cette vue ne prouve pas l'absence dans le journal.

Le **catalogue est la définition commune des exigences du produit**. `maintenance.toml` déclare les cibles et leurs instructions de réparation ; `policy.toml` porte les paramètres signés, leurs types, bornes, valeurs de socle et recommandations ; `rules/*.toml` détaille les exigences techniques ; `values.toml` et `blocks.toml` définissent leurs paramètres et contrats minimaux d’implémentation. `catalog/floors.py` compile les cibles et valeurs de socle dans le langage de loi existant et définit les opérations gouvernées. Les choix clients signés instancient la loi effective. Les paramètres d’exécution (modèles, budgets, cadence) restent dans `standard.toml`. Le catalogue ne lit ni instruments ni agents ; les instruments reçoivent ses données inertes et produisent leurs propres mesures. K et le second juge continuent à juger la loi, pas les opinions du catalogue.

`definition()` relie chaque cible effective à sa définition de release. Une cible client sans correspondance reste explicitement non reliée. `contracts()` joint exigence, paramètres exacts, contrat du bloc, interface par stack, interdictions, sondes, câblage et vérificateurs. L’interface et toutes les missions consomment cette lecture. L’absorption par un bloc décrit une responsabilité prévue ; elle ne prouve ni son adoption correcte ni le passage de tous les chemins d’exécution. Les états de mesure et leurs limites restent distincts.

`context/missions.py` est l’unique assemblage de contexte et de dossiers d’écart. Ses lectures complètes restent disponibles aux humains. Les missions reçoivent `standard-agent-context/v2` : préfixe, digests de loi/code/catalogue, besoin et échéance, exigence, opération, preuves attendues, périmètre exact, contrats sélectionnés et carte bornée. Le paquet initial est limité à 28 000 caractères ; une entrée trop grande est différée entière avec sa référence, sans réécrire l’exigence. `read(ref=…, offset=…)` consulte une déclaration ou un document épinglé ; `search(in=context, query=…)` découvre leurs références. Ce sont les outils de recherche existants, sous les mêmes restrictions et budgets. La sélection ne dispense jamais d’une exigence omise. BUILD conserve la spécification et le contrat acceptés complets, accessibles au-delà de leur aperçu. Les lecteurs inspectent le même snapshot et les mêmes documents ; les fichiers modifiés sont inventoriés puis lus à la demande. Les diagnostics déterministes bruts accompagnent leur explication.

Les conditions clients arbitraires restent accessibles par référence. Les conditions des capacités sont exposées séparément des alternatives d’une opération ; seul K juge la chaîne choisie. `proof_plan` compare les valeurs visibles, pas la provenance ou la fraîcheur absentes de la passerelle. `decision = candidate` est une lecture indicative. Une obligation garde sa source dans la redevabilité du noyau ; un finding vert ne masque jamais une dette ouverte. Le dossier d’écart est une projection de ce contexte, pas un sous-système parallèle.

`agent/patrol.py` réalise une **mission d’exploration** : question et périmètre de lecture. `simplicity[:chemin]` examine la conception ; `rules:CATEGORIE[:chemin]` examine les exigences de la catégorie confiées à une lecture IA. Une enveloppe de snapshot impose le même périmètre aux fichiers lus, à la recherche et à la carte. L’applicabilité reste calculée sur le produit entier. Les tours automatiques alternent questions et périmètres dépôt/sous-répertoire, avec un curseur de périmètre par catégorie pour éviter qu’une catégorie reste toujours sur la même zone. La cadence et les échecs restent bornés (§11.8.1). Les résultats portent main, digest de loi et périmètre ; ils deviennent périmés si main ou la loi change. Ils restent des soupçons. Une proposition sert une dette existante ou une demande BUILD acceptée ; elle ne crée aucun fait, droit ou écart officiel.

Les frontières restent : le catalogue définit ; les blocs implémentent ; les instruments observent ; les agents proposent ; K/BT admettent et réalisent les effets gouvernés. Les liaisons loi/code restent des indices quand elles viennent d’un finding ou d’une analyse syntaxique. La capture journal/Git/findings n’est pas encore atomique ; la qualification physique et le comportement avec de vrais modèles restent à démontrer sur l’installation. Le schéma de contexte est un format interne, pas une qualification ni une preuve de complétude.

`agent/research.py` propose une boucle bornée (8 échanges par défaut, maximum configurable par construction 32 ; budget d’essais persistant par tâche/base/loi) :

| Action du modèle | Portée effective | Résultat |
|---|---|---|
| `read` | Fichier du snapshot ou déclaration/document épinglé par référence, pages de 20 000 caractères avec offset ; aucun chemin hôte | Texte et indication explicite de la suite |
| `search` | Recherche littérale dans le périmètre du snapshot, ou découverte paginée des références du contexte | Emplacements, extraits ou références |
| `fetch` | Nom d’une source HTTPS fixe configurée par l’opérateur ; aucune URL choisie par le modèle, aucun redirect, aucun identifiant dans l’URL | Documentation, avec volume/délai bornés |
| `experiment` | Fichiers proposés dans une copie temporaire ; Python système, bubblewrap, tous les namespaces séparés, sans réseau, sans HOME/clé/installation de l’agent montés | Sortie/échec, jamais un fait signé |
| Fin/proposition | Résumé, outil proposé, vérification indépendante attendue et intervention requise | Notes privées de l’agent, journal `research.jsonl` |

L’expérimentation et le précontrôle U utilisent maintenant le même bac OCI (`enclosure/`, D68), avec des limites de temps, mémoire, processus, fichier et sortie adaptées. L’expérience ne monte que le runtime système et sa copie temporaire en écriture. Sans jail réseau/fichiers, aucun code candidat ni dépendance candidate n'est démarré par U et la tâche reste bloquée. Les roues sont téléchargées par nom et version exacts, puis installées et démarrées dans le jail. L’installateur de démo installe bubblewrap ; son fonctionnement et le confinement réel doivent encore être qualifiés sur l’hôte. Ce jail U ne confine pas la suite indépendante T06. Tous les envois au modèle restent soumis au masquage et au journal d’egress. Les notes de recherche sont expurgées des secrets reconnus, écrites en 0600 sans suivre un lien symbolique et ne sont jamais chargées par les instruments comme preuve. Les lectures sont bornées avant chargement ; la recherche expose ses omissions et troncatures.

Les sources de recherche HTTPS et les modèles sont configurés par l’opérateur dans `standard.toml`. Les périmètres de réparation propres au client sont des choix signés dans `settings.scopes`, lus au démarrage de l’agent. Ils ne permettent jamais d’écrire les chemins réservés (`tests/`, `.github/`, `standard/`, fichiers de démarrage Python, chemins absolus ou remontées). Sans sonde capable de mesurer la cible, le précontrôle retourne `fixed = None` ; seule une preuve admise pourra fermer la dette. Sans périmètre de réparation disponible, une proposition de recherche reste une note.

Les mesures invariantes ne sont pas remplacées par ces outils. Le socle `suite` partage un lecteur de rapports entre l’instrument et le précontrôle : rapport absent, vide, partiellement ignoré, doublonné ou incompatible avec le code retour ⇒ non couvert/erreur ; les tests d’acceptation ignorés n’autorisent ni signature du contrat ni livraison. Un crash des outils de lint/type sans diagnostic exploitable n’est plus silencieux. La suite de main dispose désormais d’un probe `ci` ; la disparition d’un test entre main et candidat reste non couverte. Le rapport reste produit sous l’exécutant du code testé : son indépendance vis-à-vis d’une contribution hostile est une limite connue, et il ne suffit jamais seul à autoriser une fusion.

`make coverage` demeure un inventaire statique de développement. Les besoins réels et moyens absents sont exposés dans la surface et le Work Engine, avec leurs échéances originales ; aucune tâche de recherche ne signe une observation, ne crée une permission ou ne clôt une obligation. Sans modèle configuré, le travail reste visible avec les moyens disponibles et la nécessité d’intervention. Les expérimentations peuvent échouer sur l’hôte et les sources peuvent être inaccessibles : ces échecs sont du feedback, jamais une preuve positive.

---

### 20.6 Responsabilités et retrait des doublons (D65)

Motif : les anciennes partitions BUILD/RUN pouvaient doubler une obligation ; BUILD recomposait les précontrôles ;
la console collectait des séries différentes de celles utilisées par les instruments. La refonte conserve une seule
projection des besoins et une file par id de tâche. L’ouverture d’une base ancienne fusionne ses partitions dans une
transaction : échéance minimale, somme des tentatives, échéances de retry/lease maximales, événements conservés.
Aucun filtre de phase ne bloque une réparation. Demandes et obligations restent des origines distinctes ; leurs
modifications de code passent par le même candidat immuable, les mêmes revues et le même précontrôle. L’acceptation
est un contrôle supplémentaire pour une demande. Les follow-ups de recettes propres aux réparations sont conservés.

La capture HTTP de production reste dans BT. L’opérateur publie sous `readings/` un manifeste atomique et les chunks
retenus par `Series`, copiés avec leur digest. Seules les sources de rôle `metrics` sont publiées ; ni réponses de
probes, ni métriques runner, ni clés, ni accès au magasin privé de preuves. L’interface vérifie les octets, recharge
les captures manquées après un arrêt et déduplique son cache SQLite. Le cache ne collecte plus et ne peut alimenter
une mesure admise. L’historique de l’ancienne collecte UI est écarté lors de l’adoption de cette provenance. Les
captures absentes, corrompues ou périmées sont visibles ; l’inconnu ne résout pas un incident ouvert. La publication
reste une projection informative : l’origine exacte d’une réponse réseau et la qualification physique restent des
hypothèses à éprouver.

Exemples falsifiables : une même obligation présente dans deux anciennes partitions garde une seule tâche, sa date
la plus proche et son lease actif ; un redémarrage de l’interface relit les mêmes captures sans requête réseau ni
double comptage ; modifier un blob publié fait apparaître une lecture indisponible et ne clôt pas un incident.

Impact confiance : sémantique de K et du second juge inchangée ; seuils, opérations, ressources, routes d’admission,
contrats d’acceptation et interdits conservés. Les chemins et le code épinglé changent : c’est une nouvelle release,
pas une mise à jour silencieuse d’une installation existante. Le pin des instruments change avec le retrait d’une
fonction morte ; le lanceur déplacé dans `runtime/` est également couvert par le pin d’installation. Cette
réorganisation ne prétend pas réduire la TCB effective. L'adoption ciblée livrée ensuite est décrite par D66 ;
ses limites et le retour de son usage sont en §20.7.



### 20.7 Retour de l'adoption interne des blocs

L'agent et les outils de Standard emploient déjà outbound, parse, les secrets de runtime et les logs. La correction
D67 précise la disponibilité des API ; elle ne clôt pas les écarts d'implémentation ci-dessous. Reproductions locales
sur entrées synthétiques (octobre 2026), sans fournisseur réel ni qualification physique :

| Bloc / frontière | Constat et falsificateur | Correction à conduire |
|---|---|---|
| `Secret` / sérialisation | `json.dumps({"key": Secret("sentinel")})` contient `sentinel`. Hériter de `str` permet aussi des opérations brutes malgré le masquage de `str()` et `repr()`. | Un objet dédié, révélation explicite aux frontières d'envoi, refus ou masquage de la sérialisation implicite. Préserver les clés déjà typées. |
| input / normalisation | Deux clés distinctes `e` + accent combinant et `é` deviennent identiques dans `_clean` ; le dictionnaire construit conserve la dernière valeur au lieu de refuser. | Refuser les collisions après normalisation, avant le schéma. Les documents signés restent au parseur strict sans normalisation. |
| web / délai | `_read_json` attend le corps avant le lancement de la surveillance du délai. Un corps prenant 2 s ne produit aucune réponse après 1,1 s malgré `request_timeout_s = 1`. | Une borne incluant la lecture initiale et la réponse ; vérifier aussi annulation et nettoyage des tâches. |
| process / délai | L'écriture sur stdin précède `proc.wait(timeout=...)`. Un enfant dormant 0,3 s sans lire son entrée retourne encore 0 après environ 0,32 s avec `timeout=.01` et 1 MB d'entrée. | Une échéance unique couvrant entrée, attente et fermeture des sorties, avec arrêt du groupe et fermeture des descripteurs. |
| session / sorties réseau | `Oidc` possède son propre `httpx.AsyncClient` : pas de proxy ambiant ni de redirection, mais pas le DNS contrôlé, le plafond de réponse et le parseur strict d'outbound/parse. Les URLs de token et JWKS viennent de la découverte du fournisseur. | Faire réutiliser ces garanties avec un périmètre explicite des endpoints de découverte ; ne pas autoriser tous les hôtes HTTPS par commodité. Constat de lecture, pas une exploitation démontrée. |

Le regroupement utile sépare les **primitives portables** des **intégrations de framework**, sans recopier leurs
protections. `runtime` reste composite (configuration, secrets, files bornées, santé, cycle de vie) et `render` mêle
rendu de texte/HTML et réponse Starlette. Extraire les secrets de runtime et garder les réponses/cycles de vie dans
les intégrations sont les frontières à examiner ensuite ; aucun déplacement n'est justifié sans simplification
concrète d'API ou de dépendance.

Pour un agent : outbound pour le transport, parse pour décoder, un schéma input pour les commandes métier non
signées, secrets pour les clés, log pour les événements. Le journal d'egress conserve son contrat sans contenu.
Le bloc process peut servir aux commandes ordinaires ; il ne remplace pas le jail qui exécute du code candidat.
Les données de travail locales ne doivent pas être forcées dans les filtres propriétaire/tenant du bloc ORM.
Aucun bloc « agent » global ni second mécanisme d'admission n'est nécessaire pour ces responsabilités.

**Suite (D68).** Ces corrections ne seront pas conduites bloc par bloc : D68 déplace les propriétés en cause dans la
plateforme d'exécution (§4.10). Les écarts restent ouverts jusqu'à cette bascule.

---

## 21. Réception

### 21.1 Dix scénarios obligatoires

Chacun rapporte le domaine observé, la propriété affirmée, l'instrument et les hypothèses non vérifiées. Un scénario qui passe en simulation ne prouve pas la protection réelle.

1. **Élargissement adversarial** : une clé autre que celle de l'humain, un second humain, un témoin absent, un dégel → aucun élargissement hors procédure.
2. **Loi** : loi client plus faible refusée ; loi plus stricte qui ne bloque pas les restrictions immédiates.
3. **Déterminisme** : entrée identique → delta identique ; delta incomplet ou additionnel refusé ; écritures concurrentes → un seul préfixe linéarisé.
4. **Preuve** : même payload signé pour deux réalités → aucune preuve de vérité sans source qualifiée ; mauvais sujet ou couverture → refus.
5. **Obligation** : dette persistante sur 8, 20 et 100 cycles, tentatives, retraits et renommages ; échéance conservée ; clôture uniquement sur preuve indépendante.
6. **Temps** : antidate, surdate, horloge future ou contradictoire → aucun droit.
7. **Effet** : octets différents, secret alternatif, révocation juste avant le départ, ACK perdu, retry → blocage, `UNKNOWN` ou réconciliation prouvée.
8. **Rollback / genèse** : crash à chaque frontière, restauration, pins déplacés, nouvelle genèse → reprise ancrée ou arrêt.
9. **Second juge** : fautes injectées → le désaccord bloque.
10. **Autonomie** : BUILD depuis presque rien, RUN sur dépôt mature, outils existants intégrés sans autorité ; escalade due malgré l'arrêt du scheduler.

### 21.2 Portes par composant

- **Composant** : types et version, invariant testable, erreur fail-closed, contre-exemple négatif, preuve de non-contournement, métrique de ressources, propriétaire, aucun raccourci `allow`.
- **K** : un jugement complet ; loi, racines, autorité, preuve, obligation, effet gouvernés ; delta vérifiable ; aucune branche métier cachée ; différentiel contre la référence sans aucun `mismatch`.
  - Références connues (exploratoires, à re-mesurer) : jugement + second contrôle ≈ 0,29 ms médiane ; écriture durable SQLite ≈ 1,5 ms médiane ; coût d'écriture : 6 à 8 ms par entrée de 0 à 20 000 entrées depuis D49 (il croissait de 10 à 55 ms à 4 000 avant) ; différentiel du prototype hybride : 4 994 admissions et 353 refus identiques, 0 divergence.
- **T** : chaque contrat déployé, indépendance et chemins physiques audités, aucun T simulé silencieusement ; reprise, révocation et effets concurrents testés.
- **Standard** : BUILD/RUN fonctionnels, Work Engine non souverain, maintenance continue sur obligations, rapport de qualification fidèle aux preuves obtenues.

### 21.3 Portes de sortie (axes × garanties)

Chaque garantie est évaluée sur cinq axes — sémantique, compositions, défaillances, frontières physiques, autonomie — avec un statut `NOT_STARTED | TESTED_LOCAL | TESTED_MULTI_PROCESS | TESTED_EXTERNAL | NOT_APPLICABLE` (justifié). Huit portes :

1. Inventaire vérifié des garanties, chemins d'effet et dépendances.
2. Reproductibilité : oracle, fixtures, commit, logs, résultat honnête.
3. Profondeur d'interaction : ordres opposés, races.
4. Défaillances physiques : crash-injection à chaque frontière, multi-processus, absence d'egress alternatif.
5. Preuves : authentification ≠ vérité ≠ qualification.
6. Autonomie : progrès sur toute voie permise, refus sur chaque interdiction, échéances stables.
7. Revue contradictoire par un autre oracle.
8. Exhaustion raisonnable : constats regroupés par cause racine ; aucune absence absolue de faille revendiquée.

### 21.4 État de réalisation

Les états ci-dessous consignent les jalons ciblés et démonstrations du laboratoire. Ils ne signifient pas couverture générale ni qualification production : l’inventaire du code courant et ses chaînes manquantes sont en §20.1–§20.4.

| Porte | État |
|---|---|
| Sémantique et noyau (K) | Fait : jugement unique, six mécanismes, loi, redevabilité |
| Frontière durable (T) | Fait pour journal, pins, second juge, garde et passerelle. Le temps vient de l'horloge de l'opérateur ; T09 retiré (D61). |
| Preuves qualifiables | Fait pour les cibles retenues (§15.3) ; données tierces épinglées (D17) |
| Travail unifié (U) | Fait : projection, Work Engine, agent, cycle, surface, revue et attestation humaines |
| Installation | Fait : processus opérateur et agent sous deux utilisateurs Unix, cérémonie en deux phases, séparation, qualification, adaptateur GitHub |
| Hébergement (D23, chantier 1) | Fait : passerelle SSH à commande forcée, canonique à la garde, boîte de dépôt par client, opération `integrate` (D24) ; démontré avec sshd réel : contribution poussée, tests mesurés, refus sans revue, revue signée, intégration par la garde, lignée intacte ; qualify : PASS |
| Interface (D23, chantier 2) | Faite (v1, D27) : BUILD, RUN, revues signées dans le navigateur, loi, identité ; démontrée en direct (revue signée dans Chromium, admise par le noyau, contribution intégrée). Depuis : Run, Alertes, Objectifs et réglages, Demandes (D30–D35), contexte agent humain, contexte de patrouille et carte des cibles. L’exécution LLM de patrouille est disponible dans le processus agent en CLI et sur cadence ; le déclenchement web reste absent. Restent : passkeys, export des preuves, authentification en lecture, revue persistée des bindings |
| Porte LLM (D23, chantier 3) | Fait : multi-fournisseurs (Anthropic, compatible OpenAI), niveaux, masquage, journal d'egress (§11.8) |
| Outillage de l'agent (D25) | Fait et testé fonctionnellement : constats, précontrôle, mémoire et budget, carte, dossier. Le bac U échoue fermé sans runtime OCI qui l'accepte ; ses murs sont mesurés localement (§4.10), leur qualification sur l'hôte de production reste à faire. Non démontré : la boucle avec un vrai modèle (pas de clé dans la session) |
| Jalon investisseur (D15) | Démontré en git local avec T07 physique (qualify : PASS) ; sur GitHub réel, une réparation SBOM a atteint `main` de bout en bout, mais par les accès de la session et non par un jeton de garde distinct |
| Garanties physiques (§15.2) | T07 **démontré** en git local. Les autres **non démontrées** : exigent des humains, des témoins, un volume de pins et un évaluateur réellement distincts |
| Production (D30) | Fait et démontré en direct sous utilisateurs séparés : main mise en production par l'agent, contribution fautive intégrée après revue puis déployée, objectif rompu, **retour automatique en 33 s**, version fautive jamais reproposée, alerte prise en charge par une signature dans Chromium. Le redémarrage et l'objectif par composant sont venus avec D31. Restent : e-mail et messagerie, capacité |
| Réglages et vérification de la production (D31) | Fait et démontré en direct : réglages signés dans Chromium par h1 (objectif resserré appliqué tout de suite, redémarrage automatique en attente du délai, sonde ajoutée), version servie lue par le scanner et prouvée, bascule sans coupure (60 sur 60 requêtes en 200 pendant un redémarrage), version qui ne démarre pas jamais servie, retour arrière bloqué par une migration non compatible avec la raison affichée |
| Paramétrage d'ingénieur (D32) | Fait et démontré en direct : stratégie canary choisie dans Chromium par h1, changement d'Alice sur 20 % du trafic pendant 3 min puis promu sans redémarrage, changement fautif retiré en 50 s (4,08 points d'erreurs de plus, limite 0,5) ; 119 tests. Limite : les erreurs du canary ne sont vues que par le lanceur, pas par les SLO du produit |
| Isolation et instruments (D33) | Historique du laboratoire : une contribution hostile n'a pas lu la clé ni atteint le réseau ; un relecteur signant « tests au vert » a été refusé par le noyau. **État courant non qualifié :** la séparation d'utilisateur et de réseau ne confine pas le système de fichiers ni l'installation candidate. T06 retourne FAIL jusqu'à fermeture de cette frontière. |
| Construction (D34) | Fait et démontré en direct : demande écrite et signée dans Chromium par h1, contrat rouge sur main vérifié par le scanner, contrat signé, implémentation par Alice (contrat recopié, trailer), acceptation au vert mesurée en isolation, revue de h3, intégration, livraison enregistrée par l'agent, mise en production. L'implémentation par l'agent est testée avec un modèle simulé, jamais avec un vrai modèle |
| Règles dans le dépôt (D35) | Fait et démontré en direct : passage en canary signé une fois par h1, fichier commité par l'agent, intégré par la loi, puis le changement lui-même passé en canary |
| Production réduite à la mesure (D36) | Fait et testé (bout en bout, dont un retour arrière refusé par le noyau sur une consommation de 9,5) : budget production 1 205 → 791 lignes. Démontré en direct : canary promu après 10 min de cuisson, sans redémarrage |
| Hôte générique (D37) | Fait, testé et démontré en direct : 2 039 lignes de T (3 149 avant), 1 278 lignes de programmes hors T ; mise en production par registres, lanceur qui exporte lui-même, mesures rejouées (`qualify` : PASS) ; un enregistrement falsifié est détecté. En direct, le rejeu des enregistrements a montré que l'analyse canary retirait des versions saines sur du bruit (1,5 point d'écart sur 300 requêtes, produit à 2 % d'erreurs) : la retenue de l'agent compare désormais l'écart à deux erreurs-types, changement fait dans un programme et dans U, sans toucher T |
| Transactions de frontière (D38) | Fait et testé : un job de production qui dit `tests = green` est refusé par T et par le noyau ; une opération sans adaptateur du bon profil ne part pas ; un redémarrage demandé n'est jamais `not_applied` ; chaque observation, chaque effet et chaque relecture laisse une BT ; le rejeu suit les BT. Sonde `qualify` des privilèges : FAIL sur la démo (le produit est dans le groupe de la garde pour lire le dépôt), dit tel quel |
| Tests | Contrats de régression des frontières, du contexte commun, des vues BUILD/RUN, des rapports de tests, de la CI main, de la recherche sans autorité et de la qualification liée à la genèse ; falsificateurs de la revue (`tests/test_review.py`) et différentiel aléatoire des deux juges (`tests/test_differential.py`). Un test vert local n'établit aucune propriété physique sur un déploiement. |
| Pas encore là | Exécution bout en bout démontrée avec un vrai modèle ; bindings loi-code précis validés durablement ; snapshot atomique journal/Git/findings ; authentification et quota de la patrouille web ; mapping contrôle par contrôle ISO/NIS2/DORA/OWASP ; adaptateurs Kubernetes et Prometheus managé ; livraison des alertes hors interface. Les étiquettes de conformité actuelles sont des projections grossières, pas une certification. |
| Revue indépendante du code | Une revue de code complète (octobre 2026, §17.6) a été faite par un modèle, pas par un évaluateur indépendant humain : ses constats sont corrigés et testés, la revue indépendante reste à faire |

---

## 22. Discipline de changement

- Modifier ce document exige : un motif, un exemple falsifiable, une analyse d'impact sur la confiance et une décision explicite ajoutée à §18.
- **Rouvrir le découpage K/T/U** seulement si : une propriété ne peut être attribuée à K, T ou U ; un contournement de pouvoir impose une décision non couverte ; le contrat constitutionnel change de façon contradictoire ; un falsificateur n'est pas traitable par le contrat de confiance.
- Les enquêtes sur backoff, agents, WorkItems, ordonnanceur, scanners, fournisseurs ou alerting vont dans les audits d'implémentation et d'intégration. Elles ne relancent **jamais** une boucle de recherche sur tout Standard.
- Aucun nouveau document parallèle : ce fichier est la seule source. Les résultats de validation sont des artefacts générés par la CI, pas des documents rédigés.
