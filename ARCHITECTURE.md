# Standard — Architecture

Document unique de référence. Il décrit **ce que Standard est et comment il est découpé**. Il ne décrit ni l'historique des versions, ni l'état d'avancement, ni les résultats de tests. Toute affirmation de sûreté ici est une **exigence de conception**, pas une garantie démontrée.

---

## 1. Mission

Standard est une plateforme **AI-native** qui crée puis, surtout, **maintient en continu** des dépôts et systèmes logiciels par des agents autonomes, **sans jamais accorder d'autorité souveraine** à un agent, à un humain seul ou à un composant seul.

- L'agent propose, diagnostique, code, teste et corrige.
- Seul le **noyau** décide de ce qui est admissible.
- Seule la **frontière de confiance** fait partir un effet réel.

Le produit vise la **maintenance autonome** (sécurité, fiabilité, conformité ISO 27001, NIS2, DORA). L'initialisation d'un dépôt est un cas particulier de maintenance, pas une exception.

**Cycle central :** écart → obligation durable → travail autonome → preuve qualifiée → clôture ou escalade.

---

## 2. Principes directeurs

1. **Simplicité d'abord.** Un mécanisme ne s'ajoute que s'il protège une garantie nommée. Certaines limites résiduelles sont acceptées et documentées plutôt que compensées par de la complexité.
2. **Un seul souverain déterministe.** Un jugement unique, une seule sémantique, aucun second moteur, aucun `allowed` fourni de l'extérieur.
3. **La TCB est l'enjeu du produit.** Ce qui est dans la TCB ne doit souffrir d'aucune faiblesse et ne demande aucune IA pour s'appliquer.
4. **Silos.** L'AI-first s'applique à la loi et aux opérations. Il ne s'applique **pas** au noyau, où l'IA est totalement absente.
5. **La TCB ne se fait pas confiance.** Séparation interne de premier rang : un défaut d'un composant de la TCB ne suffit pas à admettre un effet interdit. La séparation est imposée par le noyau Linux (processus, utilisateurs, permissions).
6. **La TCB seule amène le dépôt vers l'état voulu.** En théorie, appliquer la TCB sans autre couche suffit à converger ; les autres couches accélèrent et enrichissent, elles ne sont pas nécessaires à la correction.
7. **La TCB ne grossit pas avec le métier.** Les règles métier croissent par déclarations ; les mécanismes de confiance restent constants.
8. **Sécurité adversariale native.** Elle naît de la première règle (FLOOR-0), pas d'un module ajouté. Un événement adversarial déclenche lui-même du travail ou un traitement spécial.
9. **Aucun acteur de confiance seul**, humains compris.
10. **Le noyau décide, il n'observe pas.** Le problème des oracles (vérité du monde réel) est assumé hors du noyau.

---

## 3. Modèle de loi

### 3.1 Trois niveaux

| Niveau | Contenu | Auteur | Changement |
|---|---|---|---|
| **FLOOR-0** | La TCB : autorité, causalité, polarité, historique, preuve, passage aux effets | Équipe Standard | Nouvelle release + nouvelle genèse. Jamais par le système. |
| **Floors** | Ce que Standard impose à tous : autonomie, sécurité, conformité | Équipe Standard, dans la release | Nouvelle release adoptée explicitement. Le client ne peut pas les affaiblir. |
| **Loi client** | Identités, contexte, exigences supplémentaires, resserrements | Humains du client | Gouverné dans le journal (quorum, délai attesté, activation). Pas de nouvelle genèse. |

Règles de composition :

- La composition est **additive** : un niveau inférieur ajoute ou durcit, jamais n'affaiblit.
- Seules les lois de FLOOR-0 sont figées à la genèse. La loi client évolue dans le journal **par élargissement gouverné**.
- Une loi présente dans le dépôt (`.standard/law.toml`) n'est qu'une **proposition** ; seule une activation gouvernée la rend effective.
- Floors et loi client activée forment **une seule loi effective épinglée** (digest + préfixe).

### 3.2 Les six mécanismes

Toute loi de la TCB s'exprime avec six primitives. Les niveaux inférieurs réutilisent les mêmes primitives chaque fois que c'est possible : une loi client doit se lire comme une loi de la TCB.

| Mécanisme | Rôle |
|---|---|
| **CAP** | Capacités : qui peut faire quoi, sur quelle ressource, dans quel contexte et pour combien de temps. Délégation uniquement atténuante. |
| **OBL** | Obligations : dettes stables nées d'un écart, avec échéance, maintien et clôture sur preuve. |
| **NIV** | Niveaux : hiérarchie FLOOR-0 > floors > loi client, et règle de non-affaiblissement. |
| **PROV** | Provenance : indépendance des chaînes de détenteurs, quorum, témoins. |
| **TYPE** | Types fermés des ressources, faits, transitions et effets. |
| **HIST** | Historique : journal append-only, préfixe authentique, loi applicable à chaque position. |

La suffisance de ces six primitives pour toute règle métier n'est pas démontrée ; c'est un objectif de conception.

### 3.3 Source de l'autonomie

L'autonomie vient de **l'écart entre ce que Standard (et le client) demande et ce que le dépôt a**. Chaque exigence active produit des besoins observables. Chaque besoin non satisfait produit une obligation. Chaque obligation produit du travail. Une obligation ne crée **jamais** une permission.

---

## 4. Architecture en couches

Les couches s'emboîtent autour du noyau. **Plus une couche est proche du noyau, moins elle reçoit de signaux.** Les connexions entre couches sont limitées et typées.

```
┌──────────────────────────────────────────────────────────┐
│ 4. SURFACE        humains : santé, couverture, dettes,   │
│                   décisions, escalades                   │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 3. AUTONOMIE (U)  agents, WorkItems, découverte,   │  │
│  │                   BUILD/RUN, intégrations          │  │
│  │  ┌──────────────────────────────────────────────┐  │  │
│  │  │ 2. CONFIANCE (T)  identités, temps, journal, │  │  │
│  │  │                   preuves, garde des effets  │  │  │
│  │  │  ┌────────────────────────────────────────┐  │  │  │
│  │  │  │ 1. NOYAU (K)  jugement déterministe    │  │  │  │
│  │  │  └────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

| Couche | Reçoit | Produit | Peut | Ne peut jamais |
|---|---|---|---|---|
| **K Noyau** | Préfixe authentique, entrée signée, loi épinglée | Décision + delta exhaustif + autorisation d'effet exacte | Juger | Lire le monde, exécuter un effet, contenir de l'IA |
| **T Confiance** | Décisions de K, signatures, mesures, réponses fournisseurs | Prémisses qualifiées, commit ancré, effet parti ou `UNKNOWN` | Attester, ancrer, garder les secrets, faire partir l'effet autorisé | Décider `allowed` |
| **U Autonomie** | Loi effective projetée, obligations, état du dépôt | Propositions signées, WorkItems, diagnostics | Travailler sous capacités bornées | Définir la loi, détenir un secret privilégié, fabriquer une preuve |
| **Surface** | Vues de K et de U | Décisions humaines signées | Montrer et solliciter | Masquer un FAULT ou un trou de couverture |

**TCB effective = K + T.** U et la Surface sont hors TCB : leur défaillance peut ralentir ou mal prioriser, jamais admettre un effet interdit.

Le silo **opérations (U)** est le seul qui ne soit pas précisément délimité : c'est un chantier de couverture, pas de précision.

---

## 5. Noyau (K)

### 5.1 Objets canoniques

Principal, ressource, capacité, preuve, obligation, transition, intention d'effet, constitution. Aucune ontologie fournisseur (GitHub, CI, cloud, SRE) dans le noyau.

### 5.2 Fonction

`decide(préfixe, entrée_signée) → (décision, delta)`

- **Pure et déterministe** : mêmes octets + même préfixe → même jugement.
- **Exhaustive** : le delta contient toutes les conséquences obligatoires ; un delta incomplet ou additionnel est refusé.
- **Fail-closed** : entrée malformée, provenance insuffisante ou dépendance T indisponible → refus explicite.

### 5.3 Contrats logiques

Ce sont des responsabilités, pas des modules imposés.

| | Responsabilité |
|---|---|
| K01 | Modèle canonique : encodage unique, versionné, sans flottant ni champ caché |
| K02 | Identité : signature liée au domaine, à la genèse, à la ressource et à la version |
| K03 | Autorité : atténuation monotone, aucun privilège par défaut, révocation et gel immédiats, élargissement par quorum + témoins + délai + veto |
| K04 | Constitution : composition non affaiblissante, genèse et récupération sans exception souveraine |
| K05 | État et transitions : ressources à états finis, champs écrits déclarés, conflits sérialisés |
| K06 | Recevabilité des preuves : sujet, méthode, couverture, fraîcheur, source, indépendance, invalidation. Une signature n'est pas une vérité ; le silence n'est jamais `healthy`. |
| K07 | Obligations : une dette stable par exigence × sujet × épisode ; retries et renommages ne remettent pas l'échéance à zéro ; retrait de loi ≠ réparation |
| K08 | Intention d'effet : destination, octets, préconditions et fenêtre exacts ; re-jugement au départ |
| K09 | Escalade : condition constitutionnelle indépendante de tout scheduler |
| K10 | Jugement unique combinant K01–K09 |

### 5.4 Séparation interne

Le noyau ne se fait pas confiance :

- un **vérificateur indépendant** (contrôle ET) recalcule les propriétés critiques ; tout désaccord arrête le journal ;
- les composants dont un défaut peut seulement **arrêter** ou **masquer** (jamais admettre) sont isolés dans des budgets séparés ;
- l'isolation entre composants est imposée par l'OS, pas par la discipline du code.

### 5.5 Langage

Python pour l'instant. Le choix final (Python, Rust, SPARK) se fera sur trois critères : sécurité, performance, fiabilité.

---

## 6. Frontière de confiance (T)

Neuf **responsabilités** (regroupables, pas neuf services). Une opération ne requiert que les T dont elle dépend ; un T manquant bloque uniquement les opérations qui en dépendent, jamais les restrictions immédiates.

| | Responsabilité | Condition physique à démontrer sur chaque déploiement |
|---|---|---|
| T01 | Épingle de release et de genèse | Installation authentique, aucun downgrade |
| T02 | Clés et identités physiques | Humains réellement distincts, custody exclusive |
| T03 | Temps attesté | Horloge et témoins indépendants ; le temps n'accorde jamais de droit |
| T04 | Préfixe durable | Ancre hors du domaine de restauration du journal |
| T05 | Vérification indépendante | Domaine de panne réellement distinct |
| T06 | Instruments de preuve | Vérité et couverture effectivement mesurées |
| T07 | Garde des effets | Credentials et egress exclusifs ; aucun chemin privilégié parallèle |
| T08 | Readback et réconciliation | Idempotence fournisseur, état `applied / not_applied / unknown` |
| T09 | Livraison des escalades | Accusé observable ; le silence n'est pas une résolution |

Un adaptateur qui atteste une observation utilisée par K, détient un secret privilégié ou fait partir un effet **appartient à T**, quel que soit son nom.

---

## 7. Autonomie (U)

| | Composant | Interdit |
|---|---|---|
| U01 | Découverte et inventaire de l'existant (CI, IAM, scanners, procédures) | Déclarer une couverture complète sans instrument T06 |
| U02 | Projection de la loi en objectifs observables | Modifier la loi pour simplifier une cible |
| U03 | Work Engine : WorkItems, reprises, retries | Confondre WorkItem et obligation ; repousser une échéance |
| U04 | Agents (Claude via API) : planifier, coder, tester, proposer | Détenir un secret privilégié ou une signature souveraine |
| U05 | BUILD : créer et transformer | Bootstrap en god mode |
| U06 | RUN : surveiller, corriger, maintenir la conformité | Clore une dette sur un scan vert |
| U07 | Intégrations : Git, CI, cloud, IAM | Autoriser une action ou fabriquer un fait qualifié |

- **WorkItems.** Les WorkItems sont canoniques et natifs : mêmes objets et même admission que l'API agent. L'initialisation se fait hors WorkItem (elle ralentirait la cadence). Après l'initialisation, l'agent ne travaille hors WorkItem que pour escalader.
- **Contrôle caché.** Pour certains risques, un contrôle IA parallèle, caché de l'agent, peut être ajouté. Il reste dans U et ne décide rien.
- **Point d'entrée agent.** `python -m standard` donne à l'agent sa tâche courante, la loi effective (floors + loi client) et les routes T à qualifier, sans lire de documentation.

---

## 8. Protocole de bout en bout

```
proposer (U)
  → authentifier / qualifier les prémisses (T)
  → juger (K)
  → vérifier indépendamment (T05)
  → committer atomiquement au préfixe ancré (T04)
  → réserver, re-juger au départ, faire partir l'effet exact (T07)
  → résultat confirmé ou UNKNOWN (T08)
  → réconcilier
  → nouvelle mesure qualifiée (T06) → clôture ou maintien de l'obligation (K)
```

- Une restriction admise avant le départ bloque l'effet ; après le départ, elle ne le rappelle pas.
- Une panne ou une réponse ambiguë devient `UNKNOWN`, puis travail de réconciliation, jamais un succès présumé.
- Un reçu d'exécution ne clôt pas une obligation ; seule une preuve qualifiée de la propriété exigée la clôt.

---

## 9. Parcours produit

1. **Constituer.** Épingler release, genèse, FLOOR-0 et floors ; composer la loi client ; établir les identités humaines et le quorum.
2. **Découvrir et qualifier.** Inventorier l'existant et choisir une route par responsabilité : réutiliser, envelopper, compléter, créer, ou signaler l'impossibilité. Qualifier les T nécessaires.
3. **Projeter.** Transformer la loi effective en besoins observables. Une mesure absente, une couverture inconnue, un instrument indisponible, un risque constaté et un effet incertain sont des états distincts.
4. **Travailler.** Les agents reprennent les obligations en BUILD ou RUN, sous capacités bornées.
5. **Décider et effectuer.** Selon le protocole de la section 8.
6. **Vérifier et poursuivre.** Clôture sur preuve, sinon reprise, réconciliation ou escalade. La Surface montre ce qui est maintenu, ce qui échappe à la couverture et les décisions attendues.

---

## 10. Garanties

Chaque garantie a un propriétaire K, un contrat T indispensable et un rôle U.

| G | K garantit | T doit rendre réel | U fait |
|---|---|---|---|
| G01 | Quorum, élargissement, veto, délais | Personnes, clés et témoins distincts | Solliciter les décisions |
| G02 | Restriction prioritaire, re-jugement | Ordre atomique, fencing | Stopper les travaux |
| G03 | Floors, loi additive | Release épinglée authentique | Proposer des règles |
| G04 | Delta canonique déterministe | Journal durable et ordonné | Proposer des modifications |
| G05 | Domaine, sens, signatures | Cryptographie, clés | Préparer les assertions |
| G06 | Aucun droit par l'horloge | Temps et provenance | Retries, backoff |
| G07 | Preuve recevable (sujet, méthode, couverture) | Vérité des instruments | Scanner |
| G08 | Ouverture, maintien, échéance, clôture | Rétention, observations fiables | WorkItems, réparations |
| G09 | Effet exact, re-jugement | Garde et egress exclusifs | Proposer des effets |
| G10 | Réservation, `UNKNOWN`, réconciliation | Fencing, readback, idempotence | Résoudre les incertitudes |
| G11 | Refus d'état incompatible | Domaines de restauration indépendants | Proposer une récupération |
| G12 | Contrôle distinct obligatoire | Vérificateur réellement indépendant | Diagnostics |
| G13 | Clôture par preuve uniquement | Couverture et vérité mesurées | Inventaire, scans |
| G14 | Genèse et récupération gouvernées | Installation, racines physiques | Préparer l'initialisation |
| G15 | Tous les effets gouvernés | Fermeture des autres chemins privilégiés | Appels sous capacité |
| G16 | Conditions d'escalade | Livraison et disponibilité | Scheduling, alertes |

---

## 11. Hébergement et produit

- **Deux hébergements, un seul protocole** : mode **dépôt seul** (tout tourne dans le dépôt du client) et **service géré** (le produit commercial). Mêmes objets, même admission, même journal.
- **Interface native** : Standard a sa propre surface de WorkItems et de décisions. Jira et toute synchronisation de tickets sont hors périmètre.
- **Hors maintenance autonome** : la TCB elle-même. Elle est changée par l'équipe Standard via une release, jamais par le système.

---

## 12. Organisation du code

Une couche = un dossier. Rien en dehors.

```
kernel/      K — jugement, six mécanismes, FLOOR-0. Aucune dépendance hors stdlib + crypto épinglée.
trusted/     T — journal, pins, garde d'effets, readback, horloge, livraison, vérificateur indépendant.
floors/      Floors de la release (déclaratifs) : autonomie, sécurité, conformité.
autonomy/    U — découverte, projection, Work Engine, agents, intégrations.
surface/     Interface humaine et point d'entrée agent.
tests/       Un test de réception par garantie G01–G16 et par scénario de la section 13.
```

Règles d'import, vérifiées automatiquement :

- `kernel` n'importe rien de Standard.
- `trusted` n'importe que `kernel`.
- `autonomy` et `surface` ne parlent à K et T que par l'interface d'admission. Ils ne reçoivent ni clé, ni credential, ni journal mutable.

---

## 13. Réception

Une release n'est exploitable que si ces dix scénarios passent **sur le déploiement réel**, avec, pour chacun, le domaine observé, la propriété affirmée, l'instrument et les hypothèses non vérifiées :

1. **Élargissement adversarial** : une clé, plusieurs clés d'un même humain, témoin non indépendant, mauvais délai, veto → aucun élargissement hors procédure.
2. **Loi** : une loi client plus faible est refusée ; une loi plus stricte ne bloque pas les restrictions immédiates.
3. **Déterminisme** : entrée identique → delta identique ; écritures concurrentes → un seul préfixe linéarisé.
4. **Preuve** : un même payload signé pour deux réalités différentes ne prouve rien sans source qualifiée.
5. **Obligation** : la dette persiste sur huit cycles et plusieurs tentatives ; échéance conservée.
6. **Temps** : une date antidatée, future ou contradictoire ne crée aucun droit.
7. **Effet** : octets différents, secret alternatif, révocation juste avant le départ, ACK perdu → blocage, `UNKNOWN` ou réconciliation prouvée.
8. **Rollback / genèse** : crash, restauration, pins déplacés, nouvelle genèse → reprise ancrée ou arrêt.
9. **Vérificateur** : fautes injectées → le désaccord bloque.
10. **Autonomie** : BUILD depuis presque rien, RUN sur dépôt mature, escalade due malgré l'arrêt du scheduler.

Un scénario qui passe en simulation ne prouve pas la protection réelle.

---

## 14. Limites assumées

- Une signature ne prouve ni la vérité d'une mesure, ni l'existence de deux personnes distinctes.
- Une tentative locale unique ne garantit pas un effet distant unique sans déduplication côté fournisseur.
- Un stockage local ne prouve pas l'indépendance des domaines de restauration.
- La conformité réglementaire ne se déduit pas d'un statut `PROVEN`.
- Il n'existe pas de preuve formelle de convergence ni de consensus multi-hôte.
- Le système fait confiance au noyau Linux pour l'isolation interne de la TCB.
