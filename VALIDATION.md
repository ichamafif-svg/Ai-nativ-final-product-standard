# Validation de la refonte du tissu

Source : `344a55aba45eb3a6e961d69c8c1e64fffb89cbfb` sur `claude/d68-platform-reuse`.
Dernier candidat de code relu : `ad525bf` (arbre identique publié sous `0dc9cfd`).
Ce rapport décrit les vérifications effectuées ; il n'est pas une attestation de production.

## Résultats

| Vérification | Résultat et portée |
|---|---|
| Suite complète d'origine | 384 tests ; 343 réussites, 34 ignorés, 7 erreurs de sockets Unix |
| Première suite complète locale de la refonte | 407 tests ; 357 réussites, 43 ignorés, les mêmes 7 erreurs de sockets Unix ; aucun échec d'assertion |
| Politique réelle mitmproxy | 7 tests réussis dans son environnement séparé et verrouillé par empreintes |
| Proxy HTTP et OpenBao réels | 1 test réussi : injection, jeton délégué et refus de réflexion avant livraison |
| ACL natives OpenBao | 3 tests réussis, dont refus d'une autre clé, autre secret, autre opération, signature de contrôle et création de jeton |
| Juges différentiels | 200 historiques aléatoires et fautes ; test réussi |
| Mutation des empreintes | Profils et parents exécutables inclus ; suite structure 16 tests réussis |
| Récupération | 4 tests réussis : reconstruction, altération, liens/traversées et budget d'expansion |
| Runtime et observations ciblés, candidat final local | 20 tests ; 15 réussites, 5 préconditions OCI absentes ; couverture du lanceur bloqué, des preuves manquantes et du refus rootless runsc |
| Autonomie et contexte après adaptation de la fixture du lanceur | 46 tests réussis |
| Suite complète Linux CI, commit `c57dac9` | 411 tests ; 368 réussites et 43 préconditions absentes ; aucun échec |
| CI physique Linux, commit `c57dac9` | Parcours utilisateur, root et gVisor réussis ; tous les murs mesurés `held` |
| Frontières, syntaxe Python, lint F/E9, shell et espaces du diff | Réussis |
| Mesure stricte des fixtures physiques | Code de sortie 1 attendu : 32 murs non mesurés ici ; aucune qualification annoncée |

Les erreurs communes portent sur construction/livraison, admission hébergée, installation, canary,
production, aller-retour admission et interface serveur. Chacune échoue à créer un socket `AF_UNIX`
avec `PermissionError: [Errno 1] Operation not permitted`. L'ensemble exact des sept cas a été comparé
entre les deux suites. Aucune adaptation des tests ne masque ces erreurs.

La première suite complète locale précède les corrections ciblées des sondes. Les tentatives destructives
ont ensuite été séparées : gVisor peut perdre son Sentry entier lorsqu'un budget est épuisé. Un rapport
manquant ne devient `held` qu'avec un marqueur de tentative, un échec et un événement natif correspondant ;
un résultat explicite `broken` est conservé. Le lanceur est tué et récupéré même si la commande native échoue.
Les vérifications natives séparées ont exercé le vrai binaire OpenBao épinglé et le vrai proxy, sans revendiquer l'isolation OCI du transport de test.

Les résultats CI sont consultables : [suite complète et 200 historiques](https://github.com/ichamafif-svg/Ai-nativ-final-product-standard/actions/runs/38810260726),
[parcours physiques utilisateur, root et gVisor](https://github.com/ichamafif-svg/Ai-nativ-final-product-standard/actions/runs/38810260687).
Le dernier delta de code ajoute le refus préventif de runsc rootless ; ses tests ciblés et les deux revues ont réussi.

## Reproduction

```sh
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.hashes
make check PYTHON=.venv/bin/python
STANDARD_DIFFERENTIAL=200 .venv/bin/python -m unittest discover -s tests -p test_differential.py -v
.venv/bin/python -m tools.fabric measure --strict
```

Pour le proxy, créer un environnement **séparé**, installer avec `--require-hashes` la fermeture
`fabric/supply_chain/egress-requirements.txt`, puis lancer `test_fabric_adversarial.py` avec cet interpréteur.
Pour les tests natifs, installer les composants épinglés avec `python -m tools.components fetch` et
utiliser `STANDARD_COMPONENTS` si leur emplacement diffère. Les tests annoncent leurs préconditions.
Les proxies du poste ont été retirés uniquement de l'environnement des tests localhost afin que HTTPX
n'envoie pas leurs requêtes locales vers le proxy SOCKS du poste.

La fermeture originale du proxy omettait `typing-extensions`. Elle a été complétée sans changer les versions
explicitement épinglées des autres dépendances, puis installée avec vérification des empreintes.

## Revues

Deux lecteurs distincts ont inspecté le même candidat immuable : correction/sécurité et simplicité.
Leurs constats sur les parents exécutables non épinglés, le namespace chargé au démarrage de K, la délégation
cgroups, sa persistance au boot et les compteurs partiels ont été corrigés et relus. Ils ne revendiquent aucune
qualification physique du déploiement. Les dix fichiers du noyau sont conservés octet pour octet après déplacement.

## Qualification restant nécessaire

La CI Linux a exercé les parcours OCI sous root, gVisor et un compte utilisateur distinct avec délégation
cgroups. Le parcours utilisateur inclut Envoy, connexion OAuth, sortie, secrets et TLS natif ; les tests de
données annoncent leur précondition PostgreSQL/PL-Python absente, sans prétendre couvrir ce domaine.
Le cycle systemd complet, les droits entre tous les comptes de production et le redémarrage après reboot
restent à qualifier sur le déploiement cible.
La vérification syntaxique des unités n'établit pas leur comportement. Le PR reste un brouillon pour cette raison.

Les limites de conception et de déploiement restent dans `ARCHITECTURE.md` et `fabric/guarantees.toml` :
CLI agent directe non enfermée, autorités de contrôle/preuve/récupération non séparées physiquement,
restauration des données et clés non fournie par la reconstruction d'artefacts, vérification avant import,
délai sortant et renouvellement borné des jetons encore à réaliser. Les réflexions transformées des secrets
et les quotas distribués ne font pas partie des garanties ajoutées.

Références d'intégration : [délégation cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[policies OpenBao](https://openbao.org/docs/concepts/policies/),
[hooks HTTP mitmproxy](https://docs.mitmproxy.org/stable/api/events.html).

Le mode rootless de runsc est refusé car sa documentation indique que des erreurs de configuration cgroups
peuvent être ignorées. Sous un compte non privilégié, le profil base peut sélectionner runc/crun ; les profils
exigeant runsc restent indisponibles. Voir les [limites natives de runsc rootless](https://gvisor.dev/docs/user_guide/rootless/).


## Suite : enclosure du processus agent

Le PR #4 ajoute le lancement natif bubblewrap de l'agent. Sur le commit `28218c5`, les trois parcours Linux
ont réussi, dont les scénarios natifs suivants : accès hôte et écriture du dépôt refusés, plafond parent et
migration hors délégation refusés, candidat OCI imbriqué exécuté, admission autorisée puis refusée après
révocation, reconstruction d'octets vérifiés sans effacement des observations, et démarrage réel de l'agent
avec diagnostics non vides et contrat BUILD lisible. Le contrôle de ce scénario est une fixture signée à deux
juges ; il ne fournit pas une attestation de déploiement ni une mission de construction par un modèle réel.

Le workspace local refuse `unshare -Urn` avec `Operation not permitted`. Ce refus est conservé ; la qualification
native vient du parcours Linux de CI, pas d'une simulation locale. Le premier montage cgroups superposé était
refusé par runc (`EXDEV`) ; le montage natif unique a réussi sans ajouter de capacité au compte agent. Les
permissions DAC de l'hôte et les plafonds root restent donc des hypothèses explicites.

La première suite locale de cette passe a exécuté 418 tests : les sept erreurs AF_UNIX connues, un défaut de
chemin dans l'inventaire ensuite corrigé, et deux échecs liés aux proxies SOCKS du workspace. Les tests affectés
par ces proxies ont réussi après retrait des variables de proxy, sans modification de leur contrat. Les suites
ciblées inventaire (7), structure (16), catalogue (13) et autonomie/contexte (46) ont réussi.

Le dernier code `9906f6d` a également réussi les sept tests du parcours agent, dont l'appel de modèle et la
recherche HTTPS depuis l'enclosure via le vrai proxy et OpenBao, avec un fournisseur de test. Le compte agent
ne détient qu'une référence de secret ; le fournisseur observe la clé injectée sur le POST correspondant.
Les trois parcours utilisateur/root/gVisor et la politique sortante ont réussi.
Preuve : [parcours Linux et enclosure](https://github.com/ichamafif-svg/Ai-nativ-final-product-standard/actions/runs/38814708278).
