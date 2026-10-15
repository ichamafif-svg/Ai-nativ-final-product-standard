# Validation de la refonte du tissu

Source : `344a55aba45eb3a6e961d69c8c1e64fffb89cbfb` sur `claude/d68-platform-reuse`.
Dernier candidat de code relu : `d5c33c823fa2030ac861656ea2df3f090bbf773f`.
Ce rapport décrit les vérifications effectuées ; il n'est pas une attestation de production.

## Résultats

| Vérification | Résultat et portée |
|---|---|
| Suite complète d'origine | 384 tests ; 343 réussites, 34 ignorés, 7 erreurs de sockets Unix |
| Suite complète de la refonte | 407 tests ; 357 réussites, 43 ignorés, les mêmes 7 erreurs de sockets Unix ; aucun échec d'assertion |
| Politique réelle mitmproxy | 7 tests réussis dans son environnement séparé et verrouillé par empreintes |
| Proxy HTTP et OpenBao réels | 1 test réussi : injection, jeton délégué et refus de réflexion avant livraison |
| ACL natives OpenBao | 3 tests réussis, dont refus d'une autre clé, autre secret, autre opération, signature de contrôle et création de jeton |
| Juges différentiels | 200 historiques aléatoires et fautes ; test réussi |
| Mutation des empreintes | Profils et parents exécutables inclus ; suite structure 16 tests réussis |
| Récupération | 4 tests réussis : reconstruction, altération, liens/traversées et budget d'expansion |
| Compteurs runtime après dernière correction | 15 tests de configuration/isolation ; 10 réussites, 5 préconditions OCI absentes ; observation partielle explicitement inconnue |
| Frontières, syntaxe Python, lint F/E9, shell et espaces du diff | Réussis |
| Mesure stricte des fixtures physiques | Code de sortie 1 attendu : 32 murs non mesurés ici ; aucune qualification annoncée |

Les erreurs communes portent sur construction/livraison, admission hébergée, installation, canary,
production, aller-retour admission et interface serveur. Chacune échoue à créer un socket `AF_UNIX`
avec `PermissionError: [Errno 1] Operation not permitted`. L'ensemble exact des sept cas a été comparé
entre les deux suites. Aucune adaptation des tests ne masque ces erreurs.

La suite complète a été exécutée avant la dernière correction ciblée des compteurs ; celle-ci a ensuite été
vérifiée par la suite d'isolation et relue par les deux reviewers. Les vérifications natives séparées ont
exercé le vrai binaire OpenBao épinglé et le vrai proxy, sans revendiquer l'isolation OCI du transport de test.

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

La CI Linux contient les parcours OCI, les composants natifs et la délégation. Le cycle systemd réel,
le placement cgroups, les droits entre comptes et le redémarrage après reboot n'ont pas pu être exercés ici.
La vérification syntaxique des unités n'établit pas leur comportement. Le PR reste un brouillon pour cette raison.

Les limites de conception et de déploiement restent dans `ARCHITECTURE.md` et `fabric/guarantees.toml` :
processus agent encore sur l'hôte, autorités de contrôle/preuve/récupération non séparées physiquement,
restauration des données et clés non fournie par la reconstruction d'artefacts, vérification avant import,
délai sortant et renouvellement borné des jetons encore à réaliser. Les réflexions transformées des secrets
et les quotas distribués ne font pas partie des garanties ajoutées.

Références d'intégration : [délégation cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[policies OpenBao](https://openbao.org/docs/concepts/policies/),
[hooks HTTP mitmproxy](https://docs.mitmproxy.org/stable/api/events.html).
