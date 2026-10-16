# Cartographie PostgreSQL de Standard — première tranche

La carte est un **document navigable**. Elle n'autorise aucune action et ne
sert ni de preuve à K/BT, ni de mesure aux instruments. La carte dérivée déjà
présente dans `interface/context/model.py` reste la lecture d'une installation
et d'un journal précis ; cette base permet d'éditer et comparer des descriptions
architecturales. Aucune donnée de production n'y est recopiée.

## Stockage et lectures

Le schéma `interface/context/cartography.sql` crée sept tables : `types`,
`revisions`, `objects`, `relations`, `sources`, `expectations`, `exceptions`.
Les objets et relations sont plats. Une relation `contains` peut décrire une
hiérarchie ; aucune colonne `parent_id` ne lui donne un sens implicite. Une
attente s'applique à une version de type et, éventuellement, aux objets dont
les propriétés contiennent `applies_to`. Une exception `unknown` ou
`not_applicable` porte sa justification. La vue `gaps` compte les relations
documentées dans la **même révision** ; son résultat est un état documentaire.

Un `scope` identifie le système cartographié et `revision` la base exacte du
dessin (par exemple un SHA Git ou l'identifiant d'une configuration déployée).
La même identité UUID peut être reprise dans une nouvelle révision, ce qui
permet de comparer les objets sans s'appuyer sur leur nom. Les objets et liens
d'une révision scellée ne peuvent plus être modifiés ; le registre de types est
immuable par version. `knowledge_status` reste une appréciation documentaire :
`corroborated` ne prouve pas un comportement en production. Chaque source
indique son URI, sa révision éventuelle et, si connue, sa date d'observation.

L'installation exige une base **dédiée** et un propriétaire technique ; ne pas
appliquer ce schéma dans la base `product` de la barrière de données. Il ne
contient aucune information secret ni copie du code source. Le rôle de lecture
reçoit `USAGE` sur le schéma et `SELECT` sur les tables et la vue. Un rôle
d'écriture distinct et limité gère les brouillons dans des transactions ; le
propriétaire de la base garde seul les opérations DDL et de scellement. Les
privilèges réels et la connexion sont à configurer par le déploiement, pas par
la carte.

## Premier usage commun

`psql` et les variables libpq habituelles (`PGHOST`, `PGUSER`, etc.) sont
nécessaires. La CLI donne les mêmes réponses JSON aux humains et aux agents :

```sh
python -m interface.context.cartography init --dbname standard_map
python -m interface.context.cartography objects --dbname standard_map --scope standard --revision COMMIT
python -m interface.context.cartography relations --dbname standard_map --scope standard --revision COMMIT
python -m interface.context.cartography gaps --dbname standard_map --scope standard --revision COMMIT
python -m interface.context.cartography sources --dbname standard_map --scope standard --revision COMMIT
python -m interface.context.cartography gaps --dbname standard_map --scope standard --revision COMMIT --offset 100
```

L'édition initiale se fait en SQL transactionnel dans une révision `draft`.
Chaque réponse contient `items` (100 lignes au plus) et `next_offset` ; poursuivre
jusqu'à `null` pour ne pas masquer les autres lacunes. Les champs textuels et
JSON ont des tailles maximales en base, et la sortie JSON est bornée.
L'API HTTP et les vues HTML ne sont pas encore branchées à cette base. Avant
de les ajouter, il faut qualifier les rôles d'accès et remplir une première
carte de Standard à partir de sources réelles. Les filtres, parcours et
comparaisons devront rester bornés et ne jamais convertir un chemin décrit en
autorisation ou en preuve.
