# Standard

Infrastructure AI-native de création, évolution et maintenance logicielle : les agents construisent et proposent,
les décisions humaines et les exigences gouvernent, le tissu borne les capacités et les instruments vérifient.

Lire [l'architecture](ARCHITECTURE.md) pour la cible, les responsabilités et les limites actuelles.
L'inventaire [des garanties](fabric/guarantees.toml) relie chaque frontière à ses hypothèses et tests.

```sh
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.hashes
make check PYTHON=.venv/bin/python
make coverage PYTHON=.venv/bin/python
.venv/bin/python -m tools.fabric inventory
```

Le laboratoire ne constitue pas un déploiement de production qualifié. Les sondes ont des préconditions explicites ;
une protection indisponible reste non mesurée. Aucun produit client n'est présupposé.
