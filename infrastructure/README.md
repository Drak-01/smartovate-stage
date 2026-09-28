# Infrastructure Azure

[← Retour à la documentation principale](../README.md)

## Objectif

Regrouper la documentation des composants Azure de la solution : Log Analytics Workspace, Microsoft Sentinel et machines virtuelles.

Aucune capture de configuration ni procédure pas à pas n'est présente dans `/docs` pour ces composants. Seuls leur rôle et les éléments visibles sur le [schéma des ressources Azure](../architecture/README.md#ressources-azure) sont documentés.

## Log Analytics Workspace

- Rôle : point central de stockage et d'analyse des journaux collectés, interrogeable en KQL.
- Ressource visible sur le schéma des ressources : `law-smartovate-badra-SIEM`.
- Le diagramme de cas d'utilisation prévoit : choix de la configuration (région, rétention 90 jours), application des tags de facturation, vérification des paramètres selon les exigences du projet ([UML](../diagramme_uml/README.md)). Ces éléments sont issus de la modélisation.
- Configuration réalisée (région, rétention, tags) : [Information non disponible dans /docs]

## Microsoft Sentinel

- Rôle : détection et supervision à partir des données du workspace (Analytics Rules, Watchlists, incidents, alertes). Voir [Détection](../detection/README.md).
- Solution `SecurityInsights(law-smartovate-badra-siem)` visible sur le schéma des ressources.
- Procédure d'activation et capture : [Information non disponible dans /docs]

## Machines virtuelles

- Deux VM figurent sur le schéma des ressources : `siem-ub-serve` et `siem-ws-serve`, avec leur clé SSH, leur NSG, leur adresse IP publique et une ressource Bastion.
- Les procédures de connexion utilisées pour les tests sont dans [Tests](../test/README.md).
- Caractéristiques des VM (système, taille, région) : [Information non disponible dans /docs]

## Guide de déploiement

[deployment-guide.md](./deployment-guide.md) ne contient que son titre. Contenu : [Information non disponible dans /docs]

## Références

- Agent et règles de collecte : [Collecte des données](../data-collection/README.md)
- Contrôle d'accès : [RBAC](../rbac/README.md)
