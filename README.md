# SIEM Cloud-Native avec Azure Monitor et Microsoft Sentinel

Documentation technique du projet Smartovate.

## Présentation

Smartovate est une entreprise spécialisée dans le conseil et l'accompagnement de ses clients pour la sécurisation de leurs infrastructures.

Ce projet vise à concevoir, déployer et configurer une solution SIEM (Security Information and Event Management) cloud-native avec Microsoft Azure, en particulier Microsoft Sentinel et Azure Monitor.

**Périmètre**

- Déploiement d'un espace de travail Log Analytics et activation de Microsoft Sentinel.
- Configuration des connecteurs de données pour ingérer les logs de Microsoft Entra ID (anciennement Azure Active Directory), d'Azure Activity et des machines virtuelles (Windows/Linux).
- Création de règles d'analyse (Analytics Rules) personnalisées et basées sur les modèles existants pour détecter les comportements suspects.
- Développement de classeurs (Workbooks) Azure Monitor pour la visualisation des données de sécurité.
- Documentation technique et guide d'utilisation de la solution.

Le problème traité et l'objectif du stage ne sont pas documentés dans `/docs` : [Information non disponible dans /docs]

## Documentation

### Architecture
Architecture en cinq couches, flux de données, composants, schémas et ressources Azure visibles sur `architecture_Azure.png`.

[Consulter la documentation](./architecture/README.md)

### Infrastructure Azure
Log Analytics Workspace, Microsoft Sentinel, machines virtuelles et guide de déploiement (vide).

[Consulter la documentation](./infrastructure/README.md)

### Collecte des données
Méthodes de collecte pour Entra ID, Azure Activity, VM Windows et Linux, Azure Monitor Agent et DCR.

[Consulter la documentation](./data-collection/README.md)

### RBAC
Matrice RBAC cible, permissions détaillées par groupe et règles de sécurité.

[Consulter la documentation](./rbac/README.md)

### Détection
13 règles natives Microsoft, 3 requêtes KQL personnalisées, Watchlist et [guide de création de règles KQL](./detection/kql-guide.md).

[Consulter la documentation](./detection/README.md)

### Workbooks
7 paramètres interactifs et 17 requêtes KQL expliquées.

[Consulter la documentation](./workbooks/README.md)

### Tests
Scripts de simulation Linux (10 scénarios) et Windows (4 actions) et procédures de connexion aux VM. Aucun résultat de test documenté.

[Consulter la documentation](./test/README.md)

### Diagrammes UML
Cas d'utilisation, classes, états, séquences, collaboration et objets (éléments de modélisation).

[Consulter la documentation](./diagramme_uml/README.md)

### Rapport de référence
[document-technique.md](./document-technique.md) : rapport unique dont le contenu a servi de base à la répartition ci-dessus. Il est conservé comme document de référence.

## Données sensibles présentes dans les sources

Les documents contiennent, conservés tels quels :

- des adresses IP publiques et des noms d'utilisateur SSH/RDP ([Tests](./test/README.md#connexion-aux-vm)) ;
- une adresse e-mail de compte dans [TrustedUsers.csv](./TrustedUsers.csv).

Aucune anonymisation n'a été effectuée. À traiter avant toute diffusion.
# smartovate-stage
