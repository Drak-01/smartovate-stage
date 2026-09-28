# Architecture

[← Retour à la documentation principale](../README.md)

## Objectif

Présenter l'architecture cloud-native de la solution SIEM, basée sur Microsoft Azure et Microsoft Sentinel : composants, relations et flux de données.

## Vue d'ensemble

L'architecture est organisée en cinq couches.

![Architecture en cinq couches : Entra ID, Azure Activity Log, VM Windows et VM Linux (couche 1) ; Data Collection Rule et Azure Monitor Agent (couche 2) ; Log Analytics Workspace (couche 3) ; Microsoft Sentinel, Watchlist et Analytics Rule (couche 4) ; Workbook (couche 5)](../assets/architecture.drawio.png)

| Couche | Composants | Rôle |
|---|---|---|
| 1. Sources de données | Microsoft Entra ID, Azure Activity Log, VM Windows, VM Linux | Superviser les activités d'identité, les opérations Azure et les événements de sécurité des VM |
| 2. Collecte | Azure Monitor Agent (AMA), Data Collection Rules (DCR), Diagnostic Settings | Acheminer les journaux vers le workspace. La méthode dépend de la source (voir [Collecte des données](../data-collection/README.md)). |
| 3. Stockage centralisé | Log Analytics Workspace | Point central de stockage et d'analyse, interrogeable en KQL |
| 4. Détection | Microsoft Sentinel : Analytics Rules, Watchlists, incidents, alertes, requêtes KQL | Détection et supervision à partir des données du workspace. Les Analytics Rules exécutent des requêtes KQL pour identifier les comportements correspondant aux scénarios de sécurité définis ; les Watchlists maintiennent des listes de référence utilisées par certaines règles. |
| 5. Visualisation | Workbooks Microsoft Sentinel | Tableaux de bord : événements de sécurité, connexions réussies et échouées, activités Azure, alertes et détections, statistiques de supervision |

## Flux de données

| Flux | Chemin |
|---|---|
| Entra ID | Entra ID → Diagnostic Settings → Log Analytics Workspace → Microsoft Sentinel |
| Azure Activity | Azure Activity Log → Diagnostic Settings → Log Analytics Workspace → Microsoft Sentinel |
| Windows | VM Windows → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel |
| Linux | VM Linux → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel |
| Détection et visualisation | Log Analytics Workspace → Analytics Rules / Watchlists → Microsoft Sentinel → Workbooks |

> Dans la version d'origine de ce document, le flux Linux était mal formaté (la ligne « Data Collection Rule » y était déplacée). Il a été rétabli d'après la section « Collecte » du même document, qui indique AMA + DCR pour les VM Windows et Linux.

![Schéma de flux : rôles utilisateurs accédant au portail Azure (HTTPS/443), abonnement Azure contenant Entra ID, Azure Activity, Log Analytics Workspace avec Microsoft Sentinel et Workbook, et zone VM avec les agents AMA SecurityEvent (Windows) et Syslog (Linux)](../assets/workflow_1.drawio.png)

Rôles et annotations portés sur ce schéma :

| Rôle | Annotation du schéma |
|---|---|
| Ingénieur Sécurité | Configurer/RBAC |
| Administrateur Cloud | Traitement des incidents |
| Analyste Sécurité | Consultation Workbook |
| Ingénieur Système | Configuration AMA |
| Responsable Sécurité | Traitement des incidents |
| Analyste SOC | (aucune annotation) |

> **Incohérence documentée** : ces annotations diffèrent des responsabilités de la [matrice RBAC](../rbac/README.md). Exemple : la matrice attribue la configuration des sources Azure à l'Administrateur Cloud et le suivi des alertes à l'Analyste SOC. Aucune des deux versions n'est présentée ici comme la bonne.

## Ressources Azure

Le schéma `assets/architecture_Azure.png` est la seule preuve, dans `/docs`, des ressources Azure listées ci-dessous.

![Vue des ressources Azure : Log Analytics workspace law-smartovate-badra-SIEM, solution SecurityInsights, deux Data Collection Rules (dcr-linux-Security, dcr-windows-Security), deux Azure Workbooks, deux machines virtuelles (siem-ub-serve, siem-ws-serve) avec disque, interface réseau, adresse IP publique, NSG et réseau virtuel, une ressource Bastion et une clé SSH](../assets/architecture_Azure.png)

| Type | Nom affiché sur le schéma |
|---|---|
| Log Analytics workspace | `law-smartovate-badra-SIEM` |
| Solution | `SecurityInsights(law-smartovate-badra-siem)` |
| Data Collection Rules | `dcr-linux-Security`, `dcr-windows-Security` |
| Azure Workbooks | deux ressources (identifiants de type GUID) |
| Machines virtuelles | `siem-ub-serve`, `siem-ws-serve` |
| Clé SSH | `siem-ub-serve_key` |
| Réseau | `vnet-westus2-1`, `vnet-eastus-5`, `vnet-eastus-5-bastion` (Bastion), adresses IP publiques, NSG `siem-ub-serve-nsg` et `siem-ws-serve-nsg` |

Sur le schéma, les deux DCR, les deux Workbooks et la solution SecurityInsights sont reliés au workspace.

## Références

- Modélisation UML de la solution : [diagrammes UML](../diagramme_uml/README.md)
- Sources : `assets/architecture.drawio`, `assets/workflow_1.drawio`
