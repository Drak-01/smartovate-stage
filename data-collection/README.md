# Collecte des données

[← Retour à la documentation principale](../README.md)

## Objectif

Décrire comment les journaux des différentes sources sont acheminés vers le Log Analytics Workspace, puis exploités par Microsoft Sentinel. Les schémas de flux sont dans [Architecture](../architecture/README.md#flux-de-données).

Aucune capture de configuration ni procédure pas à pas de collecte n'est présente dans `/docs`. Les éléments ci-dessous sont ceux qui sont documentés.

## Sources et méthodes de collecte

| Source | Méthode | Table utilisée dans les requêtes |
|---|---|---|
| Microsoft Entra ID | Export vers le workspace via les paramètres de diagnostic | `SigninLogs`, `AuditLogs` |
| Azure Activity Log | Export vers le workspace via les paramètres de diagnostic, au niveau de l'abonnement | `AzureActivity` |
| VM Windows | Azure Monitor Agent + Data Collection Rule | `SecurityEvent` |
| VM Linux | Azure Monitor Agent + Data Collection Rule | `Syslog` |

## Microsoft Entra ID

- Les journaux sont exportés via les paramètres de diagnostic (Diagnostic Settings).
- Pour `AuditLogs` et `SigninLogs`, l'Administrateur Cloud doit disposer des droits sur les Diagnostic Settings. La configuration du connecteur Sentinel reste distincte de celle du flux de logs Azure ([RBAC](../rbac/README.md#22-administrateur-cloud--sg-cloud-admins)).
- Configuration réalisée et capture : [Information non disponible dans /docs]

## Azure Activity

- Les journaux sont exportés via les paramètres de diagnostic, au niveau de l'abonnement.
- Configuration réalisée et capture : [Information non disponible dans /docs]

## Machines virtuelles Windows et Linux

- Les événements sont collectés par Azure Monitor Agent. Le schéma de flux montre un agent « AMA - SecurityEvent » côté Windows et un agent « AMA - Syslog » côté Linux.
- Les procédures de connexion aux VM sont dans [Tests](../test/README.md#connexion-aux-vm).
- Configuration réalisée et captures : [Information non disponible dans /docs]

## Azure Monitor Agent et Data Collection Rules

- Les DCR définissent les données à collecter et leur destination.
- Deux DCR sont visibles sur le schéma des ressources : `dcr-linux-Security` et `dcr-windows-Security`.
- Le diagramme de séquence de l'[UML](../diagramme_uml/README.md#diagrammes-de-séquence) modélise la création d'une DCR avec les flux `Microsoft-SecurityEvent` et `Microsoft-Syslog`, son déploiement sur l'agent AMA et la boucle d'envoi des événements.
- Le diagramme d'objets modélise une DCR nommée « Collecte SecurityEvent + Syslog ». Ce sont des valeurs de modélisation.
- Procédure de déploiement de l'agent et création des DCR : [Information non disponible dans /docs]

## Log Analytics Workspace et Sentinel

- Le workspace stocke les journaux collectés ; Sentinel s'appuie sur ses données. Voir [Infrastructure](../infrastructure/README.md) et [Détection](../detection/README.md).

## Santé de l'ingestion

Le [Workbook](../workbooks/README.md) contient une requête de latence d'ingestion par source (`SigninLogs`, `AuditLogs`, `AzureActivity`, `SecurityEvent`, `Syslog`). Résultats : [Information non disponible dans /docs]
