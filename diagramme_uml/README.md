# Diagrammes UML

[← Retour à la documentation principale](../README.md)

## Objectif

Regrouper les diagrammes UML de modélisation de la solution. Les sources `.drawio` sont dans ce dossier, à côté des images.

> **Ce sont des éléments de modélisation.** Les valeurs des diagrammes d'objets et de séquence (par exemple `INC-2026-0842`, `timeout`, adresses IP, durées, volumes ingérés) sont des **exemples de modèle**, pas des résultats ni des incidents observés. Aucune capture correspondante n'existe dans `/docs`.

## Cas d'utilisation

![Cas d'utilisation : acteurs Ingénieur Sécurité, Administrateur Cloud, Analyste Sécurité, Ingénieur Système, Analyste SOC, Responsable Sécurité et Microsoft Sentinel, avec leurs cas d'utilisation](./01_cas_utilisation.drawio.png)

## Diagramme de classes

![Diagramme de classes : LogAnalyticsWorkspace, MicrosoftSentinel, RBAC, User, group, Workbook, KQLQueries, LogTable, DataConnector (AzureADConnector, AzureActivityConnector, AzureMonitorAgent), DataCollectionRule, VirtualMachine, Watchlist, AnalyticsRule (native et personnalisée), SecurityIncident](./02_classe.drawio.png)

## Diagramme d'états-transitions d'un incident

![États d'un incident : New, Active, Closed (True Positive ou False Positive)](./06_etat_transition.drawio.png)

## Diagrammes de séquence

![Séquence 1 : création d'une DCR par l'Ingénieur Système, déploiement sur l'agent AMA, vérification de connectivité, boucle d'envoi des événements](./sequence/seq1.drawio.png)

![Séquence 2 : exécution d'une règle personnalisée, exclusion par Watchlist, création d'un incident de sévérité High si le seuil (5+ échecs puis succès) est dépassé](./sequence/seq2.drawio.png)

![Séquence 3 : ouverture du Workbook « Supervision Identités » par le Responsable Sécurité, exécution de deux requêtes, cas de timeout de la carte géographique](./sequence/seq3.drawio.png)

Le cas de timeout de la séquence 3 est marqué « Bug 3 » dans le diagramme : c'est un bug anticipé du cahier des charges, pas un problème constaté.

## Diagrammes de collaboration

![Collaboration : DCR, agent AMA, VM et table de logs](./collaboration/02_coll_agent.drawio.png)

![Collaboration : règle personnalisée, requête, table, Watchlist et incident](./collaboration/05_coll_brf.drawio.png)

## Diagrammes d'objets

![Objets : DCR-AMA-01 avec deux agents, deux VM et deux tables (SecurityEvent, Syslog)](./objets/01_obj_dcr.drawio.png)

![Objets : règle AR-BruteForce-01, incident INC-2026-0842, Watchlist WL-TrustedIPs, requête et table SigninLogs](./objets/02_obj_analysticRule.drawio.png)

![Objets : Workbook WB-Identites-01, deux requêtes (dont un cas « timeout ») et table SigninLogs](./objets/03_obj_workbook.drawio.png)

## Références

- Architecture réelle documentée : [Architecture](../architecture/README.md)
- Règles et Workbooks : [Détection](../detection/README.md), [Workbooks](../workbooks/README.md)
