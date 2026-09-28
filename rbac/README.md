# Matrice RBAC — Microsoft Sentinel

[← Retour à la documentation principale](../README.md)

> **Incohérence documentée** : les rôles annotés sur le schéma de flux `workflow_1` (voir [Architecture](../architecture/README.md#flux-de-données)) diffèrent des responsabilités définies dans cette matrice. Aucune des deux versions n'est présentée comme la bonne.

## Objectif

Définir les permissions RBAC granulaires nécessaires pour chaque groupe Microsoft Entra ID, selon les responsabilités de chaque acteur et selon le principe du moindre privilège.

> **Important :** les groupes Microsoft Entra ID ne sont pas encore créés au Sprint 1. Cette matrice définit uniquement la structure RBAC cible.

---

## 1. Matrice RBAC globale

| Acteur | Groupe Entra ID prévu | Rôle Azure RBAC cible | Niveau d'accès | Responsabilités |
|---|---|---|---|---|
| Ingénieur Sécurité | `SG-Ing-Securite` | Custom Sentinel Security Engineer | Lecture + écriture ciblée | Configurer Microsoft Sentinel, les connecteurs, les règles de détection, l'automatisation et les composants de supervision |
| Administrateur Cloud | `SG-Cloud-Admins` | Custom Cloud Sentinel Administrator + Security Administrator (Entra) | Lecture + écriture Azure ciblée | Configurer les sources Azure et les paramètres de diagnostic (Azure + Entra ID) |
| Analyste Sécurité | `SG-Analyste-Security` | Custom Sentinel Data Source Analyst | Lecture + écriture ciblée | Configurer Azure Activity et intégrer les ressources à surveiller |
| Ingénieur Système | `SG-Ing-Systeme` | Virtual Machine Contributor + droits DCR minimaux | Lecture + écriture ciblée | Déployer Azure Monitor Agent et configurer les Data Collection Rules |
| Analyste SOC | `SG-SOC-Analystes` | Microsoft Sentinel Responder ou rôle personnalisé | Lecture + actions autorisées | Surveiller les alertes, analyser les événements et gérer les actions autorisées |
| Responsable Sécurité | `SG-Security-Managers` | Microsoft Sentinel Reader | Lecture | Contrôler et valider la configuration et la supervision de sécurité |

---

# 2. Permissions RBAC granulaires par groupe

## 2.1 Ingénieur Sécurité — `SG-Ing-Securite`

L'Ingénieur Sécurité est responsable de la configuration fonctionnelle de Microsoft Sentinel.

| Fonction / Composant | Permission RBAC | Scope recommandé | Niveau |
|---|---|---|---|
| Data Connectors | `Microsoft.SecurityInsights/dataConnectors/read` | Sentinel | Lecture |
| Data Connectors | `Microsoft.SecurityInsights/dataConnectors/write` | Sentinel | Écriture |
| Data Connectors | `Microsoft.SecurityInsights/dataConnectors/delete` | Sentinel | Écriture |
| Vérification connecteurs | `Microsoft.SecurityInsights/dataConnectorsCheckRequirements/action` | Sentinel | Action |
| Analytics Rules | `Microsoft.SecurityInsights/alertRules/read` | Sentinel | Lecture |
| Analytics Rules | `Microsoft.SecurityInsights/alertRules/write` | Sentinel | Écriture |
| Analytics Rules | `Microsoft.SecurityInsights/alertRules/delete` | Sentinel | Écriture |
| Rule Actions | `Microsoft.SecurityInsights/alertRules/actions/read` | Sentinel | Lecture |
| Rule Actions | `Microsoft.SecurityInsights/alertRules/actions/write` | Sentinel | Écriture |
| Rule Actions | `Microsoft.SecurityInsights/alertRules/actions/delete` | Sentinel | Écriture |
| Rule Execution | `Microsoft.SecurityInsights/alertRules/triggerRuleRun/action` | Sentinel | Action |
| Automation Rules | `Microsoft.SecurityInsights/automationRules/read` | Sentinel | Lecture |
| Automation Rules | `Microsoft.SecurityInsights/automationRules/write` | Sentinel | Écriture |
| Automation Rules | `Microsoft.SecurityInsights/automationRules/delete` | Sentinel | Écriture |
| Watchlists | `Microsoft.SecurityInsights/Watchlists/read` | Sentinel | Lecture |
| Watchlists | `Microsoft.SecurityInsights/Watchlists/write` | Sentinel | Écriture |
| Watchlists | `Microsoft.SecurityInsights/Watchlists/delete` | Sentinel | Écriture |
| Workspace | `Microsoft.OperationalInsights/workspaces/read` | Workspace | Lecture |
| Requêtes KQL | `Microsoft.OperationalInsights/workspaces/query/read` | Workspace | Query |
| Workbooks | `Microsoft.SecurityInsights/workbooks/read` | Sentinel | Lecture |
| Workbooks | `Microsoft.SecurityInsights/workbooks/write` | Sentinel | Écriture |
| Workbooks | `Microsoft.SecurityInsights/workbooks/delete` | Sentinel | Écriture |
| Incidents | `Microsoft.SecurityInsights/incidents/comments/read` | Sentinel | Lecture |
| Incidents | `Microsoft.SecurityInsights/incidents/comments/write` | Sentinel | Écriture |
| Investigation | `Microsoft.SecurityInsights/entities/read` | Sentinel | Lecture |
| Investigation | `Microsoft.SecurityInsights/entities/gettimeline/action` | Sentinel | Action |
| Investigation | `Microsoft.SecurityInsights/entities/getInsights/action` | Sentinel | Action |

---

## 2.2 Administrateur Cloud — `SG-Cloud-Admins`

L'Administrateur Cloud gère principalement la configuration Azure et la diffusion des journaux vers Log Analytics / Microsoft Sentinel.

| Fonction / Composant | Permission RBAC | Scope recommandé | Niveau |
|---|---|---|---|
| Diagnostic Settings | `Microsoft.Insights/diagnosticSettings/read` | Subscription / ressource | Lecture |
| Diagnostic Settings | `Microsoft.Insights/diagnosticSettings/write` | Subscription / ressource | Écriture |
| Diagnostic Settings | `Microsoft.Insights/diagnosticSettings/delete` | Subscription / ressource | Écriture |
| Activity Log | `Microsoft.Insights/EventCategories/Read` | Subscription | Lecture |
| Activity Log | `Microsoft.Insights/eventtypes/values/Read` | Subscription | Lecture |
| Log Analytics | `Microsoft.OperationalInsights/workspaces/read` | Workspace | Lecture |
| Log Analytics | `Microsoft.OperationalInsights/workspaces/write` | Workspace | Écriture |
| Tags | `Microsoft.Resources/tags/read` | Subscription / RG | Lecture |
| Tags | `Microsoft.Resources/tags/write` | Subscription / RG | Écriture |
| Data Connectors | `Microsoft.SecurityInsights/dataConnectors/read` | Sentinel | Lecture |
| Data Connectors | `Microsoft.SecurityInsights/dataConnectors/write` | Sentinel | Écriture |
| Vérification connecteurs | `Microsoft.SecurityInsights/dataConnectorsCheckRequirements/action` | Sentinel | Action |

### Responsabilité spécifique Microsoft Entra ID

Pour permettre la diffusion des `AuditLogs` et `SigninLogs` vers Log Analytics, l'Administrateur Cloud doit disposer des droits nécessaires sur les **Diagnostic Settings** de la ressource concernée.

La configuration du connecteur Sentinel reste distincte de la configuration du flux de logs Azure.

---

## 2.3 Analyste Sécurité — `SG-Analyste-Security`

L'Analyste Sécurité est principalement responsable des sources de données et de leur intégration à Sentinel.

| Fonction / Composant | Permission RBAC | Scope recommandé | Niveau |
|---|---|---|---|
| Activity Log | `Microsoft.Insights/EventCategories/Read` | Subscription | Lecture |
| Activity Log | `Microsoft.Insights/eventtypes/values/Read` | Subscription | Lecture |
| Data Connector | `Microsoft.SecurityInsights/dataConnectors/read` | Sentinel | Lecture |
| Data Connector | `Microsoft.SecurityInsights/dataConnectors/write` | Sentinel | Écriture |
| Vérification connecteur | `Microsoft.SecurityInsights/dataConnectorsCheckRequirements/action` | Sentinel | Action |
| Workspace | `Microsoft.OperationalInsights/workspaces/read` | Workspace | Lecture |
| Requêtes KQL | `Microsoft.OperationalInsights/workspaces/query/read` | Workspace | Query |

---

## 2.4 Ingénieur Système — `SG-Ing-Systeme`

L'Ingénieur Système est responsable des machines virtuelles, de l'Azure Monitor Agent et des Data Collection Rules.

| Fonction / Composant | Permission RBAC | Scope recommandé | Niveau |
|---|---|---|---|
| Virtual Machines | `Microsoft.Compute/virtualMachines/read` | VM / Resource Group | Lecture |
| VM Extensions | `Microsoft.Compute/virtualMachines/extensions/read` | VM / Resource Group | Lecture |
| VM Extensions | `Microsoft.Compute/virtualMachines/extensions/write` | VM / Resource Group | Écriture |
| VM Extensions | `Microsoft.Compute/virtualMachines/extensions/delete` | VM / Resource Group | Écriture |
| Workspace | `Microsoft.OperationalInsights/workspaces/read` | Workspace | Lecture |

### Data Collection Rules

Les permissions DCR doivent être ajoutées explicitement si l'Ingénieur Système doit créer ou modifier les règles de collecte.

Les permissions à prévoir sont de la forme :

- `Microsoft.Insights/dataCollectionRules/read`
- `Microsoft.Insights/dataCollectionRules/write`
- `Microsoft.Insights/dataCollectionRules/delete`

Le scope doit être limité au Resource Group / aux ressources utilisées pour la collecte.

---

## 2.5 Analyste SOC — `SG-SOC-Analystes`

L'Analyste SOC doit pouvoir analyser les données et les incidents sans disposer de droits d'administration sur la configuration Sentinel.

| Fonction / Composant | Permission RBAC | Scope recommandé | Niveau |
|---|---|---|---|
| Workspace | `Microsoft.OperationalInsights/workspaces/read` | Workspace | Lecture |
| Requêtes KQL | `Microsoft.OperationalInsights/workspaces/query/read` | Workspace | Query |
| Entités | `Microsoft.SecurityInsights/entities/read` | Sentinel | Lecture |
| Timeline | `Microsoft.SecurityInsights/entities/gettimeline/action` | Sentinel | Action |
| Insights | `Microsoft.SecurityInsights/entities/getInsights/action` | Sentinel | Action |
| Commentaires incidents | `Microsoft.SecurityInsights/incidents/comments/read` | Sentinel | Lecture |
| Commentaires incidents | `Microsoft.SecurityInsights/incidents/comments/write` | Sentinel | Écriture |
| Analytics Rules | `Microsoft.SecurityInsights/alertRules/read` | Sentinel | Lecture |

> L'Analyste SOC ne doit pas recevoir par défaut les permissions `write` sur les Data Connectors, Analytics Rules, Automation Rules ou Watchlists.

---

## 2.6 Responsable Sécurité — `SG-Security-Managers`

Le Responsable Sécurité possède principalement des droits de lecture et d'audit.

| Fonction / Composant | Permission RBAC | Scope recommandé | Niveau |
|---|---|---|---|
| Data Connectors | `Microsoft.SecurityInsights/dataConnectors/read` | Sentinel | Lecture |
| Analytics Rules | `Microsoft.SecurityInsights/alertRules/read` | Sentinel | Lecture |
| Automation Rules | `Microsoft.SecurityInsights/automationRules/read` | Sentinel | Lecture |
| Watchlists | `Microsoft.SecurityInsights/Watchlists/read` | Sentinel | Lecture |
| Workbooks | `Microsoft.SecurityInsights/workbooks/read` | Sentinel | Lecture |
| Workspace | `Microsoft.OperationalInsights/workspaces/read` | Workspace | Lecture |
| Requêtes KQL | `Microsoft.OperationalInsights/workspaces/query/read` | Workspace | Query |
| Entités | `Microsoft.SecurityInsights/entities/read` | Sentinel | Lecture |

> Le Responsable Sécurité ne doit pas disposer de permissions `write` par défaut. Les droits d'écriture peuvent être accordés temporairement si une responsabilité de validation ou de modification lui est attribuée.

---

# 3. Permissions communes au niveau Subscription

Certaines permissions ne doivent pas être attribuées globalement à tous les groupes.

## Gestion RBAC

À réserver aux administrateurs responsables de la gestion des attributions de rôles :

- `Microsoft.Authorization/roleAssignments/read`
- `Microsoft.Authorization/roleAssignments/write`
- `Microsoft.Authorization/roleAssignments/delete`

> Ces permissions sont particulièrement sensibles. Elles permettent de modifier les autorisations Azure et ne doivent pas être incluses dans les rôles Sentinel standards sauf nécessité explicite.

## Tags

À attribuer uniquement aux acteurs responsables de la gouvernance des ressources :

- `Microsoft.Resources/tags/read`
- `Microsoft.Resources/tags/write`

---

# 4. Synthèse du principe de moindre privilège

| Groupe | Sentinel | Azure Sources | Workspace | VM / Agent | DCR | KQL | Administration RBAC |
|---|---|---|---|---|---|---|---|
| `SG-Ing-Securite` | Écriture ciblée | Lecture / configuration connecteurs | Lecture / Query | Non | Non | Oui | Non |
| `SG-Cloud-Admins` | Connecteurs ciblés | Écriture | Écriture ciblée | Non | Non | Non requis | Selon besoin |
| `SG-Analyste-Security` | Connecteurs | Lecture | Lecture / Query | Non | Non | Oui | Non |
| `SG-Ing-Systeme` | Non | Non | Lecture | Écriture | Écriture | Non requis | Non |
| `SG-SOC-Analystes` | Lecture / actions autorisées | Non | Lecture / Query | Non | Non | Oui | Non |
| `SG-Security-Managers` | Lecture | Lecture | Lecture / Query | Non | Non | Oui | Non |

---

# 5. Rôles Azure RBAC recommandés

| Groupe Entra ID | Rôle recommandé | Justification |
|---|---|---|
| `SG-Ing-Securite` | Custom Sentinel Security Engineer | Limiter l'accès à la configuration fonctionnelle Sentinel |
| `SG-Cloud-Admins` | Custom Cloud Sentinel Administrator | Autoriser la configuration Azure et des Diagnostic Settings |
| `SG-Analyste-Security` | Custom Sentinel Data Source Analyst | Limiter l'accès à l'intégration des sources |
| `SG-Ing-Systeme` | Virtual Machine Contributor + permissions DCR ciblées | Déployer les agents et gérer les règles de collecte |
| `SG-SOC-Analystes` | Microsoft Sentinel Responder ou Custom SOC Analyst | Analyse et réponse aux incidents sans administration complète |
| `SG-Security-Managers` | Microsoft Sentinel Reader | Supervision et validation en lecture seule |

---

# 6. Séparation des responsabilités

La matrice applique une séparation des responsabilités :

### Ingénieur Sécurité

Responsable de la **configuration de Sentinel** :

- Data Connectors
- Analytics Rules
- Automation Rules
- Watchlists
- Workbooks
- Investigation

### Administrateur Cloud

Responsable de la **configuration Azure** :

- Diagnostic Settings
- Activity Logs
- Log Analytics
- Tags
- Sources Azure

### Analyste Sécurité

Responsable de l'**intégration et de la vérification des sources de données**.

### Ingénieur Système

Responsable de l'**infrastructure de collecte** :

- VM
- Azure Monitor Agent
- VM Extensions
- Data Collection Rules

### Analyste SOC

Responsable de la **surveillance et de l'analyse** :

- Incidents
- Entités
- Timeline
- Insights
- Requêtes KQL

### Responsable Sécurité

Responsable de la **supervision et de la validation** de la configuration.

---

# 7. Règles de sécurité RBAC

1. Ne pas attribuer `Microsoft Sentinel Contributor` à tous les acteurs.
2. Ne pas attribuer `Microsoft.Authorization/roleAssignments/write` sauf aux administrateurs explicitement responsables du RBAC.
3. Limiter les scopes au niveau le plus précis possible : ressource > Resource Group > Subscription.
4. Séparer la configuration Azure des sources de données de la configuration fonctionnelle Sentinel.
5. Séparer les droits d'administration des droits d'analyse SOC.
6. Utiliser des rôles personnalisés lorsque les rôles Azure intégrés donnent trop de permissions.
7. Ne pas donner de permissions `delete` lorsqu'une tâche nécessite uniquement `read` ou `write`.
8. L'Analyste SOC doit rester principalement en lecture et disposer uniquement des actions nécessaires à la réponse aux incidents.
9. Le Responsable Sécurité doit rester en lecture seule par défaut.
10. Les permissions DCR doivent être explicitement accordées à l'Ingénieur Système lorsqu'il est responsable de leur création ou modification.

---

# 8. Références Microsoft

- [Azure RBAC — Permissions Microsoft.Security](https://learn.microsoft.com/fr-fr/azure/role-based-access-control/permissions/security)