# Guide technique - Workbook SIEM Smartovate Ltd

[← Retour à la documentation principale](../README.md)

Ce document explique, requête par requête, ce que fait le classeur Microsoft Sentinel et à quoi sert chaque paramètre interactif. Il sert de référence pour l'équipe (Epic 4 – US 4.2 du cahier des charges) et de modèle pour créer de nouvelles règles KQL.

## État de la documentation

- Contenu : **7 paramètres interactifs** et **17 requêtes KQL**, réparties en 6 sections (vue d'ensemble, identités, Azure Activity, machines virtuelles, incidents et alertes, santé de l'ingestion). Le texte ci-dessous est le document source, conservé tel quel.
- Le [schéma des ressources Azure](../architecture/README.md#ressources-azure) montre deux ressources Azure Workbook. Titre et contenu de chacune : [Information non disponible dans /docs]
- Captures des Workbooks : [Information non disponible dans /docs]
- Résultats obtenus pour chaque requête : [Information non disponible dans /docs]
- Les mentions « Bug 1 » et « Bug 3 » ci-dessous renvoient à des **bugs anticipés dans le cahier des charges**, pas à des problèmes constatés.
- Modélisation du Workbook (valeurs d'exemple, non observées) : [UML](../diagramme_uml/README.md)

## Les paramètres interactifs du classeur

| Paramètre | Rôle | Exemple |
|---|---|---|
| `Workspace` | Choisit le Log Analytics Workspace à interroger | `law-smartovate-siem-badra` |
| `TimeRange` | Fenêtre de temps appliquée à toutes les requêtes | dernières 24h, 7 jours... |
| `FiltreUtilisateur` | Filtre optionnel sur un UPN (laisser vide = tout le monde) | `badra@contoso.com` |
| `Ordinateur` | Filtre optionnel sur le nom d'une machine | `VM-WEB-01` |
| `TopN` | Nombre d'éléments affichés dans les classements | `10`, `20`... |
| `Severite` | Sévérités d'incidents à afficher | High, Medium |
| `StatutIncident` | Statut des incidents affichés | Tous, New, Active, Closed |

Ces paramètres sont substitués directement dans le texte des requêtes (entre `{ }`), donc chaque requête ci-dessous s'adapte automatiquement à ce que l'utilisateur sélectionne en haut du classeur.

---

## 1. Vue d'ensemble (KPI)

```kql
SigninLogs
| where TimeGenerated {TimeRange}
| summarize Connexions=count(), Echecs=countif(ResultType != 0)
| extend Type = "Connexions Entra ID"
| project Type, Connexions, Echecs
| union ( AzureActivity | where TimeGenerated {TimeRange} | where ActivityStatusValue == "Success"
    | summarize Connexions=countif(OperationNameValue has "write"), Echecs=countif(OperationNameValue has "delete")
    | extend Type = "Opérations Azure (write/delete)" | project Type, Connexions, Echecs )
| union ( SecurityIncident | where TimeGenerated {TimeRange}
    | summarize Connexions=count(), Echecs=countif(Severity in ("High","Medium"))
    | extend Type = "Incidents Sentinel (Total / High-Medium)" | project Type, Connexions, Echecs )
```

**À quoi ça sert :** produit 3 chiffres clés d'un coup d'œil — le volume de connexions Entra ID, les opérations Azure « à risque » (création/suppression), et le nombre d'incidents Sentinel. Le `union` permet d'empiler trois résultats différents dans un seul tableau de tuiles.

---

## 2. Supervision des identités (Microsoft Entra ID)

### Connexions réussies vs échouées par jour
```kql
SigninLogs
| where TimeGenerated {TimeRange}
| where UserPrincipalName contains "{FiltreUtilisateur}"
| summarize Succes = countif(ResultType == 0), Echecs = countif(ResultType != 0) by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```
**À quoi ça sert :** `ResultType == 0` veut dire « connexion réussie » dans les logs Entra ID. On compte les succès et les échecs, regroupés par jour (`bin(...,1d)`), pour voir la tendance. Le filtre `contains "{FiltreUtilisateur}"` ne change rien si le champ est vide, sinon il ne garde que l'utilisateur choisi.

### Origine géographique des connexions
```kql
SigninLogs
| where TimeGenerated {TimeRange}
| where isnotempty(LocationDetails)
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion),
         latitude = todouble(LocationDetails.geoCoordinates.latitude), longitude = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(latitude) and isnotempty(longitude)
| summarize Connexions = count(), Echecs = countif(ResultType != 0) by City, Country, latitude, longitude
| order by Connexions desc
```
**À quoi ça sert :** les logs de connexion contiennent la géolocalisation approximative (`LocationDetails`, un champ JSON). On en extrait ville/pays/coordonnées pour les afficher sur une carte, avec une couleur qui monte au rouge si le taux d'échec est élevé — utile pour repérer une connexion venant d'un pays inhabituel.

### Top des utilisateurs en échec de connexion
```kql
SigninLogs
| where TimeGenerated {TimeRange}
| where ResultType != 0
| where UserPrincipalName contains "{FiltreUtilisateur}"
| summarize EchecsConnexion = count(), DernierEchec = max(TimeGenerated) by UserPrincipalName
| top {TopN} by EchecsConnexion desc
```
**À quoi ça sert :** classe les comptes qui échouent le plus souvent à se connecter — souvent le signe d'un mot de passe oublié ou d'une tentative d'intrusion. Cliquer sur une barre du graphique remplit automatiquement `FiltreUtilisateur` pour approfondir cet utilisateur dans les autres visuels.

### Détection Brute Force
```kql
let seuilEchecs = 5;
let fenetre = 30m;
let succes = SigninLogs
    | where TimeGenerated {TimeRange} | where ResultType == 0
    | where UserPrincipalName contains "{FiltreUtilisateur}"
    | project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress;
SigninLogs
| where TimeGenerated {TimeRange}
| where ResultType != 0
| where UserPrincipalName contains "{FiltreUtilisateur}"
| summarize EchecsCount = count(), PremierEchec = min(TimeGenerated), DernierEchec = max(TimeGenerated)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, fenetre)
| where EchecsCount >= seuilEchecs
| join kind=inner succes on UserPrincipalName, IPAddress
| where SuccessTime between (DernierEchec .. DernierEchec + fenetre)
| project UserPrincipalName, IPAddress, EchecsCount, PremierEchec, DernierEchec, SuccessTime
| order by DernierEchec desc
```
**À quoi ça sert :** c'est la règle personnalisée demandée par l'US 3.2. La logique : si un compte/IP échoue au moins 5 fois (`seuilEchecs`) en 30 minutes (`fenetre`) **puis** finit par réussir juste après, c'est le schéma classique d'une attaque par force brute qui a fini par deviner le bon mot de passe. Le `join` rapproche les échecs et le succès qui suit.

### Modifications d'identités
```kql
AuditLogs
| where TimeGenerated {TimeRange}
| where Category in ("UserManagement", "GroupManagement", "RoleManagement")
| summarize Count = count() by OperationName, bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```
**À quoi ça sert :** trace les créations/modifications d'utilisateurs, de groupes et de rôles — utile pour vérifier qu'aucun compte ou droit sensible n'a été créé sans validation.

---

## 3. Activité Azure (Azure Activity)

### Répartition des opérations sur les ressources
```kql
AzureActivity
| where TimeGenerated {TimeRange}
| summarize Count = count() by OperationNameValue, ActivityStatusValue
| top 15 by Count desc
```
**À quoi ça sert :** vue d'ensemble (camembert) des types d'actions effectuées sur les ressources Azure (création, écriture, suppression) et de leur statut (succès/échec).

### Détection de suppressions massives
```kql
AzureActivity
| where TimeGenerated {TimeRange}
| where ActivityStatusValue == "Success"
| where OperationNameValue has "delete"
| summarize SuppressionsCount = count(), Ressources = make_set(ResourceId, 20) by Caller, bin(TimeGenerated, 1h)
| where SuppressionsCount > 5
| order by SuppressionsCount desc
```
**À quoi ça sert :** alerte si un compte (`Caller`) supprime plus de 5 ressources en 1 heure — signe potentiel d'un script d'attaque ou d'une erreur humaine grave. `make_set` liste les ressources concernées pour l'investigation.

### Top des opérateurs les plus actifs
```kql
AzureActivity
| where TimeGenerated {TimeRange}
| where ActivityStatusValue == "Success"
| summarize Operations = count() by Caller
| top {TopN} by Operations desc
```
**À quoi ça sert :** identifie qui agit le plus sur l'environnement Azure. Cliquer sur une barre peuple `Ordinateur`/le contexte pour creuser plus loin (utile si l'appelant correspond à une automatisation exécutée depuis une VM).

---

## 4. Machines virtuelles (Windows/Linux)

### Connexions VM réussies vs échouées
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where Computer contains "{Ordinateur}"
| where EventID in (4624, 4625)
| extend Resultat = iff(EventID == 4624, "Succes", "Echec")
| summarize Count = count() by Resultat, bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```
**À quoi ça sert :** dans les journaux Windows, l'ID 4624 = connexion réussie, 4625 = échec. On les compare jour par jour pour repérer une hausse anormale d'échecs sur une machine.

### Top comptes/machines en échec
```kql
SecurityEvent
| where TimeGenerated {TimeRange}
| where EventID == 4625
| where Computer contains "{Ordinateur}"
| summarize EchecsCount = count() by Computer, Account = TargetUserName
| top {TopN} by EchecsCount desc
```
**À quoi ça sert :** classe les machines/comptes Windows les plus attaqués (ou mal configurés). Cliquer sur une ligne remplit le paramètre `Ordinateur` pour filtrer les autres visuels sur cette machine.

### Événements d'authentification suspects (Linux)
```kql
Syslog
| where TimeGenerated {TimeRange}
| where Computer contains "{Ordinateur}"
| where Facility == "auth" or ProcessName in ("sshd", "sudo")
| where SeverityLevel in ("err", "warning", "crit")
| summarize Count = count() by Computer, ProcessName, bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```
**À quoi ça sert :** l'équivalent Linux des ID 4624/4625 — on regarde les messages d'authentification (`sshd`, `sudo`) marqués comme erreur/avertissement/critique.

---

## 5. Incidents et alertes Microsoft Sentinel

### Répartition par sévérité
```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Severity in ({Severite})
| summarize Count = count() by Severity
```
**À quoi ça sert :** un même incident génère plusieurs lignes au fil de ses mises à jour ; `arg_max(TimeGenerated, *)` ne garde que la version la plus récente de chaque incident avant de compter par sévérité. Le filtre `Severite` permet de ne regarder, par exemple, que les incidents High/Medium.

### Tendance des incidents
```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Severity in ({Severite})
| summarize Count = count() by bin(TimeGenerated, 1d), Severity
| order by TimeGenerated asc
```
**À quoi ça sert :** même logique que ci-dessus, mais dans le temps, pour voir si le nombre d'incidents augmente ou diminue sur la période.

### Incidents actuellement ouverts
```kql
SecurityIncident
| where TimeGenerated {TimeRange}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Severity in ({Severite})
| where ("{StatutIncident}" == "Tous" or Status == "{StatutIncident}")
| project IncidentNumber, Title, Severity, Status, Owner = tostring(Owner.assignedTo), CreatedTime, LastModifiedTime
| order by Severity asc, CreatedTime desc
```
**À quoi ça sert :** la liste de travail de l'analyste : incidents non clos, triés par sévérité puis par date. Le filtre `StatutIncident` bascule entre « Tous », « New », « Active » ou « Closed ». Un lien sous ce tableau permet d'ouvrir directement la liste des incidents dans le portail Sentinel.

### Règles d'analyse en échec
```kql
SentinelHealth
| where TimeGenerated {TimeRange}
| where OperationName == "Analytics rule run"
| summarize RunsCount = count(), Failures = countif(Status == "Failure") by SentinelResourceName
| where Failures > 0
| order by Failures desc
```
**À quoi ça sert :** surveille la santé des règles de détection elles-mêmes — si une règle plante régulièrement, elle ne génère plus d'alertes et crée un angle mort de sécurité.

---

## 6. Santé de l'ingestion / des connecteurs

```kql
let SigninLogsLatency = SigninLogs | where TimeGenerated {TimeRange} | summarize DerniereIngestion = max(TimeGenerated) | extend Source = "SigninLogs";
let AuditLogsLatency = AuditLogs | where TimeGenerated {TimeRange} | summarize DerniereIngestion = max(TimeGenerated) | extend Source = "AuditLogs";
let AzureActivityLatency = AzureActivity | where TimeGenerated {TimeRange} | summarize DerniereIngestion = max(TimeGenerated) | extend Source = "AzureActivity";
let SecurityEventLatency = SecurityEvent | where TimeGenerated {TimeRange} | summarize DerniereIngestion = max(TimeGenerated) | extend Source = "SecurityEvent";
let SyslogLatency = Syslog | where TimeGenerated {TimeRange} | summarize DerniereIngestion = max(TimeGenerated) | extend Source = "Syslog";
SigninLogsLatency
| union AuditLogsLatency, AzureActivityLatency, SecurityEventLatency, SyslogLatency
| extend LatenceMinutes = datetime_diff('minute', now(), DerniereIngestion)
| extend Statut = case(LatenceMinutes > 30, "🔴 Latence critique (>30 min)",
                        LatenceMinutes > 15, "🟠 Latence élevée (>15 min)",
                        "🟢 Normal")
| project Source, DerniereIngestion, LatenceMinutes, Statut
| order by LatenceMinutes desc
```
**À quoi ça sert :** répond directement au Bug 1 anticipé dans le cahier des charges (latence d'ingestion). Pour chaque source de logs, on regarde l'heure du dernier événement reçu et on calcule combien de minutes se sont écoulées depuis (`datetime_diff`). Au-delà de 15 minutes, l'objectif du cahier des charges (US 2.1) n'est plus respecté, d'où le code couleur.

---

## Créer une nouvelle règle KQL — méthode rapide

1. **Filtrer le temps en premier** : commencez toujours par `| where TimeGenerated {TimeRange}` — c'est la requête qui s'exécute le plus vite et évite de scanner des données inutiles (cf. Bug 3 du cahier des charges).
2. **Filtrer ensuite sur les colonnes utiles** (`EventID`, `Category`, `ResultType`...) avant tout `summarize` ou `join`.
3. **Regrouper avec `summarize ... by`** pour compter/agréger, `bin(TimeGenerated, 1d)` pour découper par jour.
4. **Trier et limiter** avec `order by` et `top N` pour ne garder que l'essentiel.
5. **Tester dans "Logs"** du workspace avant de l'ajouter au classeur ou de la transformer en Analytics Rule.