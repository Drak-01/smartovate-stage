# Guide de création de nouvelles règles de détection KQL

[← Retour à la détection](./README.md) · [← Retour à la documentation principale](../README.md)

## 1. Introduction

### 1.1 Objectif du guide

Ce guide décrit la méthode à suivre pour créer, tester et déployer une nouvelle règle de détection dans Microsoft Sentinel à l’aide du **Kusto Query Language (KQL)**.

L'objectif est de permettre à un analyste sécurité de :

* identifier la source de données appropriée ;
* construire une requête KQL ;
* filtrer les événements pertinents ;
* agréger les événements ;
* définir un seuil de détection ;
* tester la requête ;
* transformer la requête en règle analytique ;
* vérifier les résultats ;
* documenter la règle.

### 1.2 Principe général

Une règle de détection suit généralement le processus suivant :

```text
Source de logs
     ↓
Filtrage des événements
     ↓
Transformation / enrichissement
     ↓
Agrégation
     ↓
Définition d'un seuil
     ↓
Résultat de détection
     ↓
Règle analytique Sentinel
     ↓
Incident de sécurité
```

---

# 2. Introduction au Kusto Query Language (KQL)

Kusto Query Language (KQL) est un langage de requête en lecture seule utilisé pour analyser les données stockées dans Azure Monitor, Microsoft Sentinel et d'autres services Azure.

Une requête KQL permet notamment de :

* sélectionner une table ;
* filtrer les événements ;
* sélectionner des colonnes ;
* créer de nouvelles colonnes ;
* agréger les données ;
* compter les événements ;
* rechercher des valeurs ;
* créer des visualisations.

Une requête KQL suit généralement le modèle :

```Kusto
Table
| opérateur
| opérateur
| opérateur
```

Chaque opérateur reçoit le résultat de l'opérateur précédent.

---

# 3. Identifier la source de données

Avant de créer une règle, il faut déterminer dans quelle table se trouvent les événements nécessaires à la détection.

Exemples de tables couramment utilisées dans Microsoft Sentinel :

| Source              | Table           |
| ------------------- | --------------- |
| Connexions Entra ID | `SigninLogs`    |
| Audit Entra ID      | `AuditLogs`     |
| Activités Azure     | `AzureActivity` |
| Événements Windows  | `SecurityEvent` |
| Événements Linux    | `Syslog`        |

La première étape consiste donc à vérifier que les données nécessaires sont effectivement présentes dans la table.

Exemple :

```Kusto
SigninLogs
| take 10
```

Ou :

```Kusto
SecurityEvent
| take 10
```

Cette étape permet de vérifier la structure des données avant d'écrire la règle.

---

# 4. Construire progressivement une requête KQL

Une règle ne doit pas être écrite directement sous sa forme finale.

Il est recommandé de construire la requête progressivement :

```text
1. Identifier la table
2. Observer les données
3. Ajouter le filtre temporel
4. Ajouter les conditions de détection
5. Sélectionner les colonnes utiles
6. Ajouter les transformations
7. Agréger les événements
8. Ajouter le seuil
9. Vérifier le résultat
```

---

# 5. Opérateur `where`

L'opérateur `where` permet de filtrer les événements.

### 5.1 Filtrer sur une période

```Kusto
SecurityEvent
| where TimeGenerated > ago(1d)
```

Cette requête retourne les événements générés au cours des dernières 24 heures.

### 5.2 Ajouter plusieurs conditions

```Kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
```

Il est également possible de combiner les conditions :

```Kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
    and Account != ""
```

### 5.3 Bonne pratique

Une règle analytique doit généralement contenir une fenêtre temporelle afin de limiter la quantité de données analysées.

Exemple :

```Kusto
SecurityEvent
| where TimeGenerated >= ago(1h)
```

---

# 6. Instruction `let`

L'instruction `let` permet de définir des variables afin de rendre les requêtes plus lisibles et facilement configurables.

Exemple :

```Kusto
let timeframe = 1h;
let threshold = 5;

SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4625
```

Dans cet exemple :

* `timeframe` définit la période d'analyse ;
* `threshold` définit le seuil de détection.

L'utilisation de variables est recommandée pour les règles qui possèdent plusieurs paramètres.

---

# 7. Déclarer des tables ou listes dynamiques

KQL permet également de créer des listes de valeurs directement dans une requête.

Exemple :

```Kusto
let suspiciousAccounts = datatable(account:string)
[
    @"\administrator",
    @"\NT AUTHORITY\SYSTEM"
];

SecurityEvent
| where Account in (suspiciousAccounts)
```

Cette technique peut être utilisée lorsqu'une règle doit comparer les événements à une liste prédéfinie de valeurs.

Elle peut notamment être utilisée pour :

* des comptes sensibles ;
* des processus suspects ;
* des adresses IP ;
* des noms d'hôtes ;
* des applications spécifiques.

---

# 8. Opérateur `extend`

L'opérateur `extend` permet de créer une nouvelle colonne à partir des données existantes.

Exemple :

```Kusto
SecurityEvent
| where ProcessName != ""
| extend ProcessLength = strlen(ProcessName)
```

La nouvelle colonne `ProcessLength` contient la longueur du nom du processus.

L'opérateur `extend` est particulièrement utile pour :

* calculer une valeur ;
* normaliser une donnée ;
* extraire une information ;
* préparer les données avant une agrégation.

---

# 9. Opérateur `project`

L'opérateur `project` permet de sélectionner les colonnes à conserver dans le résultat.

Exemple :

```Kusto
SecurityEvent
| project TimeGenerated, Computer, Account, EventID
```

Il est également possible de renommer une colonne :

```Kusto
SecurityEvent
| project
    Date = TimeGenerated,
    Machine = Computer,
    User = Account
```

### Bonne pratique

À la fin d'une requête, conserver uniquement les informations nécessaires à l'analyse facilite la lecture des résultats.

---

# 10. Opérateur `summarize`

L'opérateur `summarize` permet d'agréger plusieurs événements afin de produire des statistiques.

Exemple :

```Kusto
SecurityEvent
| summarize count() by Account
```

Cette requête compte le nombre d'événements pour chaque compte.

Autre exemple :

```Kusto
SecurityEvent
| where EventID == 4688
| summarize count() by Process, Computer
```

Cette requête permet de compter les créations de processus par machine et par processus.

---

# 11. Fonctions d'agrégation importantes

## 11.1 `count()`

Compte le nombre d'événements.

```Kusto
SecurityEvent
| summarize count() by Account
```

## 11.2 `countif()`

Compte uniquement les événements qui respectent une condition.

```Kusto
SecurityEvent
| summarize FailedLogins = countif(EventID == 4625) by Account
```

## 11.3 `dcount()`

Retourne une estimation du nombre de valeurs distinctes.

Exemple :

```Kusto
SigninLogs
| summarize ApplicationCount = dcount(AppDisplayName)
    by UserPrincipalName
```

---

# 12. Définir un seuil de détection

Une règle de détection doit généralement définir un seuil.

Exemple :

```Kusto
let timeframe = 30d;
let threshold = 3;

SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "Invalid password"
| summarize applicationCount = dcount(AppDisplayName)
    by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

Dans cet exemple, la détection est déclenchée lorsque le nombre d'applications distinctes concernées atteint le seuil défini.

### Principe

```text
Événements
    ↓
Agrégation
    ↓
Calcul du nombre
    ↓
Comparaison avec le seuil
    ↓
Détection
```

Le seuil doit être choisi en fonction du comportement attendu et du risque de faux positifs.

---

# 13. Ajouter une fenêtre temporelle

La fenêtre temporelle définit la période pendant laquelle les événements sont analysés.

Exemples :

```Kusto
ago(15m)
ago(1h)
ago(24h)
ago(7d)
ago(30d)
```

Exemple :

```Kusto
SecurityEvent
| where TimeGenerated >= ago(1h)
```

Une règle de brute force peut par exemple analyser les échecs de connexion sur une fenêtre courte :

```Kusto
let timeframe = 15m;
let threshold = 10;

SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4625
| summarize FailedAttempts = count()
    by Account, IpAddress
| where FailedAttempts >= threshold
```

---

# 14. Construire une règle de détection complète

Une règle complète doit généralement contenir :

1. les paramètres ;
2. la source de données ;
3. la fenêtre temporelle ;
4. les conditions ;
5. l'agrégation ;
6. le seuil ;
7. les informations nécessaires à l'investigation.

Exemple :

```Kusto
let timeframe = 15m;
let threshold = 10;

SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Account, IpAddress, Computer
| where FailedAttempts >= threshold
| project
    Account,
    IpAddress,
    Computer,
    FailedAttempts,
    FirstAttempt,
    LastAttempt
```

Cette structure fournit à l'analyste les informations nécessaires pour examiner la détection.

---

# 15. Ajouter une visualisation

L'opérateur `render` permet de générer une visualisation à partir des résultats.

Les visualisations courantes sont :

* `areachart`
* `barchart`
* `columnchart`
* `piechart`
* `scatterchart`
* `timechart`

Exemple :

```Kusto
SecurityEvent
| summarize count() by Account
| render barchart
```

Pour observer une évolution temporelle :

```Kusto
SecurityEvent
| summarize count() by bin(TimeGenerated, 1h)
| render timechart
```

Les visualisations sont particulièrement utiles pendant la phase de test et d'analyse.

---

# 16. Méthode de création d'une nouvelle règle

Chaque nouvelle règle doit suivre les étapes suivantes.

## Étape 1 — Définir l'objectif de sécurité

Avant d'écrire la requête, définir clairement ce que la règle doit détecter.

Exemple :

> Détecter un nombre anormalement élevé d'échecs d'authentification provenant d'une même adresse IP.

---

## Étape 2 — Identifier la source

Déterminer la table contenant les événements nécessaires.

Exemple :

```text
Windows → SecurityEvent
Entra ID → SigninLogs
Linux → Syslog
Azure → AzureActivity
```

---

## Étape 3 — Identifier les champs nécessaires

Lister les champs utilisés par la règle.

Exemple :

```text
TimeGenerated
Account
IpAddress
EventID
Computer
```

---

## Étape 4 — Construire la requête de base

Commencer avec :

```Kusto
SecurityEvent
| where TimeGenerated >= ago(1h)
```

---

## Étape 5 — Ajouter les conditions

Exemple :

```Kusto
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
```

---

## Étape 6 — Ajouter l'agrégation

```Kusto
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
| summarize FailedAttempts = count()
    by Account, IpAddress
```

---

## Étape 7 — Ajouter le seuil

```Kusto
let threshold = 10;

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
| summarize FailedAttempts = count()
    by Account, IpAddress
| where FailedAttempts >= threshold
```

---

## Étape 8 — Vérifier les résultats

La requête doit être exécutée dans **Microsoft Sentinel / Logs** afin de vérifier :

* qu'elle ne retourne pas d'erreur ;
* qu'elle retourne les événements attendus ;
* que les colonnes sont correctes ;
* que le seuil est pertinent ;
* que le nombre de résultats est acceptable.

---

## Étape 9 — Évaluer les faux positifs

Une règle ne doit pas uniquement fonctionner techniquement.

Il faut également vérifier si les résultats correspondent réellement à des comportements suspects.

Questions à se poser :

* Le seuil est-il trop faible ?
* La règle génère-t-elle trop d'alertes ?
* Certains comptes légitimes sont-ils concernés ?
* Certaines machines génèrent-elles naturellement beaucoup d'événements ?
* La fenêtre temporelle est-elle adaptée ?

---

## Étape 10 — Créer la règle analytique

Une fois la requête validée, elle peut être intégrée dans une **Analytics Rule** de Microsoft Sentinel.

Les principaux paramètres à définir sont :

* nom de la règle ;
* description ;
* gravité ;
* requête KQL ;
* fréquence d'exécution ;
* période de recherche ;
* seuil ;
* entités à mapper ;
* tactique MITRE ATT&CK ;
* technique MITRE ATT&CK ;
* paramètres d'incident ;
* automatisation éventuelle.

---

# 17. Mapping des entités

Une bonne règle doit fournir suffisamment d'informations pour identifier la cible de l'activité.

Les entités peuvent notamment être :

* Account ;
* IP Address ;
* Host ;
* User ;
* Application ;
* URL.

Exemple de résultat :

```Kusto
| project
    Account,
    IpAddress,
    Computer,
    FailedAttempts
```

Ces champs pourront ensuite être utilisés pour faciliter l'investigation de l'incident.

---

# 18. Classification MITRE ATT&CK

Lorsque cela est pertinent, la règle doit être associée à une tactique et à une technique MITRE ATT&CK.

Exemple conceptuel :

```text
Tactique :
Credential Access

Technique :
Brute Force
```

Cette classification permet de mieux organiser les détections et d'identifier les techniques couvertes par le système de détection.

---

# 19. Tester une nouvelle règle

Avant de mettre une règle en production, effectuer les tests suivants.

### Test 1 — Syntaxe

Vérifier que la requête KQL s'exécute sans erreur.

### Test 2 — Données

Vérifier que les données nécessaires sont présentes.

### Test 3 — Détection positive

Générer ou rechercher un événement correspondant au scénario attendu.

### Test 4 — Détection négative

Vérifier qu'un comportement normal ne déclenche pas inutilement la règle.

### Test 5 — Seuil

Tester différents seuils afin de trouver un compromis entre :

```text
Détection
     ↕
Faux positifs
```

### Test 6 — Performance

Vérifier que la requête ne traite pas inutilement une quantité excessive de données.

---

# 20. Bonnes pratiques KQL

## 20.1 Toujours limiter la période

Préférer :

```Kusto
| where TimeGenerated >= ago(1h)
```

plutôt qu'une recherche inutilement globale.

## 20.2 Filtrer le plus tôt possible

Exemple :

```Kusto
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
| summarize count() by Account
```

Le filtrage précoce réduit généralement la quantité de données à traiter.

## 20.3 Utiliser `let` pour les paramètres

```Kusto
let timeframe = 15m;
let threshold = 10;
```

Cela facilite la maintenance.

## 20.4 Retourner uniquement les colonnes utiles

Utiliser `project` pour simplifier le résultat.

## 20.5 Éviter les seuils arbitraires

Un seuil doit être justifié par :

* la politique de sécurité ;
* les données historiques ;
* le comportement normal ;
* le risque ;
* les tests effectués.

---

# 21. Structure recommandée d'une règle

Chaque règle créée dans le projet doit être documentée selon le modèle suivant :

```text
Nom de la règle :
Description :
Objectif :
Source de données :
Table :
Fenêtre temporelle :
Seuil :
Gravité :
Tactique MITRE :
Technique MITRE :

Champs principaux :
- TimeGenerated
- Account
- IPAddress
- Computer

Requête KQL :
...

Résultat attendu :
...

Tests effectués :
...

Faux positifs identifiés :
...

Actions de réduction des faux positifs :
...
```

---

### Logique

```text
SecurityEvent
      ↓
Dernières 15 minutes
      ↓
EventID 4625
      ↓
Regroupement par compte + IP + machine
      ↓
Comptage des échecs
      ↓
≥ 10 échecs
      ↓
Détection
```

### Informations retournées

La règle retourne :

* le compte concerné ;
* l'adresse IP ;
* la machine ;
* le nombre d'échecs ;
* la première tentative ;
* la dernière tentative.

Ces informations permettent à l'analyste SOC de commencer rapidement l'investigation.

---

## Conclusion

La création d'une règle de détection ne consiste pas uniquement à écrire une requête KQL. Une règle efficace doit associer :

**source de données + logique de détection + fenêtre temporelle + seuil + contexte d'investigation + classification MITRE + tests.**

Cette méthode permet de créer des règles cohérentes, maintenables et adaptées à une utilisation dans un environnement SOC.
