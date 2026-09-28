# Détection des menaces

[← Retour à la documentation principale](../README.md)

## Objectif

Présenter les règles de détection présentes dans `/docs` : règles natives Microsoft activées et requêtes KQL personnalisées. Aucune capture ni aucun résultat n'est disponible pour ces règles.

## Règles natives Microsoft

13 règles natives sont listées, par source. Les paramètres sont ceux indiqués dans les sources.

| Source | Règle | Objectif | Paramètres indiqués |
|---|---|---|---|
| Linux (Syslog) | Failed logon attempts in authpriv | Corréler les échecs d'authentification avec des utilisateurs inexistants (facility authpriv) pour repérer force brute ou accès non autorisé | Seuil par défaut : 15 tentatives depuis une même IP |
| Linux (Syslog) | SSH potential brute force | Identifier les IP ayant ≥ 15 échecs SSH sur une fenêtre de 4 h, sur une période totale de 24 h | 15 échecs / 4 h / 24 h |
| Windows | SecurityEvent - Multiple authentication failures followed by a success | Comptes avec plusieurs échecs consécutifs suivis d'un succès rapide (force brute ou compte de service mal configuré) | Lookback 2 h, fenêtre 1 h, seuil 5 échecs |
| Windows | Excessive Windows Logon Failures | Comptes avec plus de 50 échecs de connexion aujourd'hui et au moins 33 % du nombre d'échecs des 7 jours précédents | 50 échecs ; 33 % |
| Entra ID | Attempts to sign in to disabled accounts | Échecs de connexion à des comptes désactivés sur plusieurs applications Azure | Seuil par défaut : 3 applications |
| Entra ID | Account created or deleted by non-approved user | Comptes créés ou supprimés par des utilisateurs d'une liste d'utilisateurs non approuvés (liste à renseigner avant exécution) | — |
| Entra ID | MFA Spamming followed by Successful login | Spam MFA suivi d'une connexion réussie dans une fenêtre de temps | 10 échecs, 1 succès, fenêtre 5 min |
| Entra ID | Azure RBAC (Elevate Access) | Élévation d'accès d'un Global Administrator à tous les abonnements et groupes de gestion (rôle User Access Administrator à la racine) | — |
| Entra ID | Brute force attack against an Entra-authenticated Windows device | Plusieurs échecs suivis d'un succès sur des appareils Windows authentifiés via Entra ID (joints Entra, hybrides, Cloud PC Windows 365) | Fenêtre de temps définie |
| Entra ID | PIM Elevation Request Rejected | Rejet d'une élévation de rôle privilégié via PIM ; indicateur de compromission possible du compte demandeur | — |
| Azure Activity | Creation of expensive computes in Azure | Création de VM de grande taille ou coûteuses (GPU, nombreux vCPU) | — |
| Azure Activity | Suspicious number of resource creation or deployment activities | Nombre anormal de créations de VM ou de déploiements, par rapport à une référence établie par individu | — |
| Azure Activity | Suspicious Resource deployment | Déploiement rare de Resource / ResourceGroup par un appelant jamais vu | — |

Preuve d'activation (capture) : [Information non disponible dans /docs]

## Règles personnalisées

3 requêtes KQL personnalisées sont présentes. Pour chacune, la sévérité, la fréquence, la période de recherche, le mapping d'entités, la tactique MITRE, le résultat et la capture sont [Information non disponible dans /docs].

### Attaque par force brute sur Linux

- **Objectif** : détecter les échecs `sshd` « Failed password » répétés.
- **Logique** : 5 dernières minutes ; regroupement par machine, IP hôte et message ; seuil ≥ 7 échecs.

```kql
Syslog
| where TimeGenerated > ago(5m)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| summarize
    FailedAttempts = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by Computer, HostIP, SyslogMessage
| where FailedAttempts >= 7
```

### Windows Brute-Force Detection

- **Objectif** : détecter les échecs de connexion Windows répétés (EventID 4625).
- **Logique** : 5 dernières minutes ; regroupement par compte, IP et machine ; seuil ≥ 10 échecs.

```kql
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by Account, IpAddress, Computer
| where FailedAttempts >= 10
| project
    LastFailure,
    Account,
    IpAddress,
    Computer,
    FailedAttempts
```

### Failed Sudo Privilege Elevation (tentatives non autorisées)

- **Objectif** : détecter les échecs d'élévation de privilèges `sudo` (« authentication failure » ou « command not allowed »).
- **Logique** : regroupement par machine, utilisateur et tranche de 15 minutes ; seuil ≥ 3 échecs.

```kql
Syslog
| where ProcessName == "sudo"
| where SyslogMessage has "authentication failure" or SyslogMessage has "command not allowed"
| extend User = extract(@"user=(\S+)", 1, SyslogMessage)
| summarize FailedSudoCount = count() by Computer, User, bin(TimeGenerated, 15m)
| where FailedSudoCount >= 3
```

### Blocs KQL vides

Le document source contenait 7 blocs KQL vides à la suite de ces règles. Ils ne correspondent à aucune règle documentée : [Information non disponible dans /docs]

### Requête de force brute Entra ID

Le [Workbook](../workbooks/README.md) contient une requête « Détection Brute Force » sur `SigninLogs` (≥ 5 échecs en 30 min suivis d'un succès), présentée comme la règle personnalisée demandée par l'US 3.2. Aucune configuration d'Analytics Rule correspondante n'est documentée.

## Watchlist

- Les Watchlists maintiennent des listes de référence utilisées par certaines règles de détection.
- Le fichier [TrustedUsers.csv](../TrustedUsers.csv) contient une colonne `UserPrincipalName` et une valeur (une adresse e-mail de compte).
- Le README d'origine mentionne « création de watchlist » : « elle consiste l'email de confiance ».
- Procédure de création, capture et règle qui utilise cette Watchlist : [Information non disponible dans /docs]

## Méthode de création d'une règle

Le guide [kql-guide.md](./kql-guide.md) décrit la méthode complète (KQL, seuils, fenêtres temporelles, mapping d'entités, MITRE ATT&CK, tests, fiche de règle). Ses exemples sont génériques : ce ne sont pas des règles déployées.

Étapes principales : définir l'objectif de sécurité, identifier la source et les champs, construire la requête (fenêtre temporelle, conditions, agrégation, seuil), vérifier les résultats dans Sentinel / Logs, évaluer les faux positifs, puis créer l'Analytics Rule.

| Source | Table |
|---|---|
| Connexions Entra ID | `SigninLogs` |
| Audit Entra ID | `AuditLogs` |
| Activités Azure | `AzureActivity` |
| Événements Windows | `SecurityEvent` |
| Événements Linux | `Syslog` |

## Références

- Scripts de simulation d'événements : [Tests](../test/README.md)
- Modélisation d'une règle et d'un incident : [UML](../diagramme_uml/README.md)
