# Tests de simulation

[← Retour à la documentation principale](../README.md)

## Objectif

Générer des événements de sécurité synthétiques sur les VM Linux et Windows pour tester les règles de détection ([Détection](../detection/README.md)).

> **État** : ce dossier documente des **scripts et des scénarios**. Aucun résultat, statut ou capture de test n'est présent dans `/docs`. Aucun test n'est donc présenté comme réussi.

> **Données sensibles** : la section « Connexion aux VM » contient des adresses IP publiques et des noms d'utilisateur, conservés tels quels depuis les sources.

## Connexion aux VM

```bash
# Linux
ssh -i id_rsa user@ip

# Windows
xfreerdp /u:user /d:"" /v:ip /smart-sizing

xfreerdp /u:user /d:"smartovate.local" /v:IP /smart-sizing

xfreerdp /u:user /d:"" \
/v:IP \
/smart-sizing \
/cert:ignore
```

## Test Linux — `generate_test_syslog_alerts.sh`

Le script génère des entrées syslog synthétiques via `logger`. Pour tester : téléverser le fichier sur la VM, puis le lancer.

```bash
# voir la liste des scénarios
./generate_test_syslog_alerts.sh --list

# un scénario précis, ex: brute force SSH
./generate_test_syslog_alerts.sh ssh_bruteforce

# tous les scénarios d'un coup
./generate_test_syslog_alerts.sh all
```

Caractéristiques du script : marqueur de test `SIEMTEST`, IP fictive `IP` (adresse de documentation RFC 5737), utilisateur fictif `testuser01`. À exécuter sur une machine de laboratoire uniquement. Tous les scénarios sont simulés par `logger` : aucun compte ni fichier réel n'est modifié.

| # | Scénario | Contenu simulé | Règle visée (d'après le script) |
|---|---|---|---|
| 1 | `ssh_bruteforce` | 16 échecs « Failed password » sshd | « ssh potential brute force » (seuil 15) |
| 2 | `ssh_success_after_fail` | 5 échecs SSH puis un succès | — |
| 3 | `authpriv_unknown_user` | 16 paires « user unknown » / « authentication failure » | « Failed logon attempts in authpriv » (seuil 15) |
| 4 | `sudo_failed` | 3 échecs d'authentification sudo | — |
| 5 | `sudo_command` | Commande sudo simulée dans le log | — |
| 6 | `add_to_sudo_group` | Ajout simulé d'un utilisateur au groupe sudo | — |
| 7 | `new_user` | Création simulée d'un compte | — |
| 8 | `cron_edit` | Modification simulée d'une crontab | — |
| 9 | `log_tampering` | Purge simulée d'un fichier de log | — |
| 10 | `service_stop` | Arrêt simulé de services (audit, sshd) | — |

Pour retrouver les événements dans Sentinel (commande indiquée par le script) :

```kql
Syslog | where SyslogMessage has "SIEMTEST" | order by TimeGenerated desc
```

## Test Windows — `powershell.ps1`

Après connexion à la VM Windows, exécuter le script dans PowerShell. Il simule plusieurs événements de sécurité Windows (`SecurityEvent`).

| # | Action simulée | Event ID |
|---|---|---|
| 1 | 6 échecs de connexion (`net use` avec de mauvais identifiants) | 4625 |
| 2 | Création du compte local `HackerTestUser` | 4720 |
| 3 | Ajout du compte au groupe Administrateurs | 4732 |
| 4 | Suppression du compte de test | — |

Le script rappelle un délai d'ingestion habituel de 5 à 15 minutes avant que les événements remontent dans Sentinel.

## Résultats

Pour chacun des 10 scénarios Linux et des 4 actions Windows : résultat obtenu, alerte générée, statut.

[Test non documenté dans /docs]

Les tests des règles personnalisées, des Workbooks, de la Watchlist et du RBAC : [Test non documenté dans /docs]

## Références

- La méthode de test recommandée pour une nouvelle règle (syntaxe, données, détection positive, détection négative, seuil, performance) est décrite dans [kql-guide.md](../detection/kql-guide.md). Ce n'est pas un compte rendu de test.
- Le script Linux cite en commentaire un fichier `sentinel_syslog_alert_rules.md`, absent de `/docs`.
- Le README d'origine de ce dossier se terminait par le contenu de [TrustedUsers.csv](../TrustedUsers.csv) (en-tête `UserPrincipalName` et une adresse e-mail).
