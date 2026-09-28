#!/usr/bin/env bash
#
# generate_test_syslog_alerts.sh
#
# Génère des entrées syslog synthétiques via `logger` pour déclencher/tester
# les règles d'alerte Microsoft Sentinel décrites dans
# sentinel_syslog_alert_rules.md.
#
# ATTENTION :
#   - À exécuter uniquement sur une machine de LAB/TEST déjà connectée à ton
#     workspace Sentinel (agent AMA + DCR Syslog), jamais sur un serveur de
#     production partagé : ces logs imitent des événements de sécurité réels
#     et peuvent semer la confusion chez les analystes SOC.
#   - Nécessite `logger` (paquet bsdutils/util-linux, présent par défaut sur
#     la plupart des distros) et rsyslog/syslog-ng configuré pour écrire vers
#     les facilities auth/authpriv/cron.
#   - Ne modifie AUCUN compte, service ou fichier réel : tout est simulé via
#     `logger`, sauf la section "sudo réel" clairement indiquée.
#
# Usage :
#   ./generate_test_syslog_alerts.sh all
#   ./generate_test_syslog_alerts.sh ssh_bruteforce
#   ./generate_test_syslog_alerts.sh --list
#
set -euo pipefail

TAG_MARK="SIEMTEST"   # marqueur pour repérer facilement le trafic de test
FAKE_IP="203.0.113.77"      # adresse documentaire RFC5737, ne route nulle part
FAKE_USER="testuser01"

# Seuils des règles Sentinel visées (cf. sentinel_syslog_alert_rules.md) :
#   - Règle "Failed logon attempts in authpriv" : > 15 échecs authpriv
#     (authentication failure + user unknown) depuis la même IP
#   - Règle "SSH potential brute force"        : >= 15 échecs SSH sur une
#     fenêtre de 4h (sur une période totale observée de 24h)
# On génère volontairement 1 tentative de plus que le seuil pour ne pas
# tomber pile sur la limite (off-by-one côté requête KQL "> 15" vs ">= 15").
ATTEMPTS=16

log() { echo "[generate_test_syslog_alerts] $*"; }

# ---------------------------------------------------------------------------
# 1. Brute force SSH — échecs de mot de passe répétés (facility auth)
#    Cible la règle "ssh potential brute force" (>=15 échecs / 4h)
# ---------------------------------------------------------------------------
scenario_ssh_bruteforce() {
  log "Scénario 1: brute force SSH — ${ATTEMPTS} tentatives (${TAG_MARK})"
  local pid=$((RANDOM % 9000 + 1000))
  for i in $(seq 1 "$ATTEMPTS"); do
    logger -p auth.warning -t sshd \
      "sshd[${pid}]: Failed password for invalid user ${FAKE_USER} from ${FAKE_IP} port 2222 ssh2 [${TAG_MARK}]"
    sleep 0.5
  done
  log "  -> ${ATTEMPTS} échecs envoyés depuis ${FAKE_IP} (seuil règle: 15)."
}

# ---------------------------------------------------------------------------
# 2. Connexion SSH réussie après une série d'échecs
# ---------------------------------------------------------------------------
scenario_ssh_success_after_fail() {
  log "Scénario 2: succès SSH après échecs (${TAG_MARK})"
  local pid=$((RANDOM % 9000 + 1000))
  for i in $(seq 1 5); do
    logger -p auth.warning -t sshd \
      "sshd[${pid}]: Failed password for ${FAKE_USER} from ${FAKE_IP} port 2222 ssh2 [${TAG_MARK}]"
    sleep 1
  done
  logger -p auth.notice -t sshd \
    "sshd[${pid}]: Accepted password for ${FAKE_USER} from ${FAKE_IP} port 2222 ssh2 [${TAG_MARK}]"
}

# ---------------------------------------------------------------------------
# 3. Échecs d'authentification authpriv avec "user unknown"
#    Cible la règle "Failed logon attempts in authpriv" (authentication
#    failure + user unknown, > 15 tentatives depuis la même IP)
# ---------------------------------------------------------------------------
scenario_authpriv_unknown_user() {
  log "Scénario 3: échecs authpriv 'user unknown' — ${ATTEMPTS} tentatives (${TAG_MARK})"
  local pid=$((RANDOM % 9000 + 1000))
  for i in $(seq 1 "$ATTEMPTS"); do
    logger -p authpriv.warning -t sshd \
      "sshd[${pid}]: pam_unix(sshd:auth): check pass; user unknown [${TAG_MARK}]"
    logger -p authpriv.warning -t sshd \
      "sshd[${pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=${FAKE_IP}  user=${FAKE_USER} [${TAG_MARK}]"
    sleep 0.5
  done
  log "  -> ${ATTEMPTS} paires 'user unknown'/'authentication failure' envoyées depuis ${FAKE_IP}."
}

# ---------------------------------------------------------------------------
# 4. Échecs sudo répétés
# ---------------------------------------------------------------------------
scenario_sudo_failed() {
  log "Scénario 4: échecs sudo (${TAG_MARK})"
  for i in $(seq 1 3); do
    logger -p authpriv.warning -t sudo \
      "pam_unix(sudo:auth): authentication failure; logname=${FAKE_USER} uid=1001 euid=0 tty=/dev/pts/0 user=${FAKE_USER} [${TAG_MARK}]"
    sleep 1
  done
}

# ---------------------------------------------------------------------------
# 5. Commande sudo exécutée avec succès (simulée dans le log uniquement)
# ---------------------------------------------------------------------------
scenario_sudo_command() {
  log "Scénario 5: commande sudo simulée (${TAG_MARK})"
  logger -p authpriv.info -t sudo \
    "${FAKE_USER} : TTY=pts/0 ; PWD=/home/${FAKE_USER} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow [${TAG_MARK}]"
}

# ---------------------------------------------------------------------------
# 6. Ajout d'un utilisateur au groupe sudo/wheel (log simulé, pas d'action réelle)
# ---------------------------------------------------------------------------
scenario_add_to_sudo_group() {
  log "Scénario 6: ajout au groupe sudo (${TAG_MARK})"
  logger -p authpriv.notice -t usermod \
    "add '${FAKE_USER}' to group 'sudo' [${TAG_MARK}]"
}

# ---------------------------------------------------------------------------
# 7. Création d'un nouveau compte utilisateur (log simulé)
# ---------------------------------------------------------------------------
scenario_new_user() {
  log "Scénario 7: nouveau compte utilisateur (${TAG_MARK})"
  logger -p authpriv.info -t useradd \
    "new user: name=${FAKE_USER}, UID=1099, GID=1099, home=/home/${FAKE_USER}, shell=/bin/bash [${TAG_MARK}]"
}

# ---------------------------------------------------------------------------
# 8. Modification d'une tâche cron (log simulé)
# ---------------------------------------------------------------------------
scenario_cron_edit() {
  log "Scénario 8: édition crontab (${TAG_MARK})"
  logger -p cron.info -t crontab \
    "(${FAKE_USER}) BEGIN EDIT (${FAKE_USER}) [${TAG_MARK}]"
  logger -p cron.info -t crontab \
    "(${FAKE_USER}) REPLACE (${FAKE_USER}) [${TAG_MARK}]"
}

# ---------------------------------------------------------------------------
# 9. Suppression / purge de logs (log simulé — ne touche à aucun vrai fichier)
# ---------------------------------------------------------------------------
scenario_log_tampering() {
  log "Scénario 9: purge de log simulée (${TAG_MARK})"
  logger -p syslog.warning -t shred \
    "shred: /var/log/auth.log: removed [${TAG_MARK}]"
}

# ---------------------------------------------------------------------------
# 10. Arrêt suspect d'un service critique (log simulé)
# ---------------------------------------------------------------------------
scenario_service_stop() {
  log "Scénario 10: arrêt de service critique simulé (${TAG_MARK})"
  logger -p daemon.notice -t systemd \
    "Stopped Security Auditing Service. [${TAG_MARK}]"
  logger -p daemon.notice -t systemd \
    "sshd.service: Deactivated successfully. [${TAG_MARK}]"
}

list_scenarios() {
  cat <<EOF
Scénarios disponibles :
  ssh_bruteforce         -> Règle "ssh potential brute force" (${ATTEMPTS} échecs SSH, facility auth)
  ssh_success_after_fail -> succès après échecs
  authpriv_unknown_user  -> Règle "Failed logon attempts in authpriv" (${ATTEMPTS} x user unknown + authentication failure)
  sudo_failed            -> échecs sudo
  sudo_command           -> commande sudo
  add_to_sudo_group      -> ajout groupe sudo
  new_user               -> création utilisateur
  cron_edit              -> édition cron
  log_tampering          -> purge de log
  service_stop           -> arrêt service
  all                    -> exécute tous les scénarios ci-dessus
EOF
}

main() {
  local target="${1:-}"

  if [[ -z "$target" || "$target" == "-h" || "$target" == "--help" ]]; then
    list_scenarios
    exit 0
  fi

  if [[ "$target" == "--list" ]]; then
    list_scenarios
    exit 0
  fi

  if ! command -v logger >/dev/null 2>&1; then
    echo "Erreur: la commande 'logger' est introuvable (paquet util-linux/bsdutils)." >&2
    exit 1
  fi

  case "$target" in
    ssh_bruteforce)          scenario_ssh_bruteforce ;;
    ssh_success_after_fail)  scenario_ssh_success_after_fail ;;
    authpriv_unknown_user)   scenario_authpriv_unknown_user ;;
    sudo_failed)             scenario_sudo_failed ;;
    sudo_command)            scenario_sudo_command ;;
    add_to_sudo_group)       scenario_add_to_sudo_group ;;
    new_user)                scenario_new_user ;;
    cron_edit)               scenario_cron_edit ;;
    log_tampering)           scenario_log_tampering ;;
    service_stop)            scenario_service_stop ;;
    all)
      scenario_ssh_bruteforce
      scenario_ssh_success_after_fail
      scenario_authpriv_unknown_user
      scenario_sudo_failed
      scenario_sudo_command
      scenario_add_to_sudo_group
      scenario_new_user
      scenario_cron_edit
      scenario_log_tampering
      scenario_service_stop
      ;;
    *)
      echo "Scénario inconnu: $target" >&2
      list_scenarios
      exit 1
      ;;
  esac

  log "Terminé. Vérifie dans Sentinel (Logs) avec :"
  log "  Syslog | where SyslogMessage has \"${TAG_MARK}\" | order by TimeGenerated desc"
}

main "$@"