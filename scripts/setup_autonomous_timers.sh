#!/usr/bin/env bash
# =============================================================================
# scripts/setup_autonomous_timers.sh - Personal OS Scheduled Worker Timers
# =============================================================================
# Generates portable systemd user .service and .timer units in
# ~/.config/systemd/user/ for the 5 scheduled background jobs:
#   - pos-auto-s4        (Daily 04:00)        - Nightly Repo Self-Health & AST Check
#   - pos-auto-scouts    (Mon,Thu 06:00)      - GitHub Trending & Tech Discovery Scouts
#   - pos-auto-radar     (Daily 07:45)        - Macro & Geopolitical News Filter
#   - pos-auto-draft-pr  (Sat 07:30)          - Isolated Worktree Draft PR Factory
#   - pos-auto-digest    (Wed,Sat 09:00)      - Tactical & R&D Digest Summary
#
# Flags:
#   --dry-run, --print-units  Print all unit/timer definitions without writing files
#   --uninstall               Stop, disable, and remove the 5 user services & timers
#   --help                    Show usage information
# =============================================================================

set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
if [[ -x "${REPO_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${REPO_DIR}/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
DRY_RUN=0
UNINSTALL=0

usage() {
  cat <<EOF
Usage: bash scripts/setup_autonomous_timers.sh [--dry-run | --print-units | --uninstall]

Options:
  --dry-run, --print-units  Render all .service and .timer units to stdout without modifying systemd
  --uninstall               Disable and remove the Personal OS user services and timers
  --help                    Display this help message
EOF
}

for arg in "$@"; do
  case "$arg" in
    --dry-run|--print-units)
      DRY_RUN=1
      ;;
    --uninstall)
      UNINSTALL=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf "Unknown option: %s\n" "$arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

log_info() {
  printf "[POS-Auto-Timers] %s\n" "$1"
}

UNIT_NAMES=(
  "pos-auto-s4"
  "pos-auto-scouts"
  "pos-auto-radar"
  "pos-auto-draft-pr"
  "pos-auto-digest"
)

get_unit_spec() {
  local name="$1"
  case "$name" in
    pos-auto-s4)
      printf '%s\n' \
        "Personal OS Nightly Repo Self-Health & AST Drift Sentinel" \
        "*-*-* 04:00:00" \
        "${PYTHON_BIN} -m src.autonomous.cli --job s4 --notify"
      ;;
    pos-auto-scouts)
      printf '%s\n' \
        "Personal OS GitHub Trending & Tech Discovery Scouts" \
        "Mon,Thu *-*-* 06:00:00" \
        "${PYTHON_BIN} -m src.autonomous.cli --job scouts"
      ;;
    pos-auto-radar)
      printf '%s\n' \
        "Personal OS Daily Multi-Perspective Macro & Geopolitical Radar" \
        "*-*-* 07:45:00" \
        "${PYTHON_BIN} -m src.intel_radar --briefing"
      ;;
    pos-auto-draft-pr)
      printf '%s\n' \
        "Personal OS Weekly Isolated Worktree Draft PR Factory" \
        "Sat *-*-* 07:30:00" \
        "${PYTHON_BIN} -m src.autonomous.cli --job draft-pr-factory"
      ;;
    pos-auto-digest)
      printf '%s\n' \
        "Personal OS Tactical & Deep R&D Digest Synthesis" \
        "Wed,Sat *-*-* 09:00:00" \
        "${PYTHON_BIN} -m src.autonomous.cli --job sat-digest --with-agy --notify"
      ;;
  esac
}

render_service_unit() {
  local desc="$1"
  local exec_cmd="$2"
  cat <<EOF
[Unit]
Description=${desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${REPO_DIR}
Environment="PATH=${HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=-${REPO_DIR}/.env
ExecStart=${exec_cmd}
EOF
}

render_timer_unit() {
  local name="$1"
  local desc="$2"
  local on_cal="$3"
  cat <<EOF
[Unit]
Description=Timer for ${desc}

[Timer]
OnCalendar=${on_cal}
Persistent=true
RandomizedDelaySec=60
Unit=${name}.service

[Install]
WantedBy=timers.target
EOF
}

if [[ "${UNINSTALL}" -eq 1 ]]; then
  for name in "${UNIT_NAMES[@]}"; do
    service_file="${SYSTEMD_USER_DIR}/${name}.service"
    timer_file="${SYSTEMD_USER_DIR}/${name}.timer"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      log_info "[DRY-RUN] Would disable/stop ${name}.timer and remove ${service_file} + ${timer_file}"
    else
      if command -v systemctl >/dev/null 2>&1; then
        systemctl --user disable --now "${name}.timer" 2>/dev/null || true
      fi
      rm -f "${service_file}" "${timer_file}"
      log_info "Removed ${name}.service and ${name}.timer"
    fi
  done
  if [[ "${DRY_RUN}" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload 2>/dev/null || true
  fi
  log_info "Autonomous timers uninstall completed."
  exit 0
fi

if [[ "${DRY_RUN}" -eq 0 ]]; then
  mkdir -p "${SYSTEMD_USER_DIR}"
fi

for name in "${UNIT_NAMES[@]}"; do
  mapfile -t spec < <(get_unit_spec "${name}")
  desc="${spec[0]}"
  on_cal="${spec[1]}"
  exec_cmd="${spec[2]}"

  service_content="$(render_service_unit "${desc}" "${exec_cmd}")"
  timer_content="$(render_timer_unit "${name}" "${desc}" "${on_cal}")"

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf "=== %s/%s.service ===\n%s\n\n" "${SYSTEMD_USER_DIR}" "${name}" "${service_content}"
    printf "=== %s/%s.timer ===\n%s\n\n" "${SYSTEMD_USER_DIR}" "${name}" "${timer_content}"
  else
    printf "%s\n" "${service_content}" > "${SYSTEMD_USER_DIR}/${name}.service"
    printf "%s\n" "${timer_content}" > "${SYSTEMD_USER_DIR}/${name}.timer"
    log_info "Wrote ${name}.service and ${name}.timer (${on_cal})"
  fi
done

if [[ "${DRY_RUN}" -eq 0 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload 2>/dev/null || true
    for name in "${UNIT_NAMES[@]}"; do
      systemctl --user enable --now "${name}.timer" 2>/dev/null || true
    done
    log_info "Reloaded systemd user daemon and enabled all ${#UNIT_NAMES[@]} autonomous timers."
  else
    log_info "systemctl not found; generated unit files only."
  fi
else
  log_info "[DRY-RUN] Printed all ${#UNIT_NAMES[@]} autonomous service/timer pairs without modifying system."
fi
