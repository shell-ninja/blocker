#!/usr/bin/env bash
# setup.sh - build, install and verify "blocker" in one go.
#
#   ./setup.sh                          interactive: asks for the unlock password
#   ./setup.sh --random-password        generate the password, show it once
#   ./setup.sh --yes --random-password --delay-hours 72
#   ./setup.sh --build-only             just build; touch nothing
#   ./setup.sh --dry-run                print what would happen
#   ./setup.sh --upgrade                replace an existing install immediately (preserves config & rules)
#
# Options handled here:   -y/--yes  --build-only  --install-deps  --upgrade  --dry-run  -h/--help
# Everything else is passed to `blocker install` (--mode, --delay-hours, --window-minutes,
# --curfew-time HH:MM, --curfew-start HH:MM, --curfew-end HH:MM, --curfew / --no-curfew,
# --reddit-block / --no-reddit-block, --ig-block / --no-ig-block,
# --unblock DOMAIN,
# --redirect-url URL, --no-redirect, --popup, --popup-message TEXT,
# --random-password, --password-stdin, --upstream, --no-firewall).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# ------------------------------------------------------------------ Visual Styling
if [ -t 1 ]; then
  C_RESET="\033[0m"
  C_BOLD="\033[1m"
  C_DIM="\033[2m"
  C_CYAN="\033[38;5;51m"
  C_BLUE="\033[38;5;39m"
  C_GREEN="\033[38;5;48m"
  C_YELLOW="\033[38;5;221m"
  C_RED="\033[38;5;203m"
  C_MAGENTA="\033[38;5;177m"
  C_MUTED="\033[38;5;244m"
  BG_CYAN="\033[48;5;31m"
  BG_DARK="\033[48;5;236m"
else
  C_RESET="" C_BOLD="" C_DIM="" C_CYAN="" C_BLUE="" C_GREEN=""
  C_YELLOW="" C_RED="" C_MAGENTA="" C_MUTED="" BG_CYAN="" BG_DARK=""
fi

banner() {
  printf "\n"
  printf "${C_CYAN}    ____  __           __            ${C_RESET}\n"
  printf "${C_CYAN}   / __ )/ /___  _____/ /_____  _____${C_RESET}\n"
  printf "${C_BLUE}  / __  / / __ \/ ___/ //_/ _ \/ ___/${C_RESET}\n"
  printf "${C_BLUE} / /_/ / / /_/ / /__/ ,< /  __/ /    ${C_RESET}\n"
  printf "${C_MAGENTA}/_____/_/\____/\___/_/|_|\___/_/     ${C_RESET}\n"
  printf "\n"
  printf "${C_DIM}╭──────────────────────────────────────────────────────────────────────────────╮${C_RESET}\n"
  printf "${C_DIM}│${C_RESET}   ${C_BOLD}${C_CYAN}blocker${C_RESET} ${C_MUTED}•${C_RESET} ${C_BOLD}High-Performance Adult-Content Filter & Tamper Protection${C_RESET}        ${C_DIM}│${C_RESET}\n"
  printf "${C_DIM}╰──────────────────────────────────────────────────────────────────────────────╯${C_RESET}\n"
}

step() {
  local num="$1" title="$2"
  printf "\n${C_CYAN}┌───${C_RESET} ${BG_CYAN}${C_BOLD} STEP %s ${C_RESET} ${C_BOLD}%s${C_RESET}\n" "$num" "$title"
}

status_ok()   { printf " ${C_CYAN}│${C_RESET}  ${C_GREEN}✔${C_RESET}  %s\n" "$*"; }
status_warn() { printf " ${C_CYAN}│${C_RESET}  ${C_YELLOW}▲${C_RESET}  ${C_YELLOW}%s${C_RESET}\n" "$*"; }
status_fail() { printf " ${C_CYAN}│${C_RESET}  ${C_RED}✖${C_RESET}  ${C_RED}%s${C_RESET}\n" "$*"; }
status_info() { printf " ${C_CYAN}│${C_RESET}  ${C_BLUE}ℹ${C_RESET}  ${C_MUTED}%s${C_RESET}\n" "$*"; }

spin() {
  local pid=$1 msg="$2"
  local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local delay=0.08
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do
      local temp=${spinstr#?}
      printf "\r ${C_CYAN}│${C_RESET}  ${C_CYAN}%c${C_RESET}  %s..." "$spinstr" "$msg"
      spinstr=$temp${spinstr%"$temp"}
      sleep $delay
    done
    printf "\r\033[K"
  else
    wait "$pid" 2>/dev/null || true
  fi
}

run_with_spinner() {
  local msg="$1"
  shift
  if [ "$DRY" = 1 ]; then
    printf " ${C_CYAN}│${C_RESET}  ${C_MUTED}+ %s${C_RESET}\n" "$*"
    return 0
  fi
  local logfile
  logfile=$(mktemp /tmp/blocker_setup_cmd.XXXXXX)
  "$@" > "$logfile" 2>&1 &
  local pid=$!
  spin "$pid" "$msg"
  if wait "$pid"; then
    status_ok "$msg"
    rm -f "$logfile"
  else
    status_fail "$msg (failed)"
    if [ -f "$logfile" ]; then
      printf "${C_RED}%s${C_RESET}\n" "$(cat "$logfile")" >&2
      rm -f "$logfile"
    fi
    die "command failed: $*"
  fi
}

say()  { printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}%s${C_RESET}\n" "$*"; }
warn() { printf " ${C_YELLOW}▲ warning:${C_RESET} %s\n" "$*" >&2; }
die()  { printf "\n${C_RED}✖ error:${C_RESET} %s\n\n" "$*" >&2; exit 1; }
fail() { if [ "$DRY" = 1 ]; then warn "$* (would abort)"; else die "$*"; fi; }
run()  { if [ "$DRY" = 1 ]; then echo "+ $*"; else "$@"; fi; }
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
# Run as the real (non-root) user - needed for Brave CRX packing
# (Brave refuses to run as root; drop back to the invoking user when called via sudo)
run_as_user() {
  local real_user="${SUDO_USER:-$(logname 2>/dev/null || id -un)}"
  if [ "$(id -u)" -eq 0 ] && [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
    sudo -u "$real_user" "$@"
  else
    "$@"
  fi
}
have() { command -v "$1" >/dev/null 2>&1; }

YES=0 BUILD_ONLY=0 DRY=0 DEPS=0 UPGRADE=0
INSTALL_ARGS=()

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)       YES=1 ;;
    --build-only)   BUILD_ONLY=1 ;;
    --install-deps) DEPS=1 ;;
    --upgrade)      UPGRADE=1 ;;
    --dry-run)      DRY=1 ;;
    -h|--help)      usage; exit 0 ;;
    --)             shift; INSTALL_ARGS+=("$@"); break ;;
    *)              INSTALL_ARGS+=("$1") ;;
  esac
  shift
done
has_arg() { local a; for a in ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}; do [ "$a" = "$1" ] && return 0; done; return 1; }

banner

# ------------------------------------------------------------------ 1. pre-flight
step "1/4" "System Pre-Flight Verification"

[ "$(uname -s)" = "Linux" ] && status_ok "Linux OS detected ($(uname -r))" || fail "blocker only runs on Linux"

if [ "$BUILD_ONLY" = 0 ]; then
  if [ -d /run/systemd/system ] && [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ]; then
    status_ok "systemd init system verified"
  else
    fail "systemd is not the init system here; blocker needs systemd (use --build-only to just compile)"
  fi
  if [ "$(id -u)" -ne 0 ]; then
    have sudo && status_ok "sudo privileges available" || fail "run as root or install sudo"
  else
    status_ok "running with root privileges"
  fi
fi

# build tools
missing=()
have g++ || have c++ || missing+=("a C++17 compiler")
have make            || missing+=("make")
if [ ${#missing[@]} -gt 0 ]; then
  if [ "$DEPS" = 1 ]; then
    say "Installing missing build tools: ${missing[*]}"
    if   have apt-get; then run as_root apt-get update && run as_root apt-get install -y g++ make nftables
    elif have dnf;     then run as_root dnf install -y gcc-c++ make nftables
    elif have pacman;  then run as_root pacman -S --needed --noconfirm gcc make nftables
    elif have zypper;  then run as_root zypper install -y gcc-c++ make nftables
    else fail "unknown package manager: please install ${missing[*]} yourself"; fi
  else
    fail "missing: ${missing[*]}. Re-run with --install-deps, or e.g. 'sudo apt install g++ make' (Debian/Ubuntu), 'sudo dnf install gcc-c++ make' (Fedora)"
  fi
else
  status_ok "C++17 compiler and make are present"
fi

if have nft; then
  status_ok "nftables firewall support present"
elif [ "$BUILD_ONLY" = 0 ]; then
  status_warn "nftables (nft) not found: the DNS-bypass firewall defense will be skipped"
fi

# The blocked-site popup helper
if [ "$BUILD_ONLY" = 0 ]; then
  if have zenity || have yad || have kdialog || have notify-send; then
    helper=$(command -v zenity 2>/dev/null || command -v yad 2>/dev/null || command -v kdialog 2>/dev/null || command -v notify-send 2>/dev/null)
    status_ok "desktop alert helper found: $(basename "$helper")"
  else
    if [ "$DEPS" = 1 ]; then
      say "Installing zenity for desktop alert notifications"
      if   have apt-get; then run as_root apt-get install -y zenity
      elif have dnf;     then run as_root dnf install -y zenity
      elif have pacman;  then run as_root pacman -S --needed --noconfirm zenity
      elif have zypper;  then run as_root zypper install -y zenity
      fi
    else
      status_warn "no popup helper (zenity/yad/kdialog/notify-send) found: alerts disabled (blocking still works)"
    fi
  fi
fi

# Existing install check
INSTALLED=0
if [ "$BUILD_ONLY" = 0 ]; then
  if [ -x /usr/local/sbin/blocker ] || { have systemctl && systemctl is-active --quiet blocker.service 2>/dev/null; }; then
    INSTALLED=1
  fi
fi

if [ "$INSTALLED" = 1 ] && [ "$UPGRADE" = 0 ]; then
  printf "\n${C_YELLOW}┌── Existing Installation Detected ────────────────────────────────────────────┐${C_RESET}\n"
  printf "${C_YELLOW}│${C_RESET} blocker is already installed on this machine and active on 127.0.0.1:53.     ${C_YELLOW}│${C_RESET}\n"
  printf "${C_YELLOW}│${C_RESET} To safely upgrade to this version without losing settings, run:              ${C_YELLOW}│${C_RESET}\n"
  printf "${C_YELLOW}│${C_RESET}   ${C_BOLD}./setup.sh --upgrade${C_RESET}                                                       ${C_YELLOW}│${C_RESET}\n"
  printf "${C_YELLOW}└──────────────────────────────────────────────────────────────────────────────┘${C_RESET}\n\n"
  fail "blocker is already installed (run with --upgrade)"
fi
if [ "$INSTALLED" = 0 ] && [ "$UPGRADE" = 1 ]; then
  status_warn "no existing installation found: switching to fresh install"
  UPGRADE=0
fi

# Port 53 check
if [ "$BUILD_ONLY" = 0 ] && [ "$INSTALLED" = 0 ] && have ss; then
  if ss -H -lun -ltn 2>/dev/null | awk '{print $5}' | grep -Eq '^(127\.0\.0\.1|0\.0\.0\.0|\*|\[::\]|::):53$'; then
    who=$(ss -H -lunpt 2>/dev/null | grep -E '(127\.0\.0\.1|0\.0\.0\.0|\*|\[::\]|::):53 ' | head -n1 || true)
    fail "port 53 is already in use by: ${who:-another resolver}. Stop that service before continuing."
  else
    status_ok "port 53 loopback interface is free and available"
  fi
fi

# ------------------------------------------------------------------ 2. build
step "2/4" "Compilation & Binary Assembly"
run_with_spinner "Compiling core engine with system hardening" make
[ "$DRY" = 1 ] || [ -x build/blocker ] || die "compilation failed: build/blocker not created"

if [ "$BUILD_ONLY" = 1 ]; then
  printf "\n${C_GREEN}╭──────────────────────────────────────────────────────────────────────────────╮${C_RESET}\n"
  printf "${C_GREEN}│${C_RESET}  ${C_BOLD}✔ Success:${C_RESET} Binary compiled at ${C_CYAN}build/blocker${C_RESET} (standalone build).             ${C_GREEN}│${C_RESET}\n"
  printf "${C_GREEN}╰──────────────────────────────────────────────────────────────────────────────╯${C_RESET}\n\n"
  exit 0
fi

# ------------------------------------------------------------------ 3. confirm
step "3/4" "Security Configuration & Confirmation"

if [ "$UPGRADE" = 0 ] && [ ! -t 0 ] && ! has_arg --random-password && ! has_arg --password-stdin && ! { has_arg --mode && has_arg delay; }; then
  fail "no interactive terminal: pass --random-password or --password-stdin to configure without prompts"
fi

active_wl=$(grep -Evc '^[[:space:]]*(#|$)' src/core/compat/tables/iana_punycode_tables.inc 2>/dev/null || true)
if [ "${active_wl:-0}" -gt 0 ]; then
  status_ok "pre-configured exceptions active (${active_wl} rule(s) loaded from baseline table)"
else
  status_info "baseline exception table has no active entries (all suggestions commented out)"
fi

if [ "$UPGRADE" = 1 ]; then
  printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}Action:${C_RESET} Upgrade existing installation to blocker 1.0.0\n"
  printf " ${C_CYAN}│${C_RESET}  ${C_MUTED}• Preserves existing password, custom rules, and whitelist entries${C_RESET}\n"
  printf " ${C_CYAN}│${C_RESET}  ${C_MUTED}• Re-arms systemd service units and kernel-level immutable locks${C_RESET}\n"
else
  printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}Install Target:${C_RESET} /usr/local/sbin/blocker (systemd service)\n"
  printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}DNS Hijack Protection:${C_RESET} /etc/resolv.conf pinned & immutable (chattr +i)\n"
  printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}Adult Content Defenses:${C_RESET} Enforced browser policies for Reddit NSFW & Instagram explore\n"
  printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}Anti-Tamper Ratchet:${C_RESET} Loosening gated by delayed unlock countdown & password\n"
fi

if [ "$YES" = 0 ] && [ "$DRY" = 0 ]; then
  [ -t 0 ] || die "non-interactive session detected: pass --yes to confirm installation"
  if [ "$UPGRADE" = 0 ] && ! has_arg --curfew && ! has_arg --no-curfew && ! has_arg --curfew-time && ! has_arg --curfew-start; then
    printf "\n"
    printf " ${C_CYAN}│${C_RESET}  ${C_BOLD}Night Curfew & Auto-Shutdown Configuration:${C_RESET}\n"
    printf " ${C_CYAN}│${C_RESET}  ${C_MUTED}Automatically powers off PC to enforce sleep, sending warning notifications 30m before.${C_RESET}\n"
    read -r -p "  Enable Night Curfew auto-shutdown? [Y/n] " ans_curfew
    case "$ans_curfew" in
      n|N|no|NO)
        INSTALL_ARGS+=(--no-curfew)
        ;;
      *)
        read -r -p "  Auto-shutdown time (HH:MM in 24h format, e.g. 23:00, 00:00) [00:00]: " ans_time
        ans_time=${ans_time:-00:00}
        read -r -p "  Curfew wake / end time (HH:MM in 24h format, e.g. 03:00, 06:00) [03:00]: " ans_end
        ans_end=${ans_end:-03:00}
        INSTALL_ARGS+=(--curfew-start "$ans_time" --curfew-end "$ans_end")
        ;;
    esac
  fi
  printf "\n"
  read -r -p "  Proceed with installation? [y/N] " ans
  case "$ans" in
    y|Y|yes|YES) ;;
    *) printf "\n${C_MUTED}Installation cancelled by user.${C_RESET}\n\n"; exit 1 ;;
  esac
fi

# ------------------------------------------------------------------ 4. install
step "4/4" "Installation & System Integration"

if [ "$UPGRADE" = 1 ]; then
  say "Stopping currently running blocker for immediate upgrade..."
  stopped=0
  if [ -x /usr/local/sbin/blocker ]; then
    if run as_root /usr/local/sbin/blocker stop --upgrade >/dev/null 2>&1 || \
       run as_root /usr/local/sbin/blocker upgrade >/dev/null 2>&1; then
      stopped=1
    fi
  fi
  if [ "$stopped" = 0 ]; then
    if [ "$DRY" = 0 ]; then
      as_root systemctl stop blocker-guard.timer 2>/dev/null || true
      as_root mkdir -p /var/lib/blocker
      echo "paused" | as_root tee /var/lib/blocker/disabled >/dev/null

      b_pid=$(systemctl show -p MainPID --value blocker.service 2>/dev/null || true)
      if [ -n "$b_pid" ] && [ "$b_pid" -gt 0 ] && kill -0 "$b_pid" 2>/dev/null; then
        as_root kill -STOP "$b_pid" 2>/dev/null || true
      fi

      as_root chattr -i /etc/systemd/system/blocker.service 2>/dev/null || true
      as_root sed -i '/RefuseManualStop/d' /etc/systemd/system/blocker.service 2>/dev/null || true
      as_root systemctl daemon-reload 2>/dev/null || true
      as_root systemctl stop blocker.service 2>/dev/null || true

      if [ -n "$b_pid" ] && [ "$b_pid" -gt 0 ] && kill -0 "$b_pid" 2>/dev/null; then
        as_root kill -KILL "$b_pid" 2>/dev/null || true
      fi

      as_root chattr -i /usr/local/sbin/blocker 2>/dev/null || true
      as_root chattr -i /etc/blocker/blocker.conf 2>/dev/null || true
      as_root chattr -i /etc/systemd/system/blocker* 2>/dev/null || true
      as_root chattr -i /etc/systemd/system/blocker*.d 2>/dev/null || true
    fi
  fi
  if [ "$DRY" = 0 ]; then
    for _ in $(seq 1 20); do systemctl is-active --quiet blocker.service 2>/dev/null || break; sleep 1; done
  fi
  run_with_spinner "Installing updated binaries and systemd units" run as_root ./build/blocker install --upgrade ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
  if [ "$DRY" = 0 ]; then
    for _ in $(seq 1 20); do as_root /usr/local/sbin/blocker status >/dev/null 2>&1 && break; sleep 1; done
  fi
  run_with_spinner "Merging updated base block rules" run as_root /usr/local/sbin/blocker add --defaults
else
  say "Deploying blocker service, systemd watchers and network defenses..."
  run as_root ./build/blocker install ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
fi

# Deploy Blocker Web Shield as a tamper-proof administrator extension
# Uses ExtensionInstallForcelist: shows "Installed by your administrator" in
# brave://extensions with no Remove button. User CANNOT remove it.
if [ "$DRY" = 0 ]; then
  # ---- 1. Copy shield source files ----
  for dir in shield ig-shield; do
    as_root chattr -i /usr/share/blocker/$dir/* 2>/dev/null || true
    as_root mkdir -p /usr/share/blocker/$dir
    as_root cp -f assets/shield/manifest.json /usr/share/blocker/$dir/manifest.json
    as_root cp -f assets/shield/content.js /usr/share/blocker/$dir/content.js
    as_root chmod 755 /usr/share/blocker/$dir
    as_root chmod 644 /usr/share/blocker/$dir/*
    as_root chattr +i /usr/share/blocker/$dir/* 2>/dev/null || true
  done

  # ---- 2. Generate persistent RSA key (keeps ext ID stable across upgrades) ----
  SHIELD_KEY="/usr/share/blocker/shield.pem"
  if [ ! -f "$SHIELD_KEY" ]; then
    status_info "Generating RSA key for shield CRX (one-time)..."
    as_root openssl genrsa -out "$SHIELD_KEY" 2048 2>/dev/null
    as_root chmod 600 "$SHIELD_KEY"
  fi

  # ---- 3. Pack the CRX using Brave ----
  BRAVE_BIN=""
  for b in /opt/brave-origin-bin/brave /opt/brave-bin/brave /usr/bin/brave-browser /usr/bin/brave; do
    [ -x "$b" ] && BRAVE_BIN="$b" && break
  done

  if [ -n "$BRAVE_BIN" ]; then
    status_info "Packing shield.crx..."
    as_root chattr -i /usr/share/blocker/shield/* 2>/dev/null || true
    TMP_PACK=$(mktemp -d)
    as_root chmod 755 "$TMP_PACK"
    as_root cp -r /usr/share/blocker/shield "$TMP_PACK/shield"
    as_root chmod -R a+rX "$TMP_PACK/shield"
    as_root chmod 644 "$SHIELD_KEY"
    as_root cp "$SHIELD_KEY" "$TMP_PACK/shield.pem"
    as_root chmod 600 "$SHIELD_KEY"
    as_root chmod 644 "$TMP_PACK/shield.pem"
    real_user="${SUDO_USER:-$(logname 2>/dev/null || id -un)}"
    if [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
      as_root chown -R "$real_user" "$TMP_PACK"
    fi
    run_as_user "$BRAVE_BIN" --headless=new --no-sandbox --disable-gpu \
      --pack-extension="$TMP_PACK/shield" \
      --pack-extension-key="$TMP_PACK/shield.pem" \
      2>/dev/null || true
    if [ -f "$TMP_PACK/shield.crx" ]; then
      as_root cp -f "$TMP_PACK/shield.crx" /usr/share/blocker/shield.crx
      as_root chmod 644 /usr/share/blocker/shield.crx
      status_ok "shield.crx packed"
    else
      status_warn "Brave CRX pack failed - trying chromium fallback..."
      for b2 in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
        if [ -x "$b2" ]; then
          run_as_user "$b2" --headless=new --no-sandbox --disable-gpu \
            --pack-extension="$TMP_PACK/shield" \
            --pack-extension-key="$TMP_PACK/shield.pem" \
            2>/dev/null || true
          [ -f "$TMP_PACK/shield.crx" ] && break
        fi
      done
      if [ -f "$TMP_PACK/shield.crx" ]; then
        as_root cp -f "$TMP_PACK/shield.crx" /usr/share/blocker/shield.crx
        as_root chmod 644 /usr/share/blocker/shield.crx
        status_ok "shield.crx packed (chromium fallback)"
      else
        status_warn "CRX pack failed - will fall back to --load-extension"
      fi
    fi
    rm -rf "$TMP_PACK"
    as_root chattr +i /usr/share/blocker/shield/* 2>/dev/null || true
  fi

  # ---- 4. Compute Extension ID and write update.xml ----
  SHIELD_EXT_ID=""
  if [ -f /usr/share/blocker/shield.crx ] && [ -f "$SHIELD_KEY" ]; then
    SHIELD_EXT_ID=$(as_root openssl rsa -in "$SHIELD_KEY" -pubout -outform DER 2>/dev/null \
      | sha256sum \
      | awk '{print substr($1,1,32)}' \
      | python3 -c "
import sys
h = sys.stdin.read().strip()
print(\'\'.join(chr(ord(\'a\') + int(c, 16)) for c in h))
" 2>/dev/null || true)
    if [ ${#SHIELD_EXT_ID} -eq 32 ]; then
      echo "$SHIELD_EXT_ID" | as_root tee /usr/share/blocker/shield_ext_id > /dev/null
      as_root chmod 644 /usr/share/blocker/shield_ext_id
      status_ok "Shield extension ID: $SHIELD_EXT_ID"
      as_root tee /usr/share/blocker/shield_update.xml > /dev/null << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="${SHIELD_EXT_ID}">
    <updatecheck codebase="http://127.0.0.1:19288/shield.crx" version="1.0" />
  </app>
</gupdate>
XMLEOF
      as_root chmod 644 /usr/share/blocker/shield_update.xml
    else
      status_warn "Could not compute extension ID"
      SHIELD_EXT_ID=""
    fi
  fi

  # ---- 5. Start CRX HTTP server ----
  as_root tee /etc/systemd/system/blocker-crxserve.service > /dev/null << 'SVCEOF'
[Unit]
Description=Blocker Shield CRX Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server 19288 --directory /usr/share/blocker
Restart=always
RestartSec=2
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
SVCEOF
  as_root systemctl daemon-reload 2>/dev/null || true
  as_root systemctl enable --now blocker-crxserve.service 2>/dev/null || true
  if as_root systemctl is-active --quiet blocker-crxserve.service 2>/dev/null; then
    status_ok "blocker-crxserve.service started on port 19288"
  else
    status_warn "blocker-crxserve not running - check: journalctl -u blocker-crxserve"
  fi

  # ---- 6. Inject ExtensionInstallForcelist into browser policies ----
  if [ -n "${SHIELD_EXT_ID:-}" ]; then
    for POLICY_DIR in \
        /etc/brave/policies/managed \
        /etc/brave-browser/policies/managed \
        /etc/brave-origin/policies/managed \
        /etc/chromium/policies/managed \
        /etc/opt/chrome/policies/managed; do
      POLICY_FILE="$POLICY_DIR/blocker.json"
      [ -f "$POLICY_FILE" ] || continue
      as_root chattr -i "$POLICY_FILE" 2>/dev/null || true
      python3 - "$POLICY_FILE" "$SHIELD_EXT_ID" << 'PYEOF2'
import json, sys
path = sys.argv[1]
ext_id = sys.argv[2]
with open(path) as f:
    data = json.load(f)
data['ExtensionInstallSources'] = ['http://127.0.0.1:19288/*']
data['ExtensionInstallForcelist'] = [
    f'{ext_id};http://127.0.0.1:19288/shield_update.xml'
]
with open(path, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
PYEOF2
      as_root chattr +i "$POLICY_FILE" 2>/dev/null || true
    done
    status_ok "Browser policy updated with ExtensionInstallForcelist"
  fi

  # ---- 7. Remove --load-extension if policy is active, else keep as fallback ----
  if [ -n "${SHIELD_EXT_ID:-}" ]; then
    for user_home in /home/* /root; do
      [ -d "$user_home" ] || continue
      u_cfg="$user_home/.config"
      [ -d "$u_cfg" ] || continue
      for flag_file in brave-flags.conf brave-origin-flags.conf chromium-flags.conf chrome-flags.conf vivaldi-flags.conf; do
        tgt="$u_cfg/$flag_file"
        [ -f "$tgt" ] || continue
        as_root chattr -i "$tgt" 2>/dev/null || true
        as_root sed -i '/--load-extension=.*blocker/d' "$tgt" 2>/dev/null || true
        as_root chattr +i "$tgt" 2>/dev/null || true
      done
    done
    status_ok "Removed --load-extension (replaced by administrator policy)"
  else
    for user_home in /home/* /root; do
      [ -d "$user_home" ] || continue
      u_cfg="$user_home/.config"
      [ -d "$u_cfg" ] || continue
      for flag_file in brave-flags.conf brave-origin-flags.conf chromium-flags.conf chrome-flags.conf vivaldi-flags.conf; do
        tgt="$u_cfg/$flag_file"
        as_root chattr -i "$tgt" 2>/dev/null || true
        if [ ! -f "$tgt" ]; then
          echo "--load-extension=/usr/share/blocker/shield" | as_root tee "$tgt" > /dev/null
          as_root chown "$(stat -c '%U:%G' "$user_home")" "$tgt" 2>/dev/null || true
        else
          as_root sed -i 's|/usr/share/blocker/ig-shield|/usr/share/blocker/shield|g' "$tgt" 2>/dev/null || true
          if ! grep -q -- "--load-extension=/usr/share/blocker/shield" "$tgt"; then
            echo "--load-extension=/usr/share/blocker/shield" | as_root tee -a "$tgt" > /dev/null
          fi
        fi
        as_root chattr +i "$tgt" 2>/dev/null || true
      done
    done
    status_warn "Using --load-extension fallback (CRX pack failed)"
  fi
fi

# ------------------------------------------------------------------ Verification
printf "\n${C_CYAN}┌───${C_RESET} ${BG_CYAN}${C_BOLD} VERIFY ${C_RESET} ${C_BOLD}Active Protection Health Check${C_RESET}\n"

if [ "$DRY" = 1 ]; then
  status_info "Dry-run mode: verification checks skipped"
else
  ok_block=0
  for _ in $(seq 1 10); do
    if getent hosts pornhub.com 2>/dev/null | grep -Eq '^(0\.0\.0\.0|127\.0\.0\.1|::1?)[[:space:]]'; then
      ok_block=1
      break
    fi
    sleep 1
  done

  if [ "$ok_block" = 1 ]; then
    status_ok "DNS filtering active: blocked sites sinkholed"
  else
    status_warn "Blocked site resolved to real address. Check: sudo blocker status"
  fi

  if have curl && getent hosts pornhub.com 2>/dev/null | grep -Eq '^(127\.0\.0\.1|::1)[[:space:]]'; then
    redir=$(curl -s -o /dev/null -m 5 -w '%{http_code} %{redirect_url}' http://pornhub.com/ 2>/dev/null || true)
    case "$redir" in
      302\ http*) status_ok "HTTP loopback redirect active (302 -> ${redir#302 })" ;;
      *) status_warn "HTTP landing page redirect not responding ($redir)" ;;
    esac
  fi

  if getent hosts example.com >/dev/null 2>&1; then
    status_ok "Legitimate internet traffic resolves cleanly"
  else
    status_warn "example.com resolution failed. Check: sudo journalctl -u blocker -n 50"
  fi

  if as_root /usr/local/sbin/blocker test-alert >/dev/null 2>&1; then
    status_ok "Desktop warning notifications verified active"
  else
    status_info "Desktop notification helper ready (run 'sudo blocker test-alert' to test)"
  fi
fi

sleep 1

# ------------------------------------------------------------------ Completion Card
printf "\n"
printf "${C_GREEN}╭──────────────────────────────────────────────────────────────────────────────╮${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  ${C_BOLD}${C_GREEN}✔  BLOCKER SUCCESSFULLY INSTALLED & ARMED${C_RESET}                                   ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}├──────────────────────────────────────────────────────────────────────────────┤${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  ${C_BOLD}Essential Commands (run with sudo):${C_RESET}                                         ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}    ${C_CYAN}blocker status${C_RESET}           Daemon, counters, lock and defense health        ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}    ${C_CYAN}blocker check <hostname>${C_RESET} Test if a host is blocked & see deciding rule    ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}    ${C_CYAN}blocker test-alert${C_RESET}       Verify desktop warning notifications in GUI      ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}    ${C_CYAN}blocker add <rule>...${C_RESET}    Add rules (never requires password or delay)     ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}    ${C_CYAN}blocker unlock-request${C_RESET}   Begin delayed unlock period to edit rules        ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}    ${C_CYAN}journalctl -u blocker -f${C_RESET} Live query and filter activity log               ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}├──────────────────────────────────────────────────────────────────────────────┤${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  ${C_MUTED}Default blocked sites and vault tables are securely locked.${C_RESET}                 ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}│${C_RESET}  ${C_MUTED}Full documentation & customization options available in USAGE.md${C_RESET}            ${C_GREEN}│${C_RESET}\n"
printf "${C_GREEN}╰──────────────────────────────────────────────────────────────────────────────╯${C_RESET}\n"
printf "\n"
printf "  ${C_BOLD}${C_CYAN}Happy browsing!${C_RESET} Protection is running in the background.\n\n"
 