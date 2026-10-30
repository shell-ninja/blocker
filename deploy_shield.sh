#!/usr/bin/env bash
# deploy_shield.sh - Deploy the tamper-proof shield extension
# Run as: sudo bash deploy_shield.sh
set -euo pipefail

RED='\033[38;5;203m'; GREEN='\033[38;5;48m'; CYAN='\033[38;5;51m'
YELLOW='\033[38;5;221m'; MUTED='\033[38;5;244m'; BOLD='\033[1m'; RST='\033[0m'

ok()   { printf " ${GREEN}✔${RST}  %s\n" "$*"; }
warn() { printf " ${YELLOW}▲${RST}  ${YELLOW}%s${RST}\n" "$*"; }
info() { printf " ${CYAN}ℹ${RST}  ${MUTED}%s${RST}\n" "$*"; }
die()  { printf "\n${RED}✖ error:${RST} %s\n\n" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Must run as root: sudo bash $0"

# Get the real (non-root) user who invoked sudo
ACTUAL_USER="${SUDO_USER:-$(logname 2>/dev/null || id -un)}"
BLOCKER_SRC="/main/Code/shell-ninja/blocker"
SHIELD_KEY="/usr/share/blocker/shield.pem"

echo ""
printf "${CYAN}${BOLD}  Blocker Shield Deployment${RST}\n"
echo "  Running as root, packing as user: $ACTUAL_USER"
echo ""

# ---- 1. Copy shield source files ----
info "Copying shield source files..."
for dir in shield ig-shield; do
  chattr -i /usr/share/blocker/$dir/* 2>/dev/null || true
  mkdir -p /usr/share/blocker/$dir
  cp -f "$BLOCKER_SRC/assets/shield/manifest.json" /usr/share/blocker/$dir/manifest.json
  cp -f "$BLOCKER_SRC/assets/shield/content.js"    /usr/share/blocker/$dir/content.js
  chmod 755 /usr/share/blocker/$dir
  chmod 644 /usr/share/blocker/$dir/*
done
ok "Shield source files copied"

# ---- 2. RSA key ----
if [ ! -f "$SHIELD_KEY" ]; then
  info "Generating RSA key (one-time)..."
  openssl genrsa -out "$SHIELD_KEY" 2048 2>/dev/null
  chmod 600 "$SHIELD_KEY"
  ok "RSA key generated"
else
  ok "RSA key exists: $SHIELD_KEY"
fi

# ---- 3. Pack CRX ----
BRAVE_BIN=""
for b in /opt/brave-origin-bin/brave /opt/brave-bin/brave /usr/bin/brave-browser /usr/bin/brave; do
  [ -x "$b" ] && BRAVE_BIN="$b" && break
done
[ -n "$BRAVE_BIN" ] || die "No Brave binary found"

info "Packing shield.crx (running Brave as $ACTUAL_USER)..."
chattr -i /usr/share/blocker/shield/* 2>/dev/null || true

TMP_PACK=$(mktemp -d)
# Copy files to temp and make them readable by the actual user
cp -r /usr/share/blocker/shield "$TMP_PACK/shield"
chmod -R a+rX "$TMP_PACK/shield"
# Copy pem with user-readable perms (only exists in temp, gets deleted)
cp "$SHIELD_KEY" "$TMP_PACK/shield.pem"
chmod 644 "$TMP_PACK/shield.pem"
chown -R "$ACTUAL_USER" "$TMP_PACK"

# Run Brave as the actual user (Brave refuses to pack as root)
sudo -u "$ACTUAL_USER" "$BRAVE_BIN" --headless=new --no-sandbox --disable-gpu \
  --pack-extension="$TMP_PACK/shield" \
  --pack-extension-key="$TMP_PACK/shield.pem" \
  2>/dev/null || true

if [ -f "$TMP_PACK/shield.crx" ]; then
  cp -f "$TMP_PACK/shield.crx" /usr/share/blocker/shield.crx
  chmod 644 /usr/share/blocker/shield.crx
  ok "shield.crx packed: $(ls -lh /usr/share/blocker/shield.crx | awk '{print $5}')"
else
  rm -rf "$TMP_PACK"
  die "CRX pack failed. Check: sudo -u $ACTUAL_USER $BRAVE_BIN --version"
fi
rm -rf "$TMP_PACK"

# Re-lock shield source files
chattr +i /usr/share/blocker/shield/* 2>/dev/null || true

# ---- 4. Compute extension ID ----
info "Computing extension ID..."
SHIELD_EXT_ID=$(openssl rsa -in "$SHIELD_KEY" -pubout -outform DER 2>/dev/null \
  | sha256sum \
  | awk '{print substr($1,1,32)}' \
  | python3 -c "
import sys
h = sys.stdin.read().strip()
print(''.join(chr(ord('a') + int(c, 16)) for c in h))
" 2>/dev/null || true)

[ ${#SHIELD_EXT_ID} -eq 32 ] || die "Extension ID computation failed (got: '$SHIELD_EXT_ID')"

echo "$SHIELD_EXT_ID" > /usr/share/blocker/shield_ext_id
chmod 644 /usr/share/blocker/shield_ext_id
ok "Extension ID: $SHIELD_EXT_ID"

# ---- 5. Write update.xml ----
cat > /usr/share/blocker/shield_update.xml << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="${SHIELD_EXT_ID}">
    <updatecheck codebase="http://127.0.0.1:19288/shield.crx" version="1.0" />
  </app>
</gupdate>
XMLEOF
chmod 644 /usr/share/blocker/shield_update.xml
ok "shield_update.xml written"

# ---- 6. Install and start CRX HTTP server ----
info "Installing blocker-crxserve.service..."
cat > /etc/systemd/system/blocker-crxserve.service << 'SVCEOF'
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
systemctl daemon-reload
systemctl enable blocker-crxserve.service 2>/dev/null || true
systemctl restart blocker-crxserve.service 2>/dev/null || systemctl start blocker-crxserve.service
sleep 1
if systemctl is-active --quiet blocker-crxserve.service; then
  ok "blocker-crxserve.service running on port 19288"
else
  warn "Service not active - check: journalctl -u blocker-crxserve -n 20"
fi

if curl -fs http://127.0.0.1:19288/shield_update.xml -o /dev/null 2>/dev/null; then
  ok "CRX HTTP server responding correctly"
else
  warn "HTTP server not responding yet on port 19288"
fi

# ---- 7. Inject ExtensionInstallForcelist into browser policy JSON ----
info "Updating browser policy..."
for POLICY_DIR in \
    /etc/brave/policies/managed \
    /etc/brave-browser/policies/managed \
    /etc/brave-origin/policies/managed \
    /etc/chromium/policies/managed \
    /etc/opt/chrome/policies/managed; do
  POLICY_FILE="$POLICY_DIR/blocker.json"
  [ -f "$POLICY_FILE" ] || continue
  # Make writable
  chattr -i "$POLICY_FILE" 2>/dev/null || true
  python3 - "$POLICY_FILE" "$SHIELD_EXT_ID" << 'PYEOF'
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
print(f"  Updated: {path}")
PYEOF
  # Re-lock
  chattr +i "$POLICY_FILE" 2>/dev/null || true
done
ok "Browser policy updated with ExtensionInstallForcelist"

# ---- 8. Remove --load-extension from flag files ----
info "Removing --load-extension from browser flag files..."
for user_home in /home/* /root; do
  [ -d "$user_home" ] || continue
  u_cfg="$user_home/.config"
  [ -d "$u_cfg" ] || continue
  for flag_file in brave-flags.conf brave-origin-flags.conf chromium-flags.conf chrome-flags.conf vivaldi-flags.conf; do
    tgt="$u_cfg/$flag_file"
    [ -f "$tgt" ] || continue
    chattr -i "$tgt" 2>/dev/null || true
    sed -i '/--load-extension=.*blocker/d' "$tgt" 2>/dev/null || true
    chattr +i "$tgt" 2>/dev/null || true
    echo "    Cleaned: $tgt"
  done
done
ok "--load-extension removed from all flag files"

# ---- 9. Install updated blocker binary ----
if [ -f "$BLOCKER_SRC/build/blocker" ]; then
  info "Installing updated blocker binary..."
  chattr -i /usr/local/sbin/blocker 2>/dev/null || true
  cp -f "$BLOCKER_SRC/build/blocker" /usr/local/sbin/blocker
  chmod 700 /usr/local/sbin/blocker
  chown root:root /usr/local/sbin/blocker
  ok "blocker binary updated"
fi

# ---- 10. Restart blocker daemon to pick up new policy ----
info "Restarting blocker daemon..."
systemctl restart blocker.service 2>/dev/null || true
sleep 2
if systemctl is-active --quiet blocker.service; then
  ok "blocker.service restarted"
else
  warn "blocker.service not active - check: journalctl -u blocker -n 30"
fi

# ---- Done ----
printf "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RST}\n"
printf "${GREEN}${BOLD}║  Shield Deployment Complete                          ║${RST}\n"
printf "${GREEN}${BOLD}╠══════════════════════════════════════════════════════╣${RST}\n"
printf "${GREEN}${BOLD}║${RST}  Extension ID : ${CYAN}%-38s${RST}${GREEN}${BOLD}║${RST}\n" "$SHIELD_EXT_ID"
printf "${GREEN}${BOLD}║${RST}  CRX server   : ${CYAN}http://127.0.0.1:19288${RST}               ${GREEN}${BOLD}║${RST}\n"
printf "${GREEN}${BOLD}║${RST}  Policy type  : ${CYAN}ExtensionInstallForcelist${RST}            ${GREEN}${BOLD}║${RST}\n"
printf "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RST}\n\n"
printf "${YELLOW}${BOLD}▲  ACTION REQUIRED:${RST} Fully close and reopen Brave browser.\n"
printf "   Then go to ${CYAN}brave://extensions${RST}\n"
printf "   'Blocker Web Shield' should show:\n"
printf "   ${MUTED}\"Installed by your administrator\"  (no Remove button)${RST}\n\n"
