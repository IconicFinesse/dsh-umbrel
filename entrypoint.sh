#!/bin/bash
# dsh-umbrel entrypoint (dsh role): keep the dsh program install in the data
# volume converged to the tracked version, then run dsh web under a light
# supervisor that captures the launch link for the gate and rolls back if a
# fresh update fails to come up.
#
# Update policy (Brauk's standing choice): ALWAYS LATEST. The pin file
# /data/dsh-version.txt holds a dist-tag (default "latest") or an exact
# version to freeze on. Every start resolves the tag and, if it moved,
# installs the new version BESIDE the old one, verifies the binary runs,
# then swaps atomically. The previous install is kept at /data/app.old as a
# one-generation rollback. User data (~/.dsh) is never in the swap path, so
# updates cannot delete it — proven in the 2026-11-08 spike both directions
# (good bump 0.2.1-rc.5 -> 0.2.2-rc.1, and a bogus pin that was rejected
# with the old version kept serving).
set -u

DATA=/data
export HOME="$DATA/home"
export DSH_HOME="$HOME/.dsh"
export npm_config_cache="$DATA/.npm-cache"
APP_DIR="$DATA/app"
NEW_DIR="$DATA/app.new"
OLD_DIR="$DATA/app.old"
PIN_FILE="$DATA/dsh-version.txt"
WEB_LOG="$HOME/dsh-web.log"
LINK_FILE="$HOME/dsh-link.txt"
PKG="@deepseek-ai/dsh"

mkdir -p "$HOME" "$DSH_HOME" "$npm_config_cache"

# ---------- resolve target version ----------
if [ ! -f "$PIN_FILE" ]; then
  echo "latest" > "$PIN_FILE"
  echo "[entrypoint] created version pin: latest (tracks npm dist-tag)"
fi
PIN="$(tr -d '[:space:]' < "$PIN_FILE")"
INSTALLED=""
[ -f "$APP_DIR/.dsh-version" ] && INSTALLED="$(cat "$APP_DIR/.dsh-version")"

if [[ "$PIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  TARGET="$PIN"
else
  TARGET="$(npm view "$PKG" "dist-tags.$PIN" 2>/dev/null || true)"
  if [ -z "$TARGET" ]; then
    echo "[entrypoint] WARNING: could not resolve dist-tag '$PIN' (offline?) — keeping ${INSTALLED:-nothing}"
    TARGET="$INSTALLED"
  fi
fi

# ---------- converge the install ----------
SWAPPED=0
if [ -n "$TARGET" ] && [ "$TARGET" != "$INSTALLED" ]; then
  echo "[entrypoint] installing dsh@$TARGET (current: ${INSTALLED:-none})"
  rm -rf "$NEW_DIR"
  if npm install -g --prefix "$NEW_DIR" "$PKG@$TARGET" \
     && "$NEW_DIR/bin/dsh" --version >/dev/null 2>&1; then
    echo "$TARGET" > "$NEW_DIR/.dsh-version"
    rm -rf "$OLD_DIR"
    [ -d "$APP_DIR" ] && mv "$APP_DIR" "$OLD_DIR"
    mv "$NEW_DIR" "$APP_DIR"
    SWAPPED=1
    echo "[entrypoint] dsh@$TARGET installed and verified — swapped in (rollback kept at app.old)"
  else
    echo "[entrypoint] ERROR: dsh@$TARGET install/verify failed — keeping ${INSTALLED:-nothing}"
    rm -rf "$NEW_DIR"
    [ -z "$INSTALLED" ] && { echo "[entrypoint] no working dsh to run; exiting"; exit 1; }
  fi
elif [ -n "$TARGET" ]; then
  echo "[entrypoint] dsh@$INSTALLED is the tracked version ($PIN) — no update"
fi

export PATH="$APP_DIR/bin:$PATH"
cd "$HOME"

# dsh refuses wildcard binds (0.0.0.0) by design — it demands one concrete
# address so the web UI is never accidentally exposed as a network-wide RCE
# surface. In a container that address is the primary interface IPv4,
# assigned at start, so resolve it here (same pattern as the VM launcher).
HOST_IP="$(node -e 'const os=require("os");for(const l of Object.values(os.networkInterfaces()))for(const a of l||[])if(a.family==="IPv4"&&!a.internal){console.log(a.address);process.exit(0)}' 2>/dev/null)"
if [ -z "$HOST_IP" ]; then
  echo "[entrypoint] ERROR: could not resolve a concrete IPv4 to bind"; exit 1
fi

# ---------- supervised web start (link capture + update rollback) ----------
start_web() {
  : > "$WEB_LOG"
  "$APP_DIR/bin/dsh" web --no-open --host "$HOST_IP" --port 3080 \
    > >(tee -a "$WEB_LOG") 2>&1 &
  WEB_PID=$!
  # Capture the launch link for the gate as soon as dsh prints it.
  for _ in $(seq 1 60); do
    if grep -qE 'https?://[^ ]*/?\?token=' "$WEB_LOG" 2>/dev/null; then
      grep -oE 'https?://[^ ]*/?\?token=[^ ]+' "$WEB_LOG" | head -1 > "$LINK_FILE"
      chmod 600 "$LINK_FILE" 2>/dev/null || true
      return 0
    fi
    kill -0 "$WEB_PID" 2>/dev/null || return 1
    sleep 1
  done
  return 1
}

echo "[entrypoint] starting dsh web on $HOST_IP:3080 (HOME=$HOME)"
if ! start_web; then
  if [ "$SWAPPED" = "1" ] && [ -d "$OLD_DIR" ]; then
    ROLLBACK_VERSION="$(cat "$OLD_DIR/.dsh-version" 2>/dev/null || echo unknown)"
    echo "[entrypoint] ERROR: dsh@$TARGET failed to come up — rolling back to $ROLLBACK_VERSION"
    kill "$WEB_PID" 2>/dev/null || true
    rm -rf "$APP_DIR"
    mv "$OLD_DIR" "$APP_DIR"
    if ! start_web; then
      echo "[entrypoint] ERROR: rollback also failed to start; exiting"
      exit 1
    fi
    echo "[entrypoint] rollback succeeded — running dsh@$ROLLBACK_VERSION"
  else
    echo "[entrypoint] ERROR: dsh web failed to start; exiting"
    exit 1
  fi
fi

trap 'kill -TERM "$WEB_PID" 2>/dev/null || true' TERM INT
wait "$WEB_PID"
