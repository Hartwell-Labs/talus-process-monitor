#!/usr/bin/env bash
# ── issue-license.sh — issue a signed Talus license ───────────────────────
# Usage:
#   scripts/issue-license.sh --org "Acme Corp" [--tier enterprise] \
#       [--expires 2027-12-31] [--seats 5] [--max-nodes 0] \
#       [--license-id TALUS-...] [    --features f1,f2] [--count N] [--offline] [--format short|raw] [--format pretty|raw]
#
# Signs the license locally with the owner's Ed25519 key, then automatically
# pre-registers it on the activation server (POST /api/v1/admin/register)
# so it shows up in the admin panel immediately — before the customer's
# first activation. The signing key never leaves this machine; only the
# already-public license payload travels to the server.
#
#   --count N   issue N keys for the same organization (each with its own
#               license_id); seats are per key
#   --offline   skip server registration (key registers on first activation)
#
# The ADMIN_TOKEN is read from ~/.secrets/talus/admin_token (or
# TALUS_ADMIN_TOKEN) and is never printed or committed.

set -euo pipefail

KEYGEN="${TALUS_KEYGEN_BIN:-license-keygen/target/release/talus-keygen}"
KEYS_DIR="${TALUS_KEYGEN_DIR:-$HOME/.secrets/talus/license-keys}"
SERVER="${TALUS_LICENSE_SERVER:-https://talus-license-server.metaforicmail.workers.dev}"
TOKEN_FILE="${TALUS_ADMIN_TOKEN_FILE:-$HOME/.secrets/talus/admin_token}"

cd "$(dirname "$0")/.." # repo root

if [[ ! -x "$KEYGEN" ]]; then
  echo "error: keygen binary not found at $KEYGEN" >&2
  echo "build it with: (cd license-keygen && cargo build --release)" >&2
  exit 1
fi
if [[ ! -f "$KEYS_DIR/signing_key.json" ]]; then
  echo "error: no signing key at $KEYS_DIR/signing_key.json" >&2
  echo "create one with: TALUS_KEYGEN_DIR=\"$KEYS_DIR\" $KEYGEN init" >&2
  exit 1
fi

# ── Parse arguments ───────────────────────────────────────────────────────
ORG="" TIER="enterprise" EXPIRES="" SEATS="1" MAX_NODES="" LICENSE_ID="" FEATURES="" FORMAT="short"
COUNT=1 OFFLINE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org) ORG="$2"; shift 2 ;;
    --tier) TIER="$2"; shift 2 ;;
    --expires) EXPIRES="$2"; shift 2 ;;
    --seats) SEATS="$2"; shift 2 ;;
    --max-nodes) MAX_NODES="$2"; shift 2 ;;
    --license-id) LICENSE_ID="$2"; shift 2 ;;
    --features) FEATURES="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    --format) FORMAT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ "$COUNT" =~ ^[1-9][0-9]*$ ]] || { echo "error: --count must be >= 1" >&2; exit 1; }
if [[ "$COUNT" -gt 1 && -n "$LICENSE_ID" ]]; then
  echo "error: --license-id cannot be combined with --count > 1" >&2
  exit 1
fi

export TALUS_KEYGEN_DIR="$KEYS_DIR"

# ── Admin token for server registration (never printed) ───────────────────
ADMIN_TOKEN=""
if [[ "$OFFLINE" == "0" ]]; then
  if [[ -n "${TALUS_ADMIN_TOKEN:-}" ]]; then
    ADMIN_TOKEN="$TALUS_ADMIN_TOKEN"
  elif [[ -s "$TOKEN_FILE" ]]; then
    ADMIN_TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  else
    echo "warning: no admin token at $TOKEN_FILE — issuing OFFLINE instead." >&2
    echo "         The key will register on the server at first activation." >&2
    OFFLINE=1
  fi
fi

# ── Issue + register ──────────────────────────────────────────────────────
declare -a SUMMARY_IDS=()

for ((i = 1; i <= COUNT; i++)); do
  # Explicit --license-id only makes sense for a single key.
  ID_ARGS=()
  [[ "$COUNT" == 1 && -n "$LICENSE_ID" ]] && ID_ARGS+=(--license-id "$LICENSE_ID")

  KEYGEN_JSON="$("$KEYGEN" issue \
    --tier "$TIER" \
    ${ORG:+--organization "$ORG"} \
    ${EXPIRES:+--expires "$EXPIRES"} \
    ${MAX_NODES:+--max-nodes "$MAX_NODES"} \
    ${FEATURES:+--features "$FEATURES"} \
    --seats "$SEATS" \
    --format "$FORMAT" \
    --json \
    "${ID_ARGS[@]}")"

  # Parse the keygen JSON (python3: no jq dependency).
  PARSED="$(python3 - "$ORG" <<PYEOF
import json, sys

d = json.loads('''$KEYGEN_JSON''')
org = sys.argv[1] if len(sys.argv) > 1 else None
out = {
    "license_id": d["license_id"],
    "license_key": d["license_key"],
    "tier": d["tier"],
    "max_nodes": d.get("max_nodes", 0),
    "seats": d.get("seats", 1),
    "expires_at": d.get("expires_at"),
    "features": d.get("features"),
    "org": org,
}
print(json.dumps(out))
PYEOF
)"

  LIC_ID="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['license_id'])" "$PARSED")"
  LIC_KEY="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['license_key'])" "$PARSED")"
  # ── Bind the short key to its JWT on the server (short format only) ─────
  # The customer-facing short key resolves to the JWT via this binding.
  # Without it a short key cannot activate. Raw-format keys skip this.
  if [[ "$FORMAT" == "short" && "$OFFLINE" == "0" ]]; then
    LIC_CANONICAL="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['license_key_canonical'])" "$PARSED")"
    HTTP="$(curl -sS -o /tmp/talus-bind-reply.json -w '%{http_code}' \
      -X POST "$SERVER/api/v1/admin/bind" \
      -H 'content-type: application/json' \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -d "{\"short_key\":\"$LIC_KEY\",\"license_key\":\"$LIC_CANONICAL\",\"license_id\":\"$LIC_ID\"}" || echo 000)"
    if [[ "$HTTP" == 200 ]]; then
      BIND_STATUS="short-key binding: OK"
    else
      REPLY="$(cat /tmp/talus-bind-reply.json 2>/dev/null || echo '')"
      echo "warning: short-key binding failed (HTTP $HTTP): $REPLY" >&2
      echo "         Customers CANNOT activate this key until binding succeeds." >&2
      BIND_STATUS="short-key binding: FAILED (HTTP $HTTP)"
    fi
    rm -f /tmp/talus-bind-reply.json
  else
    BIND_STATUS="short-key binding: SKIPPED"
  fi

  # ── Pre-register on the server (best-effort but loud on failure) ────────
  REGISTER_STATUS="server-registration: SKIPPED (--offline)"
  if [[ "$OFFLINE" == "0" ]]; then
    BODY="$(python3 - "$PARSED" <<PYEOF
import json, sys

d = json.loads(sys.argv[1])
print(json.dumps({
    "license_id": d["license_id"],
    "tier": d["tier"],
    "org": d["org"],
    "features": d["features"],
    "max_nodes": d["max_nodes"],
    "max_seats": d["seats"],
    "expires_at": d["expires_at"],
}))
PYEOF
)"
    HTTP="$(curl -sS -o /tmp/talus-register-reply.json -w '%{http_code}' \
      -X POST "$SERVER/api/v1/admin/register" \
      -H 'content-type: application/json' \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -d "$BODY" || echo 000)"
    if [[ "$HTTP" == 200 ]]; then
      REGISTER_STATUS="server-registration: OK"
    else
      REPLY="$(cat /tmp/talus-register-reply.json 2>/dev/null || echo '')"
      echo "warning: server registration failed (HTTP $HTTP): $REPLY" >&2
      echo "         The key is still valid — it self-registers on first activation." >&2
      REGISTER_STATUS="server-registration: FAILED (HTTP $HTTP) — key self-registers on first activation"
    fi
    rm -f /tmp/talus-register-reply.json
  fi

  SUMMARY_IDS+=("$LIC_ID")

  # ── Customer-facing output ──────────────────────────────────────────────
  echo
  echo "═══════════════════════════════════════════════════════════"
  if [[ "$COUNT" -gt 1 ]]; then
    echo "  LICENSE KEY GENERATED ($i / $COUNT)"
  else
    echo "  LICENSE KEY GENERATED"
  fi
  echo "═══════════════════════════════════════════════════════════"
  echo
  echo "  License ID:    $LIC_ID"
  echo "  Tier:          $TIER"
  [[ -n "$ORG" ]] && echo "  Organization:  $ORG"
  if [[ -n "$EXPIRES" ]]; then
    echo "  Expires:       $EXPIRES"
  else
    echo "  Expires:       never (perpetual)"
  fi
  echo "  Seats:         $SEATS"
  [[ -n "$MAX_NODES" && "$MAX_NODES" != "0" ]] && echo "  Max nodes:     $MAX_NODES"
  echo "  $BIND_STATUS"
  echo "  $REGISTER_STATUS"
  echo
  echo "  ┌─────────────────────────────────────────────────────┐"
  echo "  │  LICENSE KEY                                        │"
  echo "  ├─────────────────────────────────────────────────────┤"
  printf '  │  %-51s │\n' "$(python3 - "$LIC_KEY" <<'PYEOF'
import textwrap, sys
for line in textwrap.wrap(sys.argv[1], 51):
    print(line)
PYEOF
)"
  echo "  └─────────────────────────────────────────────────────┘"
  echo
  echo "  Activation command (send to the customer):"
  echo "    talus license activate <KEY>"
  echo "═══════════════════════════════════════════════════════════"
done

# ── Summary for multi-key runs ────────────────────────────────────────────
if [[ "$COUNT" -gt 1 ]]; then
  echo
  echo "Issued $COUNT licenses for \"${ORG:-<no org>}\": ${SUMMARY_IDS[*]}"
fi
