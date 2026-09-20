#!/usr/bin/env bash
# ── generate-batch.sh — issue + bind a batch of short-format licenses ──────
# Usage: generate-batch.sh <COUNT> <ORG> <OUT_TSV> [TIER] [SEATS] [EXPIRES]
# Emits TSV: license_id TAB short_key TAB tier TAB org TAB expires
# Every key is bound on the production server (admin/bind) right after
# issue — customers can activate immediately.
set -euo pipefail

COUNT="${1:?usage: generate-batch.sh <COUNT> <ORG> <OUT_TSV> [TIER] [SEATS] [EXPIRES]}"
ORG="${2:?missing org}"
OUT="${3:?missing output tsv}"
TIER="${4:-enterprise}"
SEATS="${5:-1}"
EXPIRES="${6:-}"

KEYGEN="${TALUS_KEYGEN_BIN:-license-keygen/target/release/talus-keygen}"
KEYS_DIR="${TALUS_KEYGEN_DIR:-$HOME/.secrets/talus/license-keys}"
SERVER="${TALUS_LICENSE_SERVER:-https://talus-license-server.metaforicmail.workers.dev}"
TOKEN_FILE="${TALUS_ADMIN_TOKEN_FILE:-$HOME/.secrets/talus/admin_token}"

cd "$(dirname "$0")/.."
export TALUS_KEYGEN_DIR="$KEYS_DIR"

ADMIN_TOKEN=""
if [[ -n "${TALUS_ADMIN_TOKEN:-}" ]]; then
  ADMIN_TOKEN="$TALUS_ADMIN_TOKEN"
elif [[ -s "$TOKEN_FILE" ]]; then
  ADMIN_TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
else
  echo "error: no admin token at $TOKEN_FILE" >&2
  exit 1
fi

: > "$OUT"
OK=0 FAIL=0

for ((i = 1; i <= COUNT; i++)); do
  ARGS=(issue --tier "$TIER" --organization "$ORG" --seats "$SEATS" --format short --json)
  [[ -n "$EXPIRES" ]] && ARGS+=(--expires "$EXPIRES")

  if ! JSON="$("$KEYGEN" "${ARGS[@]}" 2>/dev/null)"; then
    echo "✗ [$i/$COUNT] keygen failed" >&2
    FAIL=$((FAIL + 1))
    continue
  fi

  read -r LID LKEY LCANON < <(python3 -c "
import json, sys
d = json.loads(sys.argv[1])
print(d['license_id'], d['license_key'], d['license_key_canonical'])
" "$JSON")

  HTTP="$(curl -sS -o /tmp/talus-batch-bind.json -w '%{http_code}' --max-time 20 \
    -X POST "$SERVER/api/v1/admin/bind" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d "{\"short_key\":\"$LKEY\",\"license_key\":\"$LCANON\",\"license_id\":\"$LID\"}" || echo 000)"

  # Pre-register so the license shows in the panel before first activation.
  REG="$(python3 -c "
import json, sys
d = json.loads(sys.argv[1])
print(json.dumps({
    'license_id': d['license_id'],
    'tier': d['tier'],
    'org': d['organization'],
    'features': d.get('features'),
    'max_nodes': d.get('max_nodes', 0),
    'max_seats': d.get('seats', 1),
    'expires_at': d.get('expires_at'),
}))
" "$JSON")"
  RHTTP="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
    -X POST "$SERVER/api/v1/admin/register" \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d "$REG" || echo 000)"

  if [[ "$HTTP" == "200" && "$RHTTP" == "200" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$LID" "$LKEY" "$TIER" "$ORG" "${EXPIRES:-perpetual}" >> "$OUT"
    OK=$((OK + 1))
    echo "✓ [$i/$COUNT] $LID $LKEY"
  else
    FAIL=$((FAIL + 1))
    echo "✗ [$i/$COUNT] $LID bind=$HTTP register=$RHTTP" >&2
  fi
done

echo
echo "Done: $OK ok, $FAIL failed → $OUT"
[[ "$FAIL" == 0 ]]
