#!/usr/bin/env bash
# ── r2-publish.sh — publish a Talus artifact to the free-tier R2 bucket ────
#
# Usage:
#   scripts/r2-publish.sh mit 0.8.4 ../target/release/talus-monitor
#   scripts/r2-publish.sh enterprise 0.8.4 ./talus-monitor-enterprise
#
# Objects:
#   <line>/<version>/<filename>
#   <line>/index.json          manifest: versions, files, sizes, uploaded_at
#
# Free-tier discipline:
#   • Only PUTs and one manifest GET/PUT — Class A, a handful per release.
#   • Keeps the five newest versions per line, deleting older objects.
#   • Refuses to publish if the recorded total would exceed 8 GiB of the 10 GiB
#     free storage, leaving headroom for manifests and in-flight uploads.
#
# Requires: npx wrangler authenticated against the account that owns the
# bucket. Nothing here reads or prints license data.

set -euo pipefail

BUCKET="talus-downloads"
KEEP_VERSIONS=5
MAX_BYTES=$((8 * 1024 * 1024 * 1024))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SERVER_DIR"

die() { echo "r2-publish: $*" >&2; exit 1; }

LINE="${1:-}"
VERSION="${2:-}"
shift 2 2>/dev/null || true
[ -n "$LINE" ] && [ -n "$VERSION" ] && [ "$#" -gt 0 ] || {
  echo "usage: $0 <mit|enterprise> <version> <file>..." >&2
  exit 2
}
case "$LINE" in mit|enterprise) ;; *) die "line must be mit or enterprise" ;; esac
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be x.y.z"

for file in "$@"; do
  [ -f "$file" ] || die "missing file: $file"
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

manifest_file="$tmp/index.json"
if ! npx wrangler r2 object get "$BUCKET/$LINE/index.json" \
  --file "$manifest_file" --remote >/dev/null 2>&1; then
  printf '{"line":"%s","versions":[]}' "$LINE" >"$manifest_file"
fi

# Record the new files and their sizes; refuse if storage would cross 8 GiB.
new_entries="$tmp/new.json"
: >"$new_entries"
first=1
for file in "$@"; do
  name="$(basename "$file")"
  size="$(wc -c <"$file" | tr -d ' ')"
  entry="{\"name\":\"$name\",\"size\":$size}"
  if [ "$first" -eq 1 ]; then first=0; else printf ',' >>"$new_entries"; fi
  printf '%s' "$entry" >>"$new_entries"
done

projected="$(node - "$manifest_file" "$VERSION" "$new_entries" "$KEEP_VERSIONS" "$MAX_BYTES" <<'NODE'
const fs = require('node:fs');
const [manifestPath, version, entriesPath, keepRaw, maxRaw] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const files = JSON.parse(`[${fs.readFileSync(entriesPath, 'utf8')}]`);
const keep = Number(keepRaw);
const max = Number(maxRaw);

const versions = (manifest.versions || []).filter((v) => v.version !== version);
versions.push({ version, files, uploaded_at: new Date().toISOString() });
const kept = versions.slice(-keep);
const removed = versions.slice(0, Math.max(0, versions.length - keep));
const total = kept.flatMap((v) => v.files || []).reduce((n, f) => n + (f.size || 0), 0);

if (total > max) {
  console.error(
    `projected ${(total / 2 ** 30).toFixed(2)} GiB exceeds the 8 GiB guard; refusing`,
  );
  process.exit(1);
}
fs.writeFileSync(manifestPath, JSON.stringify({ line: manifest.line, versions: kept }, null, 2));
for (const v of removed) {
  for (const f of v.files || []) console.log(`${v.version}/${f.name}`);
}
NODE
)" || die "storage guard rejected this publish"

for file in "$@"; do
  name="$(basename "$file")"
  key="$LINE/$VERSION/$name"
  echo "  put $BUCKET/$key ($(wc -c <"$file" | tr -d ' ') bytes)"
  npx wrangler r2 object put "$BUCKET/$key" --file "$file" \
    --content-type application/octet-stream \
    --cache-control "$([ "$LINE" = mit ] && echo 'public, max-age=31536000, immutable' || echo 'private, no-store')" \
    --remote >/dev/null
done

# Prune before writing the new manifest, so a failure leaves the old index
# pointing at objects that still exist.
while IFS= read -r old; do
  [ -n "$old" ] || continue
  echo "  prune $BUCKET/$LINE/$old"
  npx wrangler r2 object delete "$BUCKET/$LINE/$old" --remote >/dev/null || true
done <<<"$projected"

echo "  put $BUCKET/$LINE/index.json"
npx wrangler r2 object put "$BUCKET/$LINE/index.json" --file "$manifest_file" \
  --content-type application/json --cache-control no-store --remote >/dev/null

echo "published $LINE $VERSION: $*"
