#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
externum_bin="${EXTERNUM:-externum}"

if ! command -v "$externum_bin" >/dev/null 2>&1; then
    echo "error: Externum not found (install it or set EXTERNUM=/path/to/externum)" >&2
    exit 1
fi

"$externum_bin" run "$here/knowledge.ext" >"$here/knowledge.json"
TALUS_EXPORT=markers "$externum_bin" run "$here/knowledge.ext" >"$here/knowledge.markers"
TALUS_EXPORT=notes "$externum_bin" run "$here/knowledge.ext" >"$here/knowledge.notes"
echo "wrote $here/knowledge.json, $here/knowledge.markers and $here/knowledge.notes"
