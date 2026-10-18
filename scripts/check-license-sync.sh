#!/usr/bin/env bash
# Verify that the licence files shipped inside the crate match the canonical
# ones at the repository root.
#
# Cargo packages files from the package directory, not the repository root, and
# it cannot reach outside it. So the crate carries its own copies of LICENSE,
# LICENSE.commercial and NOTICE, and nothing else keeps them in step. A drift
# here means a user installs a crate whose terms point at a document that says
# something different from the repository's.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
for f in LICENSE.commercial NOTICE; do
  if ! cmp -s "$f" "process-monitor/$f"; then
    echo "  DRIFT: $f differs from process-monitor/$f"
    cp "$f" "process-monitor/$f"
    git add "process-monitor/$f"
    status=1
  else
    echo "  ok: $f"
  fi
done

# The crate ships ../LICENSE via license-file, so verify it separately.
cargo package --list -p talus-process-monitor --allow-dirty 2>/dev/null \
  | grep -qx "LICENSE" || { echo "  ERROR: LICENSE is not in the package"; status=1; }
cargo package --list -p talus-process-monitor --allow-dirty 2>/dev/null \
  | grep -qx "LICENSE.commercial" || { echo "  ERROR: LICENSE.commercial is not in the package"; status=1; }
cargo package --list -p talus-process-monitor --allow-dirty 2>/dev/null \
  | grep -qx "NOTICE" || { echo "  ERROR: NOTICE is not in the package"; status=1; }

if [ "$status" -eq 0 ]; then
  echo "  licence files: in sync and packaged"
else
  echo "  licence files: fixed copies; review the change before committing"
fi
exit "$status"