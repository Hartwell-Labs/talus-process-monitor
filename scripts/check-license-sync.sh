#!/usr/bin/env bash
# Verify that the licence files shipped with the crate are present and packaged.
#
# The crate directory is the repository root, so there is no second copy to
# keep in sync. What still needs checking is that `cargo package` actually
# includes the documents the terms point at.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
for f in LICENSE LICENSE.commercial NOTICE; do
  if [ ! -f "$f" ]; then
    echo "  ERROR: missing $f"
    status=1
  else
    echo "  present: $f"
  fi
done

for f in LICENSE LICENSE.commercial NOTICE; do
  cargo package --list -p talus-process-monitor --allow-dirty 2>/dev/null \
    | grep -qx "$f" || { echo "  ERROR: $f is not in the package"; status=1; }
done

if [ "$status" -eq 0 ]; then
  echo "  licence files: present and packaged"
else
  echo "  licence files: PROBLEM — fix before releasing"
fi
exit "$status"
