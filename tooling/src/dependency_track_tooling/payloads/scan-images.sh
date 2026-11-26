#!/bin/sh
# Each target is validated before staging; scan sequentially without a Docker socket.
set -eu
tab="$(printf '\t')"
while IFS="$tab" read -r identity image; do
    [ -n "$identity" ] || continue
    if ! syft "registry:$image" --scope squashed \
        -o "cyclonedx-json=/work/$identity.cdx.json" >/dev/null 2>&1; then
        touch "/work/$identity.failed"
    fi
done < /work/images.tsv
