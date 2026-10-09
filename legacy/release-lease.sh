#!/usr/bin/env bash
set -euo pipefail
station="$1"
lease="/opt/codestra-dev/control-plane/leases/$station.json"
[ -f "$lease" ] || exit 0
mv "$lease" "/opt/codestra-dev/control-plane/evidence/$station.lease.json"
echo "LEASE_RELEASED $station"
