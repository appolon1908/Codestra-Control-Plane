#!/usr/bin/env bash
set -euo pipefail
station="$1"
agent="$2"
task="$3"
lease="/opt/codestra-dev/control-plane/leases/$station.json"
[ ! -e "$lease" ] || { echo LEASE_EXISTS; exit 1; }
python3 -c "import json,datetime; p='$lease'; now=datetime.datetime.now(datetime.timezone.utc).isoformat(); json.dump({'station':'$station','agent':'$agent','task':'$task','status':'CLAIMED','started_at':now,'heartbeat_at':now},open(p,'w'),indent=2)"
echo "CLAIMED $station"
